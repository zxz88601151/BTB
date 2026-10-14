// Package p2p 实现最基础的点对点网络层骨架，基于 TCP + 简单的换行分隔 JSON 消息协议。
//
// 设计说明（骨架阶段，刻意简化）：
//   - 每个节点既是服务端（监听端口接受连接）也是客户端（主动连接种子节点/对等节点）
//   - 消息类型先只定义握手、区块广播、交易广播三种，后续可扩展 GetBlocks / Inv 等
//   - 真实项目建议换成成熟的 P2P 框架（如 libp2p），自己实现的协议要特别注意：
//     消息大小限制、超时处理、恶意节点限流、日食攻击防护（多个网络出口/多样化的对等节点来源）
package p2p

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// MessageType 标识网络消息的类型。
type MessageType string

const (
	MsgHandshake  MessageType = "handshake"   // 建立连接后的握手，交换版本号、链高度等信息
	MsgNewBlock   MessageType = "new_block"   // 广播新挖出的区块
	MsgNewTx      MessageType = "new_tx"      // 广播新的交易
	MsgGetBlocks  MessageType = "get_blocks"  // 请求区块（用于新节点同步）
	MsgBlocksResp MessageType = "blocks_resp" // 区块请求的响应
	MsgAddr       MessageType = "addr"        // 节点发现：交换已知对等节点地址列表（Gossip）
)

// Message 网络传输的通用消息信封，Payload 按 Type 不同解析成不同结构。
// ID 为请求/响应关联用（同步 GetBlocks/BlocksResp 等），旧节点忽略本字段（JSON 未知字段兼容）。
type Message struct {
	Type    MessageType     `json:"type"`
	ID      string          `json:"id,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

// HandshakePayload 握手信息：让对方了解己方的基本状态。
type HandshakePayload struct {
	NodeID      string `json:"node_id"`
	ChainHeight int    `json:"chain_height"`
	ListenAddr  string `json:"listen_addr"` // 便于对方把我方地址转发给其他节点（节点发现）
}

// GetBlocksPayload 同步请求：从 FromHeight 开始取 Count 个块。
// RequestID 为请求关联 ID（p2p 层从 Message.ID 填入，响应须原样带回）。
type GetBlocksPayload struct {
	FromHeight int    `json:"from_height"`
	Count      int    `json:"count"`
	RequestID  string `json:"request_id,omitempty"`
}

// BlocksRespPayload 同步响应：FromHeight 起的块列表（每块为 block.Block 的 JSON）。
// RequestID 须与请求一致，请求方按此匹配等待中的 Fetcher 调用。
type BlocksRespPayload struct {
	FromHeight int               `json:"from_height"`
	Blocks     []json.RawMessage `json:"blocks"`
	RequestID  string            `json:"request_id,omitempty"`
}

// AddrPayload 节点发现：已知对等节点地址列表。
type AddrPayload struct {
	Addrs []string `json:"addrs"`
}

// Handler 由上层（区块链核心逻辑）实现，用于处理收到的各类消息。
// 拆分成接口是为了让 p2p 包只关心"传输"，不关心"业务"（区块验证、交易校验等）。
type Handler interface {
	OnHandshake(peerAddr string, payload HandshakePayload)
	OnNewBlock(peerAddr string, raw json.RawMessage)
	OnNewTx(peerAddr string, raw json.RawMessage)
}

// SyncHandler 可选接口：实现它的 Handler 可处理同步与节点发现消息。
// 未实现时 p2p 层仅记录日志，忽略该类消息（兼容旧 Handler）。
type SyncHandler interface {
	OnGetBlocks(peerAddr string, payload GetBlocksPayload)
	OnBlocksResp(peerAddr string, payload BlocksRespPayload)
	OnAddr(peerAddr string, payload AddrPayload)
}

// 评分/封禁参数（策略参数，参考老线 P0-5 口径）。
const (
	BanScoreThreshold = 100              // 累计 100 分封禁
	BanDuration       = 10 * time.Minute // 封禁 10 分钟，到期自动解封
	BadBlockScore     = 10               // 无效块/无效交易 +10 分
)

// Node 一个 P2P 节点实例。
type Node struct {
	listenAddr string
	handler    Handler
	nodeID     string
	heightFunc func() int // 返回本地链高（握手用），未设置时为 0

	mu          sync.Mutex
	peers       map[string]net.Conn // 已建立连接的对等节点：地址 -> 连接
	scores      map[string]int      // 对端评分（恶意行为累计）
	bannedUntil map[string]time.Time
	knownPeers  map[string]time.Time // 节点发现：已知地址 -> 发现时间
	actualAddr  string               // 实际监听地址（:0 时为系统分配的端口）
}

// NewNode 创建一个节点，监听 listenAddr（例如 ":6688"）。
func NewNode(listenAddr string, handler Handler) *Node {
	return &Node{
		listenAddr:  listenAddr,
		handler:     handler,
		peers:       make(map[string]net.Conn),
		scores:      make(map[string]int),
		bannedUntil: make(map[string]time.Time),
		knownPeers:  make(map[string]time.Time),
	}
}

// SetLocalInfo 设置握手用的本节点 ID 与链高函数（链高函数由上层提供，握手时实时读取）。
func (n *Node) SetLocalInfo(nodeID string, heightFunc func() int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nodeID = nodeID
	n.heightFunc = heightFunc
}

// Addr 返回实际监听地址（Start 后可用；:0 时为系统分配的端口）。
func (n *Node) Addr() string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.actualAddr
}

// Start 启动监听，接受其他节点的入站连接。这是一个阻塞调用，通常放到单独的 goroutine 里跑。
func (n *Node) Start() error {
	ln, err := net.Listen("tcp", n.listenAddr)
	if err != nil {
		return fmt.Errorf("监听失败: %w", err)
	}
	n.mu.Lock()
	n.actualAddr = ln.Addr().String()
	n.mu.Unlock()
	log.Printf("[p2p] 节点已启动，监听地址 %s", n.actualAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[p2p] 接受连接出错: %v", err)
			continue
		}
		go func(c net.Conn) {
			// 入站连接先发握手，再读消息（双向交换链高）。
			n.sendHandshake(c)
			n.handleConn(c)
		}(conn)
	}
}

// sendHandshake 向指定连接发送握手消息。
func (n *Node) sendHandshake(conn net.Conn) {
	n.mu.Lock()
	nodeID := n.nodeID
	heightFunc := n.heightFunc
	listenAddr := n.actualAddr
	if listenAddr == "" {
		listenAddr = n.listenAddr
	}
	n.mu.Unlock()
	height := 0
	if heightFunc != nil {
		height = heightFunc()
	}
	payload, _ := json.Marshal(HandshakePayload{NodeID: nodeID, ChainHeight: height, ListenAddr: listenAddr})
	msg := Message{Type: MsgHandshake, Payload: payload}
	data, err := json.Marshal(msg)
	if err != nil {
		return
	}
	data = append(data, '\n')
	_, _ = conn.Write(data)
}

// ConnectToPeer 主动连接一个对等节点（例如种子节点地址），并发送握手消息。
func (n *Node) ConnectToPeer(addr string) error {
	if n.IsBanned(addr) {
		return fmt.Errorf("对端 %s 仍在封禁期，拒绝连接", addr)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("连接对等节点 %s 失败: %w", addr, err)
	}

	n.mu.Lock()
	n.peers[addr] = conn
	n.mu.Unlock()

	go n.handleConn(conn)
	n.sendHandshake(conn)
	return nil
}

// SendTo 向指定对端发送一条消息（同步请求等点对点消息用）。
func (n *Node) SendTo(addr string, msg Message) error {
	n.mu.Lock()
	conn, ok := n.peers[addr]
	n.mu.Unlock()
	if !ok {
		return fmt.Errorf("未连接的对端: %s", addr)
	}
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = conn.Write(data)
	return err
}

// Peers 返回当前已连接对端地址列表。
func (n *Node) Peers() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, 0, len(n.peers))
	for addr := range n.peers {
		out = append(out, addr)
	}
	return out
}

// AddKnownPeer 记录一个已知节点地址（节点发现用）。
func (n *Node) AddKnownPeer(addr string) {
	if addr == "" {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.knownPeers == nil {
		n.knownPeers = make(map[string]time.Time)
	}
	n.knownPeers[addr] = time.Now()
}

// KnownPeers 返回已知节点地址列表。
func (n *Node) KnownPeers() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]string, 0, len(n.knownPeers))
	for addr := range n.knownPeers {
		out = append(out, addr)
	}
	return out
}

// ReportBadPeer 上报对端恶意行为：加分，累计 >= 100 分封禁 10 分钟，断开连接。
// 返回是否已封禁。封禁到期自动解封（IsBanned 按时间判断）。
func (n *Node) ReportBadPeer(addr string, points int) bool {
	n.mu.Lock()
	n.scores[addr] += points
	banned := n.scores[addr] >= BanScoreThreshold
	if banned {
		n.bannedUntil[addr] = time.Now().Add(BanDuration)
	}
	conn := n.peers[addr]
	n.mu.Unlock()
	if banned {
		log.Printf("[p2p] 对端 %s 评分 %d 达封禁阈值，封禁 %v", addr, n.PeerScore(addr), BanDuration)
		if conn != nil {
			_ = conn.Close()
		}
	}
	return banned
}

// IsBanned 判断对端是否在封禁期（到期自动视为解封）。
func (n *Node) IsBanned(addr string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	until, ok := n.bannedUntil[addr]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(n.bannedUntil, addr)
		n.scores[addr] = 0
		return false
	}
	return true
}

// PeerScore 返回对端当前评分。
func (n *Node) PeerScore(addr string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.scores[addr]
}

// Broadcast 把一条消息发送给所有已连接的对等节点（跳过封禁对端）。
func (n *Node) Broadcast(msg Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[p2p] 序列化消息失败: %v", err)
		return
	}
	data = append(data, '\n') // 用换行分隔消息帧，简化的粘包处理方案

	n.mu.Lock()
	conns := make(map[string]net.Conn, len(n.peers))
	for addr, conn := range n.peers {
		if until, banned := n.bannedUntil[addr]; banned && time.Now().Before(until) {
			continue
		}
		conns[addr] = conn
	}
	n.mu.Unlock()
	for addr, conn := range conns {
		if _, err := conn.Write(data); err != nil {
			log.Printf("[p2p] 向 %s 广播消息失败: %v", addr, err)
		}
	}
}

// handleConn 持续读取某个连接上的消息并分发给 handler。
// 入站连接在此注册进 peers（此前仅出站连接注册，导致广播发不到入站对端）。
func (n *Node) handleConn(conn net.Conn) {
	addr := conn.RemoteAddr().String()
	n.mu.Lock()
	if n.peers == nil {
		n.peers = make(map[string]net.Conn)
	}
	n.peers[addr] = conn
	n.mu.Unlock()
	defer func() {
		conn.Close()
		n.mu.Lock()
		delete(n.peers, addr)
		n.mu.Unlock()
	}()

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			log.Printf("[p2p] 与 %s 的连接已断开: %v", addr, err)
			return
		}

		var msg Message
		if err := json.Unmarshal(line, &msg); err != nil {
			log.Printf("[p2p] 解析来自 %s 的消息失败: %v", addr, err)
			continue
		}

		n.dispatch(addr, msg)
	}
}

func (n *Node) dispatch(peerAddr string, msg Message) {
	switch msg.Type {
	case MsgHandshake:
		var payload HandshakePayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			log.Printf("[p2p] 解析握手消息失败: %v", err)
			return
		}
		// 节点发现：记录对方监听地址，握手后回发本节点已知地址列表（Gossip）。
		if payload.ListenAddr != "" {
			n.AddKnownPeer(payload.ListenAddr)
		}
		n.handler.OnHandshake(peerAddr, payload)
		known := n.KnownPeers()
		if len(known) > 0 {
			_ = n.SendTo(peerAddr, Message{Type: MsgAddr, Payload: mustJSON(AddrPayload{Addrs: known})})
		}
	case MsgNewBlock:
		n.handler.OnNewBlock(peerAddr, msg.Payload)
	case MsgNewTx:
		n.handler.OnNewTx(peerAddr, msg.Payload)
	case MsgGetBlocks:
		if h, ok := n.handler.(SyncHandler); ok {
			var payload GetBlocksPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				log.Printf("[p2p] 解析 GetBlocks 失败: %v", err)
				return
			}
			payload.RequestID = msg.ID
			h.OnGetBlocks(peerAddr, payload)
		}
	case MsgBlocksResp:
		if h, ok := n.handler.(SyncHandler); ok {
			var payload BlocksRespPayload
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				log.Printf("[p2p] 解析 BlocksResp 失败: %v", err)
				return
			}
			if payload.RequestID == "" {
				payload.RequestID = msg.ID
			}
			h.OnBlocksResp(peerAddr, payload)
		}
	case MsgAddr:
		var payload AddrPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			log.Printf("[p2p] 解析 Addr 失败: %v", err)
			return
		}
		for _, a := range payload.Addrs {
			n.AddKnownPeer(a)
		}
		if h, ok := n.handler.(SyncHandler); ok {
			h.OnAddr(peerAddr, payload)
		}
	default:
		// 未知类型忽略（兼容未来消息类型），不报错、不惩罚。
		log.Printf("[p2p] 收到未知类型消息: %s（来自 %s，已忽略）", msg.Type, peerAddr)
	}
}

func mustJSON(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

// 节点发现与断线重连（任务卡片 4）说明：
//   - 发现：启动时连种子节点（--seed / 配置 SeedPeers）；握手时交换已知地址（MsgAddr Gossip），
//     收到新地址后由上层决定是否连接（去重、防自连、防封禁地址）。
//   - 断线重连：上层（cmd/node）对种子节点做指数退避重连（1s→2s→4s…上限 60s），
//     重连成功后重新握手、重新比对高度并同步。本包提供连接与评分原语，不持有重连循环。
//   - 评分：无效块/交易由上层调 ReportBadPeer(+10)，100 分封禁 10 分钟。
