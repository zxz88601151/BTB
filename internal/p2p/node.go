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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
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
// Auth 为轻量消息签名（P4 常开）：对不含 Auth 的消息体签名；旧节点不发 Auth，
// 接收方对无 Auth 的消息直接接受（向后兼容）；有 Auth 但验签失败的消息丢弃。
type Message struct {
	Type    MessageType     `json:"type"`
	ID      string          `json:"id,omitempty"`
	Payload json.RawMessage `json:"payload"`
	Auth    *MessageAuth    `json:"auth,omitempty"`
}

// HandshakePayload 握手信息：让对方了解己方的基本状态。
type HandshakePayload struct {
	NodeID          string `json:"node_id"`
	ChainHeight     int    `json:"chain_height"`
	ListenAddr      string `json:"listen_addr"`                // 便于对方把我方地址转发给其他节点（节点发现）
	TransportPubKey []byte `json:"transport_pubkey,omitempty"` // 本节点传输签名公钥（65 字节未压缩 P-256）
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

	// P4 mTLS 与轻量消息签名：transportPriv 为本节点传输签名私钥
	// （节点启动时临时生成，仅用于消息来源认证，与钱包私钥无关，
	// 公钥随握手交换；重启后更换，不作长期身份）。
	tlsOpts       TLSOptions
	tlsServerCfg  *tls.Config
	tlsClientCfg  *tls.Config
	transportPriv *ecdsa.PrivateKey
	peerKeys      map[string]*ecdsa.PublicKey // 对端连接地址 -> 传输签名公钥（握手时登记）

	mu          sync.Mutex
	peers       map[string]net.Conn // 已建立连接的对等节点：地址 -> 连接
	scores      map[string]int      // 对端评分（恶意行为累计）
	bannedUntil map[string]time.Time
	knownPeers  map[string]time.Time // 节点发现：已知地址 -> 发现时间
	actualAddr  string               // 实际监听地址（:0 时为系统分配的端口）
}

// NewNode 创建一个节点，监听 listenAddr（例如 ":6688"）。
func NewNode(listenAddr string, handler Handler) *Node {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return &Node{
		listenAddr:    listenAddr,
		handler:       handler,
		peers:         make(map[string]net.Conn),
		scores:        make(map[string]int),
		bannedUntil:   make(map[string]time.Time),
		knownPeers:    make(map[string]time.Time),
		transportPriv: priv,
		peerKeys:      make(map[string]*ecdsa.PublicKey),
	}
}

// SetTLSOptions 配置 mTLS（P4）。Enabled=false 时为明文 TCP（默认，本地兼容）。
// Enabled=true 时立即从文件加载证书，失败返回错误，节点不应以明文回退启动。
func (n *Node) SetTLSOptions(opts TLSOptions) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.tlsOpts = opts
	if !opts.Enabled {
		n.tlsServerCfg, n.tlsClientCfg = nil, nil
		return nil
	}
	serverCfg, err := TLSConfigFromFiles(opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	clientCfg, err := TLSConfigFromFiles(opts.CertFile, opts.KeyFile, opts.CAFile)
	if err != nil {
		return err
	}
	clientCfg.ServerName = "localhost"
	n.tlsServerCfg, n.tlsClientCfg = serverCfg, clientCfg
	return nil
}

// signPayload 对不含 Auth 的消息体做 P-256 签名，固定 64 字节 r||s 拼接。
func (n *Node) signPayload(unsigned []byte) ([]byte, error) {
	n.mu.Lock()
	priv := n.transportPriv
	n.mu.Unlock()
	if priv == nil {
		return nil, fmt.Errorf("传输签名私钥未初始化")
	}
	digest := sha256.Sum256(unsigned)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

// signMessage 给一条消息附加 Auth 签名（对不含 Auth 的消息体签名）。
func (n *Node) signMessage(msg Message) Message {
	if n.nodeID == "" {
		return msg // 未设 nodeID 时不签名（单测 / 旧路径兼容）
	}
	unsigned, err := json.Marshal(Message{Type: msg.Type, ID: msg.ID, Payload: msg.Payload})
	if err != nil {
		return msg
	}
	sig, err := n.signPayload(unsigned)
	if err != nil {
		return msg
	}
	msg.Auth = &MessageAuth{NodeID: n.nodeID, Signature: sig}
	return msg
}

// verifyMessage 校验一条带 Auth 的消息：无 Auth 直接接受（旧节点兼容）；
// 有 Auth 但对端公钥未知时接受（公钥随握手到达，握手本身不强制签名）；
// 公钥已知且验签失败时返回 false，调用方丢弃该消息。
func (n *Node) verifyMessage(peerAddr string, msg Message) bool {
	if msg.Auth == nil {
		return true
	}
	n.mu.Lock()
	pub := n.peerKeys[peerAddr]
	n.mu.Unlock()
	if pub == nil {
		return true
	}
	unsigned, err := json.Marshal(Message{Type: msg.Type, ID: msg.ID, Payload: msg.Payload})
	if err != nil {
		return false
	}
	digest := sha256.Sum256(unsigned)
	sig := msg.Auth.Signature
	if len(sig) != 64 {
		return false
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, digest[:], r, s)
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
// TLSEnabled 时用 tls.Listen（mTLS 双向验证）；否则明文 TCP。
func (n *Node) Start() error {
	var ln net.Listener
	var err error
	n.mu.Lock()
	serverCfg := n.tlsServerCfg
	tlsOn := n.tlsOpts.Enabled
	n.mu.Unlock()
	if tlsOn {
		if serverCfg == nil {
			return fmt.Errorf("TLS 已启用但未配置证书（请先调 SetTLSOptions）")
		}
		ln, err = tls.Listen("tcp", n.listenAddr, serverCfg)
	} else {
		ln, err = net.Listen("tcp", n.listenAddr)
	}
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
	var pubBytes []byte
	n.mu.Lock()
	if n.transportPriv != nil {
		pubBytes = elliptic.Marshal(elliptic.P256(), n.transportPriv.PublicKey.X, n.transportPriv.PublicKey.Y)
	}
	n.mu.Unlock()
	payload, _ := json.Marshal(HandshakePayload{NodeID: nodeID, ChainHeight: height, ListenAddr: listenAddr, TransportPubKey: pubBytes})
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
	var conn net.Conn
	var err error
	n.mu.Lock()
	clientCfg := n.tlsClientCfg
	tlsOn := n.tlsOpts.Enabled
	n.mu.Unlock()
	if tlsOn {
		if clientCfg == nil {
			return fmt.Errorf("TLS 已启用但未配置证书（请先调 SetTLSOptions）")
		}
		conn, err = tls.Dial("tcp", addr, clientCfg)
	} else {
		conn, err = net.Dial("tcp", addr)
	}
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
// 发送前附加轻量签名 Auth（握手消息本身不签名，避免公钥交换循环）。
func (n *Node) SendTo(addr string, msg Message) error {
	n.mu.Lock()
	conn, ok := n.peers[addr]
	n.mu.Unlock()
	if !ok {
		return fmt.Errorf("未连接的对端: %s", addr)
	}
	if msg.Type != MsgHandshake {
		msg = n.signMessage(msg)
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
// 发送前附加轻量签名 Auth（握手消息本身不签名）。
func (n *Node) Broadcast(msg Message) {
	if msg.Type != MsgHandshake {
		msg = n.signMessage(msg)
	}
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
		// 轻量签名校验：验签失败的消息直接丢弃（不分发、不计分，避免误封）。
		if !n.verifyMessage(addr, msg) {
			log.Printf("[p2p] 来自 %s 的消息验签失败，已丢弃", addr)
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
		// 登记对端传输签名公钥（后续消息验签用）。
		if len(payload.TransportPubKey) == 65 {
			if x, y := elliptic.Unmarshal(elliptic.P256(), payload.TransportPubKey); x != nil {
				n.mu.Lock()
				n.peerKeys[peerAddr] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
				n.mu.Unlock()
			}
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
