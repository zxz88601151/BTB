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
)

// MessageType 标识网络消息的类型。
type MessageType string

const (
	MsgHandshake   MessageType = "handshake"    // 建立连接后的握手，交换版本号、链高度等信息
	MsgNewBlock    MessageType = "new_block"    // 广播新挖出的区块
	MsgNewTx       MessageType = "new_tx"       // 广播新的交易
	MsgGetBlocks   MessageType = "get_blocks"   // 请求区块（用于新节点同步）
	MsgBlocksResp  MessageType = "blocks_resp"  // 区块请求的响应
)

// Message 网络传输的通用消息信封，Payload 按 Type 不同解析成不同结构。
type Message struct {
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// HandshakePayload 握手信息：让对方了解己方的基本状态。
type HandshakePayload struct {
	NodeID      string `json:"node_id"`
	ChainHeight int    `json:"chain_height"`
	ListenAddr  string `json:"listen_addr"` // 便于对方把我方地址转发给其他节点（节点发现）
}

// Handler 由上层（区块链核心逻辑）实现，用于处理收到的各类消息。
// 拆分成接口是为了让 p2p 包只关心"传输"，不关心"业务"（区块验证、交易校验等）。
type Handler interface {
	OnHandshake(peerAddr string, payload HandshakePayload)
	OnNewBlock(peerAddr string, raw json.RawMessage)
	OnNewTx(peerAddr string, raw json.RawMessage)
}

// Node 一个 P2P 节点实例。
type Node struct {
	listenAddr string
	handler    Handler

	mu    sync.Mutex
	peers map[string]net.Conn // 已建立连接的对等节点：地址 -> 连接
}

// NewNode 创建一个节点，监听 listenAddr（例如 ":6688"）。
func NewNode(listenAddr string, handler Handler) *Node {
	return &Node{
		listenAddr: listenAddr,
		handler:    handler,
		peers:      make(map[string]net.Conn),
	}
}

// Start 启动监听，接受其他节点的入站连接。这是一个阻塞调用，通常放到单独的 goroutine 里跑。
func (n *Node) Start() error {
	ln, err := net.Listen("tcp", n.listenAddr)
	if err != nil {
		return fmt.Errorf("监听失败: %w", err)
	}
	log.Printf("[p2p] 节点已启动，监听地址 %s", n.listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[p2p] 接受连接出错: %v", err)
			continue
		}
		go n.handleConn(conn)
	}
}

// ConnectToPeer 主动连接一个对等节点（例如种子节点地址），并发送握手消息。
func (n *Node) ConnectToPeer(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("连接对等节点 %s 失败: %w", addr, err)
	}

	n.mu.Lock()
	n.peers[addr] = conn
	n.mu.Unlock()

	go n.handleConn(conn)
	return nil
}

// Broadcast 把一条消息发送给所有已连接的对等节点。
func (n *Node) Broadcast(msg Message) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[p2p] 序列化消息失败: %v", err)
		return
	}
	data = append(data, '\n') // 用换行分隔消息帧，简化的粘包处理方案

	n.mu.Lock()
	defer n.mu.Unlock()
	for addr, conn := range n.peers {
		if _, err := conn.Write(data); err != nil {
			log.Printf("[p2p] 向 %s 广播消息失败: %v", addr, err)
			// TODO: 失败次数过多应从 peers 中移除该连接，并触发重新发现节点逻辑
		}
	}
}

// handleConn 持续读取某个连接上的消息并分发给 handler。
func (n *Node) handleConn(conn net.Conn) {
	addr := conn.RemoteAddr().String()
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
		n.handler.OnHandshake(peerAddr, payload)
	case MsgNewBlock:
		n.handler.OnNewBlock(peerAddr, msg.Payload)
	case MsgNewTx:
		n.handler.OnNewTx(peerAddr, msg.Payload)
	default:
		log.Printf("[p2p] 收到未知类型消息: %s（来自 %s）", msg.Type, peerAddr)
		// TODO: 补充 MsgGetBlocks / MsgBlocksResp 的处理，用于新节点同步整条链
	}
}

// TODO 节点发现（骨架阶段先用静态种子节点列表，后续可以扩展）：
//   1. 启动时读取配置中的种子节点地址列表，逐个 ConnectToPeer
//   2. 握手时交换双方已知的 peer 列表，实现类似 Gossip 的节点发现扩散
//   3. 定期心跳检测连接存活，断线自动重连或替换节点
