package p2p

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

type testHandler struct {
	mu         sync.Mutex
	handshakes []HandshakePayload
	addrs      []AddrPayload
}

func (h *testHandler) OnHandshake(peerAddr string, payload HandshakePayload) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handshakes = append(h.handshakes, payload)
}
func (h *testHandler) OnNewBlock(peerAddr string, raw json.RawMessage)         {}
func (h *testHandler) OnNewTx(peerAddr string, raw json.RawMessage)            {}
func (h *testHandler) OnGetBlocks(peerAddr string, payload GetBlocksPayload)   {}
func (h *testHandler) OnBlocksResp(peerAddr string, payload BlocksRespPayload) {}
func (h *testHandler) OnAddr(peerAddr string, payload AddrPayload) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.addrs = append(h.addrs, payload)
}

// 评分/封禁：+10 分未封禁，累计 100 分封禁；封禁期 IsBanned 为真。
func TestReportBadPeerAndBan(t *testing.T) {
	n := NewNode(":0", &testHandler{})
	addr := "1.2.3.4:6688"
	if n.ReportBadPeer(addr, BadBlockScore) {
		t.Errorf("+10 分不应封禁")
	}
	if n.PeerScore(addr) != 10 {
		t.Errorf("评分 = %d, want 10", n.PeerScore(addr))
	}
	for i := 0; i < 9; i++ {
		n.ReportBadPeer(addr, BadBlockScore)
	}
	if !n.IsBanned(addr) {
		t.Errorf("累计 100 分应封禁")
	}
	if err := n.ConnectToPeer(addr); err == nil {
		t.Errorf("封禁期 ConnectToPeer 应拒绝")
	}
}

// 节点发现：握手后交换地址，KnownPeers 记录对方监听地址。
func TestHandshakeAndAddrGossip(t *testing.T) {
	h1 := &testHandler{}
	h2 := &testHandler{}
	n1 := NewNode("127.0.0.1:0", h1)
	n2 := NewNode("127.0.0.1:0", h2)
	n1.SetLocalInfo("node1", func() int { return 5 })
	n2.SetLocalInfo("node2", func() int { return 3 })
	go func() { _ = n1.Start() }()
	go func() { _ = n2.Start() }()
	deadline := time.Now().Add(2 * time.Second)
	for (n1.Addr() == "" || n2.Addr() == "") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n1.Addr() == "" || n2.Addr() == "" {
		t.Skip("监听地址未就绪，跳过网络握手测试")
	}
	if err := n1.ConnectToPeer(n2.Addr()); err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	// 等握手到达。
	ok := false
	for i := 0; i < 200 && !ok; i++ {
		time.Sleep(10 * time.Millisecond)
		h2.mu.Lock()
		ok = len(h2.handshakes) > 0
		h2.mu.Unlock()
	}
	if !ok {
		t.Fatalf("对端未收到握手")
	}
	h2.mu.Lock()
	got := h2.handshakes[0].ChainHeight
	h2.mu.Unlock()
	if got != 5 {
		t.Errorf("握手链高 = %d, want 5", got)
	}
	// 节点发现：n2 应记录 n1 的监听地址。
	found := false
	for _, a := range n2.KnownPeers() {
		if a == n1.Addr() {
			found = true
		}
	}
	if !found {
		t.Errorf("n2 已知节点应含 n1 监听地址 %s，got %v", n1.Addr(), n2.KnownPeers())
	}
}
