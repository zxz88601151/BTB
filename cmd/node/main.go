// cmd/node 是节点的可执行程序入口。
//
// 运行流程：
//  1. 载入硬编码创世块（genesis 包），初始化内存版区块链 + UTXO
//  2. 生成（或加载）矿工钱包
//  3. 启动 P2P 监听 + 连接种子节点（断线指数退避重连）
//  4. 同步：落后时先同步（WAITING_SYNC 门禁，矿工不挖矿），同步完成后再挖矿
//  5. 挖矿循环：Mempool 按费率打包 + Coinbase（补贴 + 费和）→ 并行挖矿 → 上链广播
//
// 创世块不再现场随机生成：创世块常量见 genesis 包，挖出回填前节点拒绝启动。
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"hundun/internal/block"
	"hundun/internal/blockchain"
	"hundun/internal/config"
	"hundun/internal/genesis"
	"hundun/internal/mempool"
	"hundun/internal/p2p"
	"hundun/internal/params"
	"hundun/internal/pow"
	chainsync "hundun/internal/sync"
	"hundun/internal/transaction"
	"hundun/internal/wallet"
)

// nodeService 把区块链、钱包、网络、Mempool、同步粘合在一起，实现 p2p.Handler + p2p.SyncHandler。
type nodeService struct {
	chain  *blockchain.Blockchain
	net    *p2p.Node
	miner  *wallet.Wallet
	pool   *mempool.Pool
	syncer *chainsync.Syncer

	mu          sync.Mutex
	peerHeights map[string]int
	pending     map[string]chan p2p.BlocksRespPayload
	pendingSeq  int
}

// OnHandshake 握手处理：记录对端高度；若对端更高且未在同步，启动同步。
func (s *nodeService) OnHandshake(peerAddr string, payload p2p.HandshakePayload) {
	log.Printf("[node] 收到来自 %s 的握手，对方链高度=%d", peerAddr, payload.ChainHeight)
	s.mu.Lock()
	s.peerHeights[peerAddr] = payload.ChainHeight
	s.mu.Unlock()
	s.syncer.NotePeerHeight(payload.ChainHeight)
	if payload.ChainHeight > s.chain.Height() && !s.syncer.IsSyncing() {
		go s.runSync(peerAddr)
	}
}

// runSync 从指定对端同步，完成后清理 Mempool（已确认的交易失效）。
func (s *nodeService) runSync(peerAddr string) {
	n, err := s.syncer.SyncFromPeer(peerAddr, s)
	if err != nil {
		log.Printf("[sync] 从 %s 同步失败（已同步 %d 块）: %v", peerAddr, n, err)
		return
	}
	log.Printf("[sync] 从 %s 同步完成，新增 %d 块，本地高度=%d", peerAddr, n, s.chain.Height())
	s.pool.Prune(s.chain.UTXOSet())
}

// OnNewBlock 新区块广播处理：校验上链 / 分叉重组 / 孤块触发同步 / 恶意对端评分。
func (s *nodeService) OnNewBlock(peerAddr string, raw json.RawMessage) {
	var b block.Block
	if err := json.Unmarshal(raw, &b); err != nil {
		log.Printf("[node] 解析新区块失败（来自 %s）: %v", peerAddr, err)
		return
	}
	if s.chain.HasBlock(b.Header.Hash()) {
		return // 已见过，不重复处理、不转发（防 Gossip 循环）
	}
	displaced, _, err := s.chain.AddBlockWithResult(&b)
	if err != nil {
		if err == blockchain.ErrOrphan {
			// 孤块：父块缺失，触发同步补父块。
			log.Printf("[node] 收到孤块（来自 %s），触发同步", peerAddr)
			if !s.syncer.IsSyncing() {
				go s.runSync(peerAddr)
			}
			return
		}
		log.Printf("[node] 拒绝来自 %s 的无效块: %v", peerAddr, err)
		s.net.ReportBadPeer(peerAddr, p2p.BadBlockScore)
		return
	}
	// 上链成功：Mempool 移除已确认交易，清理失效交易，重组挤出的交易放回池。
	s.pool.RemoveConfirmed(b.Transactions)
	s.pool.Prune(s.chain.UTXOSet())
	for _, tx := range displaced {
		_ = s.pool.Add(tx, s.chain.UTXOSet(), s.chain.Height()+1) // 失败即丢弃（重组后可能已无效）
	}
	s.broadcastBlock(&b)
}

// OnNewTx 新交易广播处理：入池成功则转发；无效签名/双花等恶意交易计分。
func (s *nodeService) OnNewTx(peerAddr string, raw json.RawMessage) {
	var tx transaction.Transaction
	if err := json.Unmarshal(raw, &tx); err != nil {
		log.Printf("[node] 解析新交易失败（来自 %s）: %v", peerAddr, err)
		return
	}
	if err := s.pool.Add(&tx, s.chain.UTXOSet(), s.chain.Height()+1); err != nil {
		// 策略性拒绝（粉尘/低费/重复/池满/缺父交易）不惩罚；恶意类（坏签名/双花/负费/未成熟）计分。
		switch err {
		case mempool.ErrBadSignature, mempool.ErrDoubleSpend, mempool.ErrNegativeFee, mempool.ErrImmature:
			s.net.ReportBadPeer(peerAddr, p2p.BadBlockScore)
		}
		return
	}
	s.net.Broadcast(p2p.Message{Type: p2p.MsgNewTx, Payload: raw})
}

// OnGetBlocks 同步请求处理：返回 FromHeight 起的块（按高度升序），RequestID 原样带回。
func (s *nodeService) OnGetBlocks(peerAddr string, payload p2p.GetBlocksPayload) {
	var raws []json.RawMessage
	for h := payload.FromHeight; h < payload.FromHeight+payload.Count; h++ {
		b, err := s.chain.BlockAt(h)
		if err != nil {
			break
		}
		data, _ := json.Marshal(b)
		raws = append(raws, data)
	}
	if raws == nil {
		raws = []json.RawMessage{}
	}
	resp, _ := json.Marshal(p2p.BlocksRespPayload{FromHeight: payload.FromHeight, Blocks: raws, RequestID: payload.RequestID})
	_ = s.net.SendTo(peerAddr, p2p.Message{Type: p2p.MsgBlocksResp, ID: payload.RequestID, Payload: resp})
}

// OnBlocksResp 同步响应处理：按 RequestID 投递给等待中的 Fetcher 请求。
func (s *nodeService) OnBlocksResp(peerAddr string, payload p2p.BlocksRespPayload) {
	_ = peerAddr
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.pending[payload.RequestID]; ok {
		select {
		case ch <- payload:
		default:
		}
		delete(s.pending, payload.RequestID)
		return
	}
	// 兼容旧节点（响应无 RequestID）：投递给唯一的等待者。
	if len(s.pending) == 1 {
		for id, ch := range s.pending {
			select {
			case ch <- payload:
			default:
			}
			delete(s.pending, id)
		}
	}
}

// OnAddr 节点发现处理：收到新地址后尝试连接（去重、防自连、限连接数）。
func (s *nodeService) OnAddr(peerAddr string, payload p2p.AddrPayload) {
	_ = peerAddr
	for _, addr := range payload.Addrs {
		if addr == s.net.Addr() || s.net.IsBanned(addr) {
			continue
		}
		already := false
		for _, p := range s.net.Peers() {
			if p == addr {
				already = true
				break
			}
		}
		if already || len(s.net.Peers()) >= 8 {
			continue
		}
		go func(a string) {
			_ = s.net.ConnectToPeer(a)
		}(addr)
	}
}

// --- sync.Fetcher 实现（P2P 取块）---

// PeerHeight 返回记录的对端高度（握手时记录）。
func (s *nodeService) PeerHeight(peer string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.peerHeights[peer]
	if !ok {
		return 0, fmt.Errorf("未知对端高度: %s", peer)
	}
	return h, nil
}

// GetBlocks 向对端发 GetBlocks 并等待 BlocksResp（30 秒超时）。
func (s *nodeService) GetBlocks(peer string, fromHeight, count int) ([]*block.Block, error) {
	s.mu.Lock()
	s.pendingSeq++
	id := fmt.Sprintf("sync-%d", s.pendingSeq)
	ch := make(chan p2p.BlocksRespPayload, 1)
	s.pending[id] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
	}()

	req, _ := json.Marshal(p2p.GetBlocksPayload{FromHeight: fromHeight, Count: count})
	if err := s.net.SendTo(peer, p2p.Message{Type: p2p.MsgGetBlocks, ID: id, Payload: req}); err != nil {
		return nil, err
	}
	select {
	case resp := <-ch:
		var out []*block.Block
		for _, raw := range resp.Blocks {
			var b block.Block
			if err := json.Unmarshal(raw, &b); err != nil {
				return nil, fmt.Errorf("解析同步块失败: %w", err)
			}
			out = append(out, &b)
		}
		return out, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("等待对端 %s 的 BlocksResp 超时", peer)
	}
}

// mineLoop 挖矿循环：同步门禁 → Mempool 打包 → 并行挖矿 → 上链广播。
func mineLoop(s *nodeService) {
	for {
		// 同步门禁（MINING-SYNC-GATE-1）：落后或正在同步时不挖矿。
		if s.syncer.IsSyncing() || s.syncer.NeedsSync() {
			log.Printf("[miner] WAITING_SYNC：本地高度=%d，已知最高=%d，等待同步完成", s.chain.Height(), s.syncer.BestHeight())
			time.Sleep(2 * time.Second)
			continue
		}
		tip, err := s.chain.Tip()
		if err != nil {
			log.Printf("[miner] 获取链尾失败: %v", err)
			time.Sleep(time.Second)
			continue
		}
		nextHeight := s.chain.Height() + 1
		// Mempool 打包：留出 80 字节头 + Coinbase 的权重。
		const reserveWeight = 656 // 80 字节头（320）+ Coinbase 约 84 字节（336）
		selected, totalFee := s.pool.SelectForBlock(params.MaxBlockWeight-reserveWeight, s.chain.UTXOSet())
		coinbaseValue := params.GetBlockSubsidy(uint64(nextHeight)) + totalFee
		txs := mempool.PackBlock(coinbaseValue, s.miner.PubKeyHash(), selected)
		candidate := block.NewCandidateBlock(tip.Header.Hash(), s.chain.CurrentBits(), txs)

		log.Printf("[miner] 开始挖矿，高度=%d，Bits=0x%08x，打包交易=%d，手续费=%d", nextHeight, candidate.Header.Bits, len(selected), totalFee)

		found, attempts := pow.MineParallel(candidate, 0)
		if !found {
			// Nonce 空间耗尽：重组装候选块（刷新 Timestamp）后重试。
			log.Printf("[miner] Nonce 空间耗尽未找到解，重新组装候选区块")
			continue
		}
		if _, _, err := s.chain.AddBlockWithResult(candidate); err != nil {
			log.Printf("[miner] 挖到区块但校验失败（可能链尾已变化）: %v", err)
			continue
		}
		log.Printf("[miner] 挖到新区块！高度=%d 哈希=%s 尝试次数=%d",
			s.chain.Height(), candidate.Header.HashHex(), attempts)
		s.pool.RemoveConfirmed(candidate.Transactions)
		s.pool.Prune(s.chain.UTXOSet())
		s.broadcastBlock(candidate)
	}
}

func (s *nodeService) broadcastBlock(b *block.Block) {
	data, _ := json.Marshal(b)
	s.net.Broadcast(p2p.Message{Type: p2p.MsgNewBlock, Payload: data})
}

// reconnectLoop 种子节点断线重连：指数退避（1s→2s→4s…上限 60s），成功后重置退避。
func reconnectLoop(n *p2p.Node, seedAddr string) {
	backoff := time.Second
	for {
		connected := false
		for _, p := range n.Peers() {
			if p == seedAddr {
				connected = true
				break
			}
		}
		if !connected {
			if err := n.ConnectToPeer(seedAddr); err != nil {
				log.Printf("[p2p] 重连种子 %s 失败: %v，%v 后重试", seedAddr, err, backoff)
				time.Sleep(backoff)
				backoff *= 2
				if backoff > 60*time.Second {
					backoff = 60 * time.Second
				}
				continue
			}
			log.Printf("[p2p] 已重连种子 %s", seedAddr)
			backoff = time.Second
		}
		time.Sleep(5 * time.Second)
	}
}

func main() {
	listenAddr := flag.String("listen", ":6688", "本节点监听地址")
	seedAddr := flag.String("seed", "", "种子节点地址，留空表示作为第一个节点启动")
	flag.Parse()

	cfg := config.DefaultConfig()
	cfg.ListenAddr = *listenAddr

	// 载入硬编码创世块（回填前拒绝启动，见 genesis 包）。
	genesisBlock, err := genesis.GenesisBlock()
	if err != nil {
		log.Fatalf("载入创世块失败: %v（创世块须先挖矿回填 genesis 包的 Timestamp/Nonce/Hash/TxID）", err)
	}
	if err := blockchain.ValidateGenesisBlock(genesisBlock); err != nil {
		log.Fatalf("创世块校验失败: %v", err)
	}
	chain := blockchain.NewBlockchainWithGenesis(genesisBlock)
	log.Printf("[node] 创世区块哈希=%s", genesisBlock.Header.HashHex())

	minerWallet, err := wallet.NewWallet()
	if err != nil {
		log.Fatalf("生成矿工钱包失败: %v", err)
	}
	log.Printf("[node] 矿工地址（公钥哈希）=%x", minerWallet.PubKeyHash())

	svc := &nodeService{
		chain:       chain,
		miner:       minerWallet,
		pool:        mempool.New(),
		syncer:      chainsync.New(chain),
		peerHeights: make(map[string]int),
		pending:     make(map[string]chan p2p.BlocksRespPayload),
	}

	p2pNode := p2p.NewNode(cfg.ListenAddr, svc)
	svc.net = p2pNode
	nodeID := fmt.Sprintf("hundun-%d-%d", time.Now().UnixNano(), os.Getpid())
	p2pNode.SetLocalInfo(nodeID, chain.Height)

	go func() {
		if err := p2pNode.Start(); err != nil {
			log.Fatalf("[p2p] 启动监听失败: %v", err)
		}
	}()

	if *seedAddr != "" {
		if err := p2pNode.ConnectToPeer(*seedAddr); err != nil {
			log.Printf("[p2p] 连接种子节点失败: %v（后台重连循环会继续尝试）", err)
		}
		go reconnectLoop(p2pNode, *seedAddr)
	}

	if cfg.MinerEnabled {
		mineLoop(svc)
	} else {
		select {} // 阻塞主 goroutine，仅作为全节点运行
	}
}
