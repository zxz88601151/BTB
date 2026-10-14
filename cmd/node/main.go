// cmd/node 是节点的可执行程序入口。
//
// 运行流程：
//  1. 载入硬编码创世块（genesis 包），初始化内存版区块链
//  2. 生成（或加载）矿工钱包
//  3. 启动 P2P 监听 + 连接种子节点
//  4. 起一个循环：不断打包交易池中的交易 + Coinbase 奖励，尝试挖矿；
//     挖到区块后追加到本地链并向全网广播
//
// 创世块不再现场随机生成：创世块常量见 genesis 包，挖出回填前节点拒绝启动。
package main

import (
	"encoding/json"
	"flag"
	"log"
	"time"

	"hundun/internal/block"
	"hundun/internal/blockchain"
	"hundun/internal/config"
	"hundun/internal/genesis"
	"hundun/internal/p2p"
	"hundun/internal/params"
	"hundun/internal/pow"
	"hundun/internal/transaction"
	"hundun/internal/wallet"
)

// nodeService 把区块链、钱包、网络粘合在一起，并实现 p2p.Handler 接口。
type nodeService struct {
	chain *blockchain.Blockchain
	net   *p2p.Node
	miner *wallet.Wallet
}

func (s *nodeService) OnHandshake(peerAddr string, payload p2p.HandshakePayload) {
	log.Printf("[node] 收到来自 %s 的握手，对方链高度=%d", peerAddr, payload.ChainHeight)
	// TODO: 若对方链高度更高，主动发起 MsgGetBlocks 请求同步缺失的区块
}

func (s *nodeService) OnNewBlock(peerAddr string, raw json.RawMessage) {
	log.Printf("[node] 收到来自 %s 的新区块广播", peerAddr)
	// TODO: 反序列化区块 -> s.chain.ValidateBlock -> 合法则 AddBlock 并继续转发（Gossip）
	// TODO: 若该区块使本地正在挖的候选区块失效（父哈希不再是链尾），需要终止当前挖矿并重新组装候选区块
}

func (s *nodeService) OnNewTx(peerAddr string, raw json.RawMessage) {
	log.Printf("[node] 收到来自 %s 的新交易广播", peerAddr)
	// TODO: 反序列化交易 -> 校验签名与 UTXO 有效性 -> 放入内存交易池（Mempool）并继续转发
}

// mineLoop 是最核心的挖矿循环：组装候选区块 -> 挖矿 -> 成功则上链并广播 -> 重复。
func mineLoop(s *nodeService) {
	for {
		tip, err := s.chain.Tip()
		if err != nil {
			log.Printf("[miner] 获取链尾失败: %v", err)
			time.Sleep(time.Second)
			continue
		}

		// TODO: 这里应该从 Mempool 中挑选手续费最高的一批交易打包，骨架阶段只打包 Coinbase
		nextHeight := uint64(s.chain.Height() + 1)
		coinbase := transaction.NewCoinbaseTx(s.miner.PubKeyHash(), params.GetBlockSubsidy(nextHeight))
		candidate := block.NewCandidateBlock(tip.Header.Hash(), s.chain.CurrentBits(), []*transaction.Transaction{coinbase})

		log.Printf("[miner] 开始挖矿，高度=%d，Bits=0x%08x", nextHeight, candidate.Header.Bits)

		// maxIterations 设置一个上限，避免长时间挖不到时无法响应"链尾已变化，需要重新组装候选区块"的情况；
		// 生产实现建议用 goroutine + context 取消，而不是轮询迭代次数。
		// 注意：pow.Mine 的 Nonce 为 uint32，超限未找到时返回 false，调用方重组装候选块后重试
		// （重组装会刷新 Timestamp，相当于 Timestamp+1 重扫）。
		found, attempts := pow.Mine(candidate, 5_000_000)
		if !found {
			log.Printf("[miner] 本轮 %d 次尝试未找到解，重新组装候选区块", attempts)
			continue
		}

		if err := s.chain.AddBlock(candidate); err != nil {
			log.Printf("[miner] 挖到区块但校验失败（可能链尾已变化）: %v", err)
			continue
		}

		log.Printf("[miner] 挖到新区块！高度=%d 哈希=%s 尝试次数=%d",
			s.chain.Height(), candidate.Header.HashHex(), attempts)

		broadcastBlock(s.net, candidate)
	}
}

func broadcastBlock(n *p2p.Node, b *block.Block) {
	// TODO: 目前只是骨架，真实实现需要把 block.Block 完整序列化（包括交易列表）后放入 Payload
	payload, _ := json.Marshal(map[string]string{"hash": b.Header.HashHex()})
	n.Broadcast(p2p.Message{Type: p2p.MsgNewBlock, Payload: payload})
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

	svc := &nodeService{chain: chain, miner: minerWallet}

	p2pNode := p2p.NewNode(cfg.ListenAddr, svc)
	svc.net = p2pNode

	go func() {
		if err := p2pNode.Start(); err != nil {
			log.Fatalf("[p2p] 启动监听失败: %v", err)
		}
	}()

	if *seedAddr != "" {
		if err := p2pNode.ConnectToPeer(*seedAddr); err != nil {
			log.Printf("[p2p] 连接种子节点失败: %v", err)
		}
	}

	if cfg.MinerEnabled {
		mineLoop(svc)
	} else {
		select {} // 阻塞主 goroutine，仅作为全节点运行
	}
}
