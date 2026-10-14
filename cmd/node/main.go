// cmd/node 是节点的可执行程序入口。
//
// 骨架阶段的运行流程：
//  1. 生成创世区块，初始化内存版区块链
//  2. 生成（或加载）矿工钱包
//  3. 启动 P2P 监听 + 连接种子节点
//  4. 起一个循环：不断打包交易池中的交易 + Coinbase 奖励，尝试挖矿；
//     挖到区块后追加到本地链并向全网广播
//
// 这是单文件骨架，方便先跑通主流程；随着功能增加，建议把挖矿循环、消息处理
// 拆分成独立的 service 结构体，main.go 只负责组装依赖（依赖注入）。
package main

import (
	"encoding/json"
	"flag"
	"log"
	"time"

	"p2pchain/internal/block"
	"p2pchain/internal/blockchain"
	"p2pchain/internal/config"
	"p2pchain/internal/p2p"
	"p2pchain/internal/pow"
	"p2pchain/internal/transaction"
	"p2pchain/internal/wallet"
)

// BlockReward 每个区块的出块奖励（最小单位）。
// 真实项目通常会设计"减半"机制（比特币每21万个区块奖励减半），此处先用固定值。
const BlockReward = 50

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

// buildGenesisBlock 构造创世区块：没有前置区块，直接给出一笔 Coinbase 奖励。
func buildGenesisBlock(minerPubKeyHash [20]byte) *block.Block {
	coinbase := transaction.NewCoinbaseTx(minerPubKeyHash, BlockReward)
	genesis := block.NewCandidateBlock([32]byte{}, pow.MaxTargetBits, []*transaction.Transaction{coinbase})

	// 创世区块也需要真正挖出来，保证哈希满足难度目标，逻辑上和普通区块一致
	pow.Mine(genesis, 0)
	return genesis
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
		coinbase := transaction.NewCoinbaseTx(s.miner.PubKeyHash(), BlockReward)
		candidate := block.NewCandidateBlock(tip.Header.Hash(), s.chain.CurrentBits(), []*transaction.Transaction{coinbase})

		log.Printf("[miner] 开始挖矿，高度=%d，难度位数=%d", s.chain.Height()+1, candidate.Header.Bits)

		// maxIterations 设置一个上限，避免长时间挖不到时无法响应"链尾已变化，需要重新组装候选区块"的情况；
		// 生产实现建议用 goroutine + context 取消，而不是轮询迭代次数。
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

	minerWallet, err := wallet.NewWallet()
	if err != nil {
		log.Fatalf("生成矿工钱包失败: %v", err)
	}
	log.Printf("[node] 矿工地址（公钥哈希）=%x", minerWallet.PubKeyHash())

	genesis := buildGenesisBlock(minerWallet.PubKeyHash())
	chain := blockchain.NewBlockchainWithGenesis(genesis)
	log.Printf("[node] 创世区块哈希=%s", genesis.Header.HashHex())

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
