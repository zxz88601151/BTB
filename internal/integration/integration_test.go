// Package integration 全链路联调：创世 → 并行挖块 → 转账 → Mempool → 打包 → 同步 → 分叉重组。
//
// 用易难度（0x207fffff）测试链，不用真实创世难度（真实难度单块需数十亿次哈希）。
package integration

import (
	"fmt"
	"testing"
	"time"

	"hundun/internal/block"
	"hundun/internal/blockchain"
	"hundun/internal/mempool"
	"hundun/internal/params"
	"hundun/internal/pow"
	chainsync "hundun/internal/sync"
	"hundun/internal/transaction"
	"hundun/internal/utxo"
	"hundun/internal/wallet"
)

type fetcher struct {
	blocks []*block.Block // 按高度顺序（不含创世）
	height int
}

func (f *fetcher) PeerHeight(peer string) (int, error) { return f.height, nil }
func (f *fetcher) GetBlocks(peer string, fromHeight, count int) ([]*block.Block, error) {
	var out []*block.Block
	for h := fromHeight; h <= f.height && len(out) < count; h++ {
		out = append(out, f.blocks[h-1])
	}
	return out, nil
}

func mineParallel(t *testing.T, parent *block.Block, txs []*transaction.Transaction, ts uint32) *block.Block {
	t.Helper()
	b := block.NewCandidateBlock(parent.Header.Hash(), 0x207fffff, txs)
	b.Header.Timestamp = ts
	if found, _ := pow.MineParallel(b, 2); !found {
		t.Fatalf("并行挖矿失败")
	}
	return b
}

func TestFullFlow(t *testing.T) {
	w1, _ := wallet.NewWallet()
	w2, _ := wallet.NewWallet()

	// 1) 创世（易难度，Coinbase 付给 w1）。
	genesis := block.NewCandidateBlock([32]byte{}, 0x207fffff,
		[]*transaction.Transaction{transaction.NewCoinbaseTx(w1.PubKeyHash(), params.GetBlockSubsidy(0))})
	genesis.Header.Timestamp = uint32(time.Now().Unix()) - 200*600
	if found, _ := pow.MineParallel(genesis, 2); !found {
		t.Fatalf("创世并行挖矿失败")
	}
	chain := blockchain.NewBlockchainWithGenesis(genesis)
	genesisTxID := genesis.Transactions[0].Hash()

	// 2) 并行挖 100 块（高度 1..100），使创世 Coinbase 成熟。
	tip := genesis
	for h := 1; h <= 100; h++ {
		cb := transaction.NewCoinbaseTxWithData([20]byte{2}, params.GetBlockSubsidy(uint64(h)), []byte(fmt.Sprintf("int-%d", h)))
		b := mineParallel(t, tip, []*transaction.Transaction{cb}, tip.Header.Timestamp+600)
		if err := chain.AddBlock(b); err != nil {
			t.Fatalf("高度 %d 追加失败: %v", h, err)
		}
		tip = b
	}
	if chain.Height() != 100 {
		t.Fatalf("高度 = %d, want 100", chain.Height())
	}

	// 3) 转账：w1 花创世 Coinbase（成熟），付 1000 给 w2，手续费 5000。
	fee := uint64(5000)
	spend := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: genesisTxID, OutIndex: 0}},
		Outputs: []transaction.TxOutput{{Value: 1000, PubKeyHash: w2.PubKeyHash()}},
	}
	change := params.GetBlockSubsidy(0) - 1000 - fee
	spend.Outputs = append(spend.Outputs, transaction.TxOutput{Value: change, PubKeyHash: w1.PubKeyHash()})
	if err := w1.SignTx(spend); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	pool := mempool.New()
	if err := pool.Add(spend, chain.UTXOSet(), chain.Height()+1); err != nil {
		t.Fatalf("转账入池失败: %v", err)
	}

	// 4) 打包：Mempool 选中交易，Coinbase = 补贴 + 费，并行挖出高度 101。
	selected, totalFee := pool.SelectForBlock(params.MaxBlockWeight, chain.UTXOSet())
	if len(selected) != 1 || totalFee != fee {
		t.Fatalf("打包选中 %d 笔、费 %d，want 1/%d", len(selected), totalFee, fee)
	}
	txs := mempool.PackBlock(params.GetBlockSubsidy(101)+totalFee, [20]byte{2}, selected)
	b101 := mineParallel(t, tip, txs, tip.Header.Timestamp+600)
	if err := chain.AddBlock(b101); err != nil {
		t.Fatalf("高度 101 追加失败: %v", err)
	}
	pool.RemoveConfirmed(b101.Transactions)
	if pool.Len() != 0 {
		t.Errorf("确认后 Mempool 应为空，got %d", pool.Len())
	}
	// UTXO：w2 应有 1000 的 UTXO。
	foundW2 := false
	for _, e := range chain.UTXOSet().Snapshot() {
		if e.Output.PubKeyHash == w2.PubKeyHash() && e.Output.Value == 1000 {
			foundW2 = true
		}
	}
	if !foundW2 {
		t.Errorf("w2 的 1000 UTXO 未找到")
	}

	// 5) 同步：新节点从创世同步到高度 101，UTXO 一致。
	chain2 := blockchain.NewBlockchainWithGenesis(genesis)
	var chainBlocks []*block.Block
	for h := 1; h <= 101; h++ {
		b, _ := chain.BlockAt(h)
		chainBlocks = append(chainBlocks, b)
	}
	sy := chainsync.New(chain2)
	n, err := sy.SyncFromPeer("peer1", &fetcher{blocks: chainBlocks, height: 101})
	if err != nil {
		t.Fatalf("同步失败: %v", err)
	}
	if n != 101 || chain2.Height() != 101 {
		t.Fatalf("同步后高度 = %d（同步 %d 块），want 101", chain2.Height(), n)
	}
	if chain2.UTXOSet().Len() != chain.UTXOSet().Len() {
		t.Errorf("同步后 UTXO 数 = %d，源链 = %d", chain2.UTXOSet().Len(), chain.UTXOSet().Len())
	}

	// 6) 分叉重组：在 chain2 上造分叉 F1（高度 101'，父=块100）+ F2（高度 102'），
	// 累计工作量超过主链，触发重组；被挤出的转账交易可重新入池。
	block100, _ := chain2.BlockAt(100)
	f1 := mineParallel(t, block100,
		[]*transaction.Transaction{transaction.NewCoinbaseTxWithData([20]byte{3}, params.GetBlockSubsidy(101), []byte("fork-1"))},
		block100.Header.Timestamp+600)
	displaced, reorged, err := chain2.AddBlockWithResult(f1)
	if err != nil {
		t.Fatalf("分叉 F1 追加失败: %v", err)
	}
	if reorged {
		t.Errorf("F1 累计工作量未超主链，不应重组")
	}
	f2 := mineParallel(t, f1,
		[]*transaction.Transaction{transaction.NewCoinbaseTxWithData([20]byte{3}, params.GetBlockSubsidy(102), []byte("fork-2"))},
		f1.Header.Timestamp+600)
	displaced, reorged, err = chain2.AddBlockWithResult(f2)
	if err != nil {
		t.Fatalf("分叉 F2 追加失败: %v", err)
	}
	if !reorged {
		t.Errorf("F2 累计工作量超主链，应触发重组")
	}
	tip2, _ := chain2.Tip()
	if tip2.Header.Hash() != f2.Header.Hash() {
		t.Errorf("重组后链尾应为 F2")
	}
	// 被挤出的转账交易（1 笔）应可重新入池（创世 UTXO 已回滚恢复）。
	if len(displaced) != 1 {
		t.Errorf("displaced = %d 笔，want 1（被挤出的转账）", len(displaced))
	}
	pool2 := mempool.New()
	for _, tx := range displaced {
		if err := pool2.Add(tx, chain2.UTXOSet(), chain2.Height()+1); err != nil {
			t.Errorf("被挤出交易重新入池失败: %v", err)
		}
	}
	_ = utxo.NewSet
}
