package blockchain

import (
	"fmt"
	"testing"
	"time"

	"hundun/internal/block"
	"hundun/internal/params"
	"hundun/internal/pow"
	"hundun/internal/transaction"
	"hundun/internal/utxo"
	"hundun/internal/wallet"
)

// distinctCoinbase 构造带高度/标签数据的 Coinbase，使不同块的 Coinbase TxID 互不相同
// （否则相同 Coinbase 在不同块重复出现会触发 BIP-30 式防重复拒绝）。
func distinctCoinbase(pkh [20]byte, value uint64, tag string) *transaction.Transaction {
	return transaction.NewCoinbaseTxWithData(pkh, value, []byte(tag))
}

// 挖一个指定父块/时间戳/交易的块（易难度 0x207fffff）。
func mineBlock(t *testing.T, parent *block.Block, txs []*transaction.Transaction, ts uint32) *block.Block {
	t.Helper()
	b := block.NewCandidateBlock(parent.Header.Hash(), 0x207fffff, txs)
	b.Header.Timestamp = ts
	if found, _ := pow.Mine(b, 100_000); !found {
		t.Fatalf("挖矿失败")
	}
	return b
}

// 创世 Coinbase 付给钱包 w 的链（便于后续花费创世 UTXO）。
func chainWithWalletGenesis(t *testing.T, w *wallet.Wallet) *Blockchain {
	t.Helper()
	genesis := block.NewCandidateBlock([32]byte{}, 0x207fffff,
		[]*transaction.Transaction{transaction.NewCoinbaseTx(w.PubKeyHash(), params.GetBlockSubsidy(0))})
	// 锚到过去：后续要挖 100+ 块，每块 +600 秒，锚到现在会导致时间戳超出“未来 7200 秒”上限。
	genesis.Header.Timestamp = uint32(time.Now().Unix()) - 101*600
	if found, _ := pow.Mine(genesis, 100_000); !found {
		t.Fatalf("创世挖矿失败")
	}
	return NewBlockchainWithGenesis(genesis)
}

// 真实手续费：成熟 Coinbase 花费 + Coinbase 申领手续费通过；超申领拒绝。
func TestValidateBlockRealFee(t *testing.T) {
	w, _ := wallet.NewWallet()
	bc := chainWithWalletGenesis(t, w)
	genesis, _ := bc.Tip()
	genesisTxID := genesis.Transactions[0].Hash()

	// 挖 100 块使创世 Coinbase 成熟（高度 100 时花费，100-0>=100）。
	for h := 1; h <= 100; h++ {
		tip, _ := bc.Tip()
		cb := distinctCoinbase([20]byte{2}, params.GetBlockSubsidy(uint64(h)), fmt.Sprintf("fee-chain-%d", h))
		b := mineBlock(t, tip, []*transaction.Transaction{cb}, tip.Header.Timestamp+600)
		if err := bc.AddBlock(b); err != nil {
			t.Fatalf("高度 %d 追加失败: %v", h, err)
		}
	}
	// 构造花费创世 UTXO 的交易，手续费 100。
	to, _ := wallet.NewWallet()
	spend := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: genesisTxID, OutIndex: 0}},
		Outputs: []transaction.TxOutput{{Value: 1000, PubKeyHash: to.PubKeyHash()}},
	}
	inVal := params.GetBlockSubsidy(0)
	spend.Outputs = append(spend.Outputs, transaction.TxOutput{Value: inVal - 1000 - 100, PubKeyHash: w.PubKeyHash()})
	if err := w.SignTx(spend); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	tip, _ := bc.Tip()
	fee := uint64(100)
	cbOK := distinctCoinbase([20]byte{2}, params.GetBlockSubsidy(101)+fee, "fee-ok-101")
	bOK := mineBlock(t, tip, []*transaction.Transaction{cbOK, spend}, tip.Header.Timestamp+600)
	if err := bc.ValidateBlock(bOK); err != nil {
		t.Fatalf("Coinbase 申领补贴+真实手续费应通过: %v", err)
	}
	if err := bc.AddBlock(bOK); err != nil {
		t.Fatalf("追加含手续费的块失败: %v", err)
	}
	// 双花：再花同一个创世 UTXO 应被拒绝（UTXO 已花费）。
	spend2 := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: genesisTxID, OutIndex: 0}},
		Outputs: []transaction.TxOutput{{Value: 1000, PubKeyHash: to.PubKeyHash()}},
	}
	if err := w.SignTx(spend2); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	tip2, _ := bc.Tip()
	cb2 := distinctCoinbase([20]byte{2}, params.GetBlockSubsidy(102), "fee-double-102")
	bDouble := mineBlock(t, tip2, []*transaction.Transaction{cb2, spend2}, tip2.Header.Timestamp+600)
	if err := bc.ValidateBlock(bDouble); err == nil {
		t.Errorf("跨块双花应被拒绝")
	}
	// 超申领：Coinbase 申领补贴+101（实际费 100）应被拒绝。
	// 需构造一笔新花费（用 bOK 中找零 UTXO）以产生真实手续费 100。
	changeTxID := spend.Hash()
	spend3 := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: changeTxID, OutIndex: 1}},
		Outputs: []transaction.TxOutput{{Value: 500, PubKeyHash: to.PubKeyHash()}},
	}
	changeVal := inVal - 1000 - 100
	spend3.Outputs = append(spend3.Outputs, transaction.TxOutput{Value: changeVal - 500 - 100, PubKeyHash: w.PubKeyHash()})
	if err := w.SignTx(spend3); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	tip3, _ := bc.Tip()
	cbOver := distinctCoinbase([20]byte{2}, params.GetBlockSubsidy(102)+101, "fee-over-102")
	bOver := mineBlock(t, tip3, []*transaction.Transaction{cbOver, spend3}, tip3.Header.Timestamp+600)
	if err := bc.ValidateBlock(bOver); err == nil {
		t.Errorf("Coinbase 超申领手续费应被拒绝")
	}
	// 坏签名：篡改 spend3 输出后签名失效。
	spendBad := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: changeTxID, OutIndex: 1}},
		Outputs: []transaction.TxOutput{{Value: 500, PubKeyHash: to.PubKeyHash()}, {Value: changeVal - 500 - 100, PubKeyHash: w.PubKeyHash()}},
	}
	if err := w.SignTx(spendBad); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	spendBad.Outputs[0].Value = 501 // 签名后篡改
	tip4, _ := bc.Tip()
	cb4 := distinctCoinbase([20]byte{2}, params.GetBlockSubsidy(102), "fee-badsig-102")
	bBad := mineBlock(t, tip4, []*transaction.Transaction{cb4, spendBad}, tip4.Header.Timestamp+600)
	if err := bc.ValidateBlock(bBad); err == nil {
		t.Errorf("坏签名交易应被拒绝")
	}
	_ = utxo.NewSet // 保证 utxo 包在测试中被引用（文档用）
}

// 分叉重组：低工作量链不重组；更高工作量分叉链触发重组，UTXO 与高度一致。
func TestForkReorgByCumulativeWork(t *testing.T) {
	bc := mustChain(t)
	genesis, _ := bc.BlockAt(0)

	// 主链：A1（高度1）、A2（高度2）。
	tip, _ := bc.Tip()
	a1 := mineBlock(t, tip, []*transaction.Transaction{distinctCoinbase([20]byte{2}, params.GetBlockSubsidy(1), "A1")}, tip.Header.Timestamp+600)
	if err := bc.AddBlock(a1); err != nil {
		t.Fatalf("A1 追加失败: %v", err)
	}
	tip, _ = bc.Tip()
	a2 := mineBlock(t, tip, []*transaction.Transaction{distinctCoinbase([20]byte{2}, params.GetBlockSubsidy(2), "A2")}, tip.Header.Timestamp+600)
	if err := bc.AddBlock(a2); err != nil {
		t.Fatalf("A2 追加失败: %v", err)
	}
	if bc.Height() != 2 {
		t.Fatalf("主链高度 = %d, want 2", bc.Height())
	}

	// 分叉：B1'（父=创世，累计工作量 2 < 主链 3），不重组。
	b1 := mineBlock(t, genesis, []*transaction.Transaction{distinctCoinbase([20]byte{3}, params.GetBlockSubsidy(1), "B1")}, genesis.Header.Timestamp+600)
	if err := bc.AddBlock(b1); err != nil {
		t.Fatalf("分叉 B1 应进索引不报错: %v", err)
	}
	if bc.Height() != 2 {
		t.Errorf("低工作量分叉不应重组，高度 = %d, want 2", bc.Height())
	}
	tipAfter, _ := bc.Tip()
	if tipAfter.Header.Hash() != a2.Header.Hash() {
		t.Errorf("低工作量分叉后链尾应仍为 A2")
	}

	// B2'：分叉累计工作量 3 = 主链 3，平局先到先赢，不重组。
	b2 := mineBlock(t, b1, []*transaction.Transaction{distinctCoinbase([20]byte{3}, params.GetBlockSubsidy(2), "B2")}, b1.Header.Timestamp+600)
	if err := bc.AddBlock(b2); err != nil {
		t.Fatalf("分叉 B2 应进索引: %v", err)
	}
	if bc.Height() != 2 {
		t.Errorf("平局分叉不应重组，高度 = %d, want 2", bc.Height())
	}

	// B3'：分叉累计工作量 4 > 主链 3，触发重组，主链变为 B 链（高度 3）。
	b3 := mineBlock(t, b2, []*transaction.Transaction{distinctCoinbase([20]byte{3}, params.GetBlockSubsidy(3), "B3")}, b2.Header.Timestamp+600)
	displaced, reorged, err := bc.AddBlockWithResult(b3)
	if err != nil {
		t.Fatalf("B3 追加失败: %v", err)
	}
	if !reorged {
		t.Errorf("更高工作量分叉应触发重组")
	}
	if bc.Height() != 3 {
		t.Fatalf("重组后高度 = %d, want 3", bc.Height())
	}
	tipFinal, _ := bc.Tip()
	if tipFinal.Header.Hash() != b3.Header.Hash() {
		t.Errorf("重组后链尾应为 B3")
	}
	// UTXO：创世 Coinbase 1 + B1'/B2'/B3' Coinbase 各 1 = 4；A1/A2 的 Coinbase 已回滚。
	if got := bc.UTXOSet().Len(); got != 4 {
		t.Errorf("重组后 UTXO 数 = %d, want 4", got)
	}
	// A1/A2 被挤出，无非 Coinbase 交易，故 displaced 为空。
	if len(displaced) != 0 {
		t.Errorf("displaced 应为空（被挤出块无非 Coinbase 交易），got %d", len(displaced))
	}
}

// 孤块：父块未到的块进孤块池，父块到达后自动接入。
func TestOrphanConnectsWhenParentArrives(t *testing.T) {
	bc := mustChain(t)
	tip, _ := bc.Tip()
	// 先造子块（父 = 尚未上链的中间块）。
	mid := mineBlock(t, tip, []*transaction.Transaction{distinctCoinbase([20]byte{2}, params.GetBlockSubsidy(1), "orphan-mid")}, tip.Header.Timestamp+600)
	child := mineBlock(t, mid, []*transaction.Transaction{distinctCoinbase([20]byte{2}, params.GetBlockSubsidy(2), "orphan-child")}, mid.Header.Timestamp+600)
	if err := bc.AddBlock(child); err != ErrOrphan {
		t.Errorf("父块未到时应返回 ErrOrphan，got %v", err)
	}
	if bc.OrphanCount() != 1 {
		t.Errorf("孤块池数量 = %d, want 1", bc.OrphanCount())
	}
	// 补上中间块，孤块应自动接入，主链高度 2。
	if err := bc.AddBlock(mid); err != nil {
		t.Fatalf("中间块追加失败: %v", err)
	}
	if bc.Height() != 2 {
		t.Errorf("孤块接入后高度 = %d, want 2", bc.Height())
	}
	if bc.OrphanCount() != 0 {
		t.Errorf("孤块接入后孤块池应为空，got %d", bc.OrphanCount())
	}
}
