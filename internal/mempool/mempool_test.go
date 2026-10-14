package mempool

import (
	"testing"
	"time"

	"hundun/internal/params"
	"hundun/internal/transaction"
	"hundun/internal/utxo"
	"hundun/internal/wallet"
)

// 构造一个 UTXO 集合：钱包 w 的一个 100000 base units 普通 UTXO。
func setupUTXO(t *testing.T, w *wallet.Wallet) (*utxo.Set, [32]byte) {
	t.Helper()
	s := utxo.NewSet()
	funding := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: [32]byte{1}, OutIndex: 0}},
		Outputs: []transaction.TxOutput{{Value: 100000, PubKeyHash: w.PubKeyHash()}},
	}
	// 直接用伪造的 funding TxID 作为 UTXO 来源（Mempool 只查 UTXO 集合，不查 funding 本身）。
	txID := funding.Hash()
	s.Put(utxo.Key{TxID: txID, OutIndex: 0}, utxo.Entry{Output: funding.Outputs[0], Height: 0, IsCoinbase: false})
	return s, txID
}

func mustTx(t *testing.T, w *wallet.Wallet, prevTxID [32]byte, outIdx uint32, to [20]byte, amount, fee uint64) *transaction.Transaction {
	t.Helper()
	tx := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: prevTxID, OutIndex: outIdx}},
		Outputs: []transaction.TxOutput{{Value: amount, PubKeyHash: to}},
	}
	// 找零：输入 100000（测试固定），找零 = 100000 - amount - fee。
	tx.Outputs = append(tx.Outputs, transaction.TxOutput{Value: 100000 - amount - fee, PubKeyHash: w.PubKeyHash()})
	if err := w.SignTx(tx); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	return tx
}

func TestAddAndSelectByFeeRate(t *testing.T) {
	w, _ := wallet.NewWallet()
	s, fundingID := setupUTXO(t, w)
	to, _ := wallet.NewWallet()
	pool := New()
	// 高费率交易（费 10000）应排在低费率（费 500，尺寸约 241 字节，费率 > 1/字节）前面。
	low := mustTx(t, w, fundingID, 0, to.PubKeyHash(), 1000, 500)
	// low 与 high 花同一个 UTXO：high 入池后 low 应因双花被拒绝——改用第二个 UTXO。
	s2 := s
	_ = s2
	// 为 high 单独准备第二个 UTXO。
	funding2 := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: [32]byte{2}, OutIndex: 0}},
		Outputs: []transaction.TxOutput{{Value: 100000, PubKeyHash: w.PubKeyHash()}},
	}
	funding2ID := funding2.Hash()
	s.Put(utxo.Key{TxID: funding2ID, OutIndex: 0}, utxo.Entry{Output: funding2.Outputs[0], Height: 0, IsCoinbase: false})
	high := mustTx(t, w, funding2ID, 0, to.PubKeyHash(), 1000, 10000)
	if err := pool.Add(low, s, 1); err != nil {
		t.Fatalf("低费率入池失败: %v", err)
	}
	if err := pool.Add(high, s, 1); err != nil {
		t.Fatalf("高费率入池失败: %v", err)
	}
	sorted := pool.Sorted()
	if sorted[0].Tx.Hash() != high.Hash() {
		t.Errorf("费率排序：首位应为高费率交易")
	}
	// 打包：两者都应被选中（权重充足）。
	selected, totalFee := pool.SelectForBlock(params.MaxBlockWeight, s)
	if len(selected) != 2 {
		t.Errorf("打包选中 = %d 笔，want 2", len(selected))
	}
	if totalFee != 10500 {
		t.Errorf("打包总费 = %d, want 10500", totalFee)
	}
}

func TestAddRejects(t *testing.T) {
	w, _ := wallet.NewWallet()
	s, fundingID := setupUTXO(t, w)
	to, _ := wallet.NewWallet()
	pool := New()

	// 粉尘：输出 < 546。
	dust := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: fundingID, OutIndex: 0}},
		Outputs: []transaction.TxOutput{{Value: 100, PubKeyHash: to.PubKeyHash()}, {Value: 100000 - 100 - 100, PubKeyHash: w.PubKeyHash()}},
	}
	if err := w.SignTx(dust); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if err := pool.Add(dust, s, 1); err != ErrDust {
		t.Errorf("粉尘交易应被 ErrDust 拒绝，got %v", err)
	}

	// 低于最低中继费率：费 0（尺寸约 100+ 字节，费须 >= 尺寸）。
	zeroFee := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: fundingID, OutIndex: 0}},
		Outputs: []transaction.TxOutput{{Value: 1000, PubKeyHash: to.PubKeyHash()}, {Value: 99000, PubKeyHash: w.PubKeyHash()}},
	}
	if err := w.SignTx(zeroFee); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if err := pool.Add(zeroFee, s, 1); err != ErrLowFee {
		t.Errorf("零费交易应被 ErrLowFee 拒绝，got %v", err)
	}

	// 池内双花：两笔花同一 UTXO，第二笔拒绝（无 RBF）。
	first := mustTx(t, w, fundingID, 0, to.PubKeyHash(), 1000, 500)
	if err := pool.Add(first, s, 1); err != nil {
		t.Fatalf("首笔入池失败: %v", err)
	}
	second := mustTx(t, w, fundingID, 0, to.PubKeyHash(), 2000, 500)
	if err := pool.Add(second, s, 1); err != ErrDoubleSpend {
		t.Errorf("池内双花应被 ErrDoubleSpend 拒绝，got %v", err)
	}

	// Coinbase 入池拒绝。
	cb := transaction.NewCoinbaseTx(w.PubKeyHash(), params.GetBlockSubsidy(1))
	if err := pool.Add(cb, s, 1); err != ErrCoinbase {
		t.Errorf("Coinbase 应被 ErrCoinbase 拒绝，got %v", err)
	}
}

func TestAncestorTxAndPrune(t *testing.T) {
	w, _ := wallet.NewWallet()
	s, fundingID := setupUTXO(t, w)
	to, _ := wallet.NewWallet()
	pool := New()
	parent := mustTx(t, w, fundingID, 0, to.PubKeyHash(), 1000, 500)
	if err := pool.Add(parent, s, 1); err != nil {
		t.Fatalf("父交易入池失败: %v", err)
	}
	// 子交易花费父交易的输出（父未确认）：允许入池。
	// 父交易输出：[0]=1000 给 to，[1]=找零 98500 给 w。子交易花父交易的找零输出（w 的钱，w 签名）。
	child := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: parent.Hash(), OutIndex: 1}},
		Outputs: []transaction.TxOutput{{Value: 1000, PubKeyHash: to.PubKeyHash()}, {Value: 98500 - 1000 - 500, PubKeyHash: w.PubKeyHash()}},
	}
	if err := w.SignTx(child); err != nil {
		t.Fatalf("子交易签名失败: %v", err)
	}
	if err := pool.Add(child, s, 1); err != nil {
		t.Fatalf("子交易（祖先）入池应允许: %v", err)
	}
	// Prune：UTXO 不变时父子都在；删除父交易后 Prune 应连带删子交易（输入失效）。
	pool.Remove(parent.Hash())
	pool.Prune(s)
	if _, ok := pool.Get(child.Hash()); ok {
		t.Errorf("父交易删除后 Prune 应删子交易")
	}
}

func TestExpiry(t *testing.T) {
	w, _ := wallet.NewWallet()
	s, fundingID := setupUTXO(t, w)
	to, _ := wallet.NewWallet()
	pool := NewWithLimits(DefaultMaxTx, DefaultMaxBytes, time.Hour)
	tx := mustTx(t, w, fundingID, 0, to.PubKeyHash(), 1000, 500)
	if err := pool.Add(tx, s, 1); err != nil {
		t.Fatalf("入池失败: %v", err)
	}
	pool.Expire(time.Now().Add(2 * time.Hour))
	if pool.Len() != 0 {
		t.Errorf("过期后池应为空，got %d", pool.Len())
	}
}
