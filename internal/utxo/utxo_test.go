package utxo

import (
	"testing"

	"hundun/internal/block"
	"hundun/internal/params"
	"hundun/internal/transaction"
	"hundun/internal/wallet"
)

// 构造一笔已签名的花费交易：花费 utxoKey 对应的 UTXO，付给 to，找零回 from。
func mustSignedTx(t *testing.T, w *wallet.Wallet, prevTxHash [32]byte, outIdx uint32, to [20]byte, amount, change uint64) *transaction.Transaction {
	t.Helper()
	tx := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: prevTxHash, OutIndex: outIdx}},
		Outputs: []transaction.TxOutput{{Value: amount, PubKeyHash: to}, {Value: change, PubKeyHash: w.PubKeyHash()}},
	}
	if err := w.SignTx(tx); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	return tx
}

func TestValidateTxValidAndFee(t *testing.T) {
	w, _ := wallet.NewWallet()
	s := NewSet()
	// 模拟一个成熟的 Coinbase UTXO（高度 0，在高度 100 花费）。
	coinbaseTx := transaction.NewCoinbaseTx(w.PubKeyHash(), params.GetBlockSubsidy(0))
	txID := coinbaseTx.Hash()
	s.Put(Key{TxID: txID, OutIndex: 0}, Entry{Output: coinbaseTx.Outputs[0], Height: 0, IsCoinbase: true})
	to, _ := wallet.NewWallet()
	tx := mustSignedTx(t, w, txID, 0, to.PubKeyHash(), 1000, params.GetBlockSubsidy(0)-1000-500)
	fee, err := ValidateTx(tx, 100, s, map[Key]bool{})
	if err != nil {
		t.Fatalf("有效交易应通过: %v", err)
	}
	if fee != 500 {
		t.Errorf("手续费 = %d, want 500", fee)
	}
}

func TestValidateTxRejects(t *testing.T) {
	w, _ := wallet.NewWallet()
	s := NewSet()
	coinbaseTx := transaction.NewCoinbaseTx(w.PubKeyHash(), params.GetBlockSubsidy(0))
	txID := coinbaseTx.Hash()
	s.Put(Key{TxID: txID, OutIndex: 0}, Entry{Output: coinbaseTx.Outputs[0], Height: 0, IsCoinbase: true})
	to, _ := wallet.NewWallet()

	// 未成熟花费（高度 99）。
	tx := mustSignedTx(t, w, txID, 0, to.PubKeyHash(), 1000, params.GetBlockSubsidy(0)-1000)
	if _, err := ValidateTx(tx, 99, s, map[Key]bool{}); err != ErrImmatureCoinbase {
		t.Errorf("未成熟 Coinbase 花费应被 ErrImmatureCoinbase 拒绝，got %v", err)
	}

	// 不存在的 UTXO。
	tx2 := mustSignedTx(t, w, [32]byte{9}, 0, to.PubKeyHash(), 1000, 0)
	if _, err := ValidateTx(tx2, 100, s, map[Key]bool{}); err != ErrUTXONotFound {
		t.Errorf("不存在的 UTXO 应被 ErrUTXONotFound 拒绝，got %v", err)
	}

	// 同块内双花。
	spent := map[Key]bool{}
	if _, err := ValidateTx(tx, 100, s, spent); err != nil {
		t.Fatalf("首次校验应通过: %v", err)
	}
	if _, err := ValidateTx(tx, 100, s, spent); err != ErrDoubleSpend {
		t.Errorf("同块内双花应被 ErrDoubleSpend 拒绝，got %v", err)
	}

	// 坏签名（篡改输出后签名失效）。
	tx3 := mustSignedTx(t, w, txID, 0, to.PubKeyHash(), 1000, params.GetBlockSubsidy(0)-1000)
	tx3.Outputs[0].Value = 2000 // 签名后篡改，TxID 变化，签名失效
	if _, err := ValidateTx(tx3, 100, s, map[Key]bool{}); err != ErrBadSignature {
		t.Errorf("坏签名应被 ErrBadSignature 拒绝，got %v", err)
	}

	// 输入和 < 输出和（用一个小额 UTXO 构造）。
	small := transaction.NewCoinbaseTx(w.PubKeyHash(), 100)
	smallID := small.Hash()
	s.Put(Key{TxID: smallID, OutIndex: 0}, Entry{Output: small.Outputs[0], Height: 0, IsCoinbase: false})
	tx4 := &transaction.Transaction{
		Inputs:  []transaction.TxInput{{PrevTxHash: smallID, OutIndex: 0}},
		Outputs: []transaction.TxOutput{{Value: 200, PubKeyHash: to.PubKeyHash()}},
	}
	if err := w.SignTx(tx4); err != nil {
		t.Fatalf("签名失败: %v", err)
	}
	if _, err := ValidateTx(tx4, 100, s, map[Key]bool{}); err != ErrNegativeFee {
		t.Errorf("输入 < 输出应被 ErrNegativeFee 拒绝，got %v", err)
	}
}

func TestApplyRollbackBlock(t *testing.T) {
	w, _ := wallet.NewWallet()
	s := NewSet()
	coinbaseTx := transaction.NewCoinbaseTx(w.PubKeyHash(), params.GetBlockSubsidy(0))
	genesisTxID := coinbaseTx.Hash()
	s.Put(Key{TxID: genesisTxID, OutIndex: 0}, Entry{Output: coinbaseTx.Outputs[0], Height: 0, IsCoinbase: true})

	to, _ := wallet.NewWallet()
	spend := mustSignedTx(t, w, genesisTxID, 0, to.PubKeyHash(), 1000, params.GetBlockSubsidy(0)-1000-10)
	b := &block.Block{
		Header:       block.Header{Version: 1, Timestamp: 1000, Bits: 0x207fffff},
		Transactions: []*transaction.Transaction{transaction.NewCoinbaseTx([20]byte{2}, params.GetBlockSubsidy(1)), spend},
	}
	undo, err := s.ApplyBlock(b, 100)
	if err != nil {
		t.Fatalf("ApplyBlock 失败: %v", err)
	}
	if s.Has(Key{TxID: genesisTxID, OutIndex: 0}) {
		t.Errorf("花费后原 UTXO 应消失")
	}
	if s.Len() != 3 { // 新 Coinbase 1 + spend 的 2 个输出
		t.Errorf("Apply 后 UTXO 数 = %d, want 3", s.Len())
	}
	s.RollbackBlock(undo)
	if !s.Has(Key{TxID: genesisTxID, OutIndex: 0}) {
		t.Errorf("回滚后原 UTXO 应恢复")
	}
	if s.Len() != 1 {
		t.Errorf("回滚后 UTXO 数 = %d, want 1", s.Len())
	}
}
