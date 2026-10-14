package transaction

import (
	"testing"

	"hundun/internal/params"
)

// 费：fee = 输入 - 输出；输入 < 输出时拒绝。
func TestFeeFromInputValues(t *testing.T) {
	tx := &Transaction{
		Inputs:  []TxInput{{PrevTxHash: [32]byte{1}, OutIndex: 0}},
		Outputs: []TxOutput{{Value: 1000, PubKeyHash: [20]byte{2}}},
	}
	fee, ok := tx.FeeFromInputValues([]uint64{1500})
	if !ok || fee != 500 {
		t.Errorf("fee = %d ok=%v, want 500 true", fee, ok)
	}
	if _, ok := tx.FeeFromInputValues([]uint64{900}); ok {
		t.Errorf("输入 < 输出时应拒绝")
	}
}

// 粉尘：输出 < 546 为粉尘；546 恰为非粉尘边界。
func TestDust(t *testing.T) {
	if !IsDustOutput(TxOutput{Value: 545}) {
		t.Errorf("545 应为粉尘")
	}
	if IsDustOutput(TxOutput{Value: 546}) {
		t.Errorf("546 应为非粉尘边界")
	}
	tx := &Transaction{Outputs: []TxOutput{{Value: 546}, {Value: 100}}}
	if !tx.ContainsDust() {
		t.Errorf("含 100 的交易应含粉尘")
	}
}

// 最低中继费率：fee >= size * 1（冻结表 §7.2）。
func TestMeetsMinRelayFee(t *testing.T) {
	tx := &Transaction{
		Inputs:  []TxInput{{PrevTxHash: [32]byte{1}, OutIndex: 0, Signature: []byte("sig"), PubKey: []byte("pk")}},
		Outputs: []TxOutput{{Value: 1000, PubKeyHash: [20]byte{2}}},
	}
	size := tx.SerializedSize()
	if size <= 0 {
		t.Fatalf("SerializedSize 应 > 0")
	}
	if !tx.MeetsMinRelayFee(uint64(size)) {
		t.Errorf("fee == size 应满足最低中继费率")
	}
	if tx.MeetsMinRelayFee(uint64(size) - 1) {
		t.Errorf("fee == size-1 应不满足最低中继费率")
	}
}

// Coinbase TxID 必须计入附带数据（报文）：改报文 -> TxID 变化；
// 普通交易签名本身仍不计入 TxID：改签名 -> TxID 不变。
func TestCoinbaseTxIDIncludesData(t *testing.T) {
	pkh := [20]byte{7}
	a := NewCoinbaseTxWithData(pkh, params.GetBlockSubsidy(0), []byte("HUNDUN A"))
	b := NewCoinbaseTxWithData(pkh, params.GetBlockSubsidy(0), []byte("HUNDUN B"))
	if a.Hash() == b.Hash() {
		t.Errorf("Coinbase 报文不同时 TxID 应不同")
	}
	// 同报文同输出 -> TxID 相同（确定性）。
	a2 := NewCoinbaseTxWithData(pkh, params.GetBlockSubsidy(0), []byte("HUNDUN A"))
	if a.Hash() != a2.Hash() {
		t.Errorf("同报文同输出时 TxID 应相同")
	}
}

func TestNormalTxIDExcludesSignature(t *testing.T) {
	mk := func(sig []byte) *Transaction {
		return &Transaction{
			Inputs:  []TxInput{{PrevTxHash: [32]byte{1}, OutIndex: 0, Signature: sig, PubKey: []byte("pk")}},
			Outputs: []TxOutput{{Value: 1000, PubKeyHash: [20]byte{2}}},
		}
	}
	if mk([]byte("sig1")).Hash() != mk([]byte("sig2")).Hash() {
		t.Errorf("普通交易改签名时 TxID 应不变")
	}
}

// SerializedSize：计数开销 + 字段尺寸，与定义一致。
func TestSerializedSize(t *testing.T) {
	tx := NewCoinbaseTx([20]byte{1}, 100)
	// 4（输入计数）+ (32+4+4+0+4+0) + 4（输出计数）+ (8+20) = 80
	if got := tx.SerializedSize(); got != 80 {
		t.Errorf("空附带数据 Coinbase SerializedSize = %d, want 80", got)
	}
	tx2 := NewCoinbaseTxWithData([20]byte{1}, 100, []byte("12345"))
	if got := tx2.SerializedSize(); got != 85 {
		t.Errorf("5 字节报文 Coinbase SerializedSize = %d, want 85", got)
	}
}
