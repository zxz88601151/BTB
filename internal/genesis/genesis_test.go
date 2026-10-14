package genesis

import (
	"testing"

	"hundun/internal/params"
)

// 创世报文精确 54 字节（冻结值）。
func TestMessageLength(t *testing.T) {
	if len(Message) != 54 {
		t.Errorf("创世报文长度 = %d, want 54", len(Message))
	}
	if Message != "HUNDUN 2026-10-14: Nvidia to invest $2B more in Europe" {
		t.Errorf("创世报文与冻结值不符")
	}
}

// 创世 Coinbase：输出 = 50 HUNDUN，附带数据 = 报文，TxID 计入报文。
func TestCoinbaseTx(t *testing.T) {
	tx, err := CoinbaseTx()
	if err != nil {
		t.Fatalf("CoinbaseTx err=%v", err)
	}
	if !tx.IsCoinbase() {
		t.Errorf("创世交易应为 Coinbase")
	}
	if len(tx.Outputs) != 1 || tx.Outputs[0].Value != params.GetBlockSubsidy(0) {
		t.Errorf("创世 Coinbase 输出应为 50 HUNDUN")
	}
	if string(tx.Inputs[0].Signature) != Message {
		t.Errorf("创世 Coinbase 附带数据应为创世报文")
	}
	pkh, _ := PubKeyHash()
	if tx.Outputs[0].PubKeyHash != pkh {
		t.Errorf("创世 Coinbase 归属 PubKeyHash 不符")
	}
}

// GenesisBlock() 回填后必须返回与常量一致的创世块（哈希 / TxID / 时间戳 / Nonce）。
func TestGenesisBlockMined(t *testing.T) {
	b, err := GenesisBlock()
	if err != nil {
		t.Fatalf("回填后 GenesisBlock() err=%v", err)
	}
	if b.Header.Hash() != Hash {
		t.Errorf("创世块哈希与常量不符")
	}
	if b.Header.MerkleRoot != TxID {
		t.Errorf("创世块 Merkle 根应 = TxID")
	}
	if b.Header.Timestamp != Timestamp || b.Header.Nonce != Nonce {
		t.Errorf("创世块时间戳/Nonce 与常量不符")
	}
	if b.Transactions[0].Hash() != TxID {
		t.Errorf("创世 Coinbase TxID 与常量不符")
	}
	if Timestamp != 1791971142 || Nonce != 423499407 {
		t.Errorf("创世 Timestamp/Nonce 与挖矿输出不符")
	}
}

// CandidateBlock 结构：Version=1，Prev 全零，Bits=GenesisBits，Merkle=TxID。
func TestCandidateBlock(t *testing.T) {
	b, err := CandidateBlock(1700000000)
	if err != nil {
		t.Fatalf("CandidateBlock err=%v", err)
	}
	if b.Header.Version != 1 {
		t.Errorf("Version 应为 1")
	}
	if b.Header.PrevBlockHash != ([32]byte{}) {
		t.Errorf("PrevHash 应全零")
	}
	if b.Header.Bits != params.GenesisBits {
		t.Errorf("Bits 应为 GenesisBits")
	}
	if b.Header.MerkleRoot != b.Transactions[0].Hash() {
		t.Errorf("单笔交易时 Merkle 根应 = TxID")
	}
}
