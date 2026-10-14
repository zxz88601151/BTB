package block

import (
	"encoding/binary"
	"testing"

	"hundun/internal/transaction"
)

// 区块头恒 80 字节、定长小端（冻结表 §2.3）。
func TestSerializeHeader80BytesLittleEndian(t *testing.T) {
	var prev, merkle [32]byte
	for i := range prev {
		prev[i] = byte(i)
		merkle[i] = byte(255 - i)
	}
	h := Header{
		Version:       1,
		PrevBlockHash: prev,
		MerkleRoot:    merkle,
		Timestamp:     0x01020304,
		Bits:          0x1d00ffff,
		Nonce:         0x0a0b0c0d,
	}
	ser := h.SerializeHeader()
	if len(ser) != 80 {
		t.Fatalf("SerializeHeader 长度 = %d, want 80", len(ser))
	}
	if binary.LittleEndian.Uint32(ser[0:4]) != 1 {
		t.Errorf("Version 应为小端 1")
	}
	if binary.LittleEndian.Uint32(ser[68:72]) != 0x01020304 {
		t.Errorf("Timestamp 位置/字节序错误")
	}
	if binary.LittleEndian.Uint32(ser[72:76]) != 0x1d00ffff {
		t.Errorf("Bits 位置/字节序错误")
	}
	if binary.LittleEndian.Uint32(ser[76:80]) != 0x0a0b0c0d {
		t.Errorf("Nonce 位置/字节序错误")
	}
	for i := 0; i < 32; i++ {
		if ser[4+i] != byte(i) || ser[36+i] != byte(255-i) {
			t.Errorf("Prev/Merkle 位置错误，i=%d", i)
			break
		}
	}
}

// Merkle：单笔交易时根 = TxID；奇数时最后一笔自拼（与双 SHA-256 逐级哈希一致）。
func TestMerkleRootSingleTx(t *testing.T) {
	tx := transaction.NewCoinbaseTx([20]byte{9}, 50_000_000)
	root := ComputeMerkleRoot([]*transaction.Transaction{tx})
	if root != tx.Hash() {
		t.Errorf("单笔交易 Merkle 根应 = TxID")
	}
}

// 块尺寸 / 权重：80 + 交易尺寸，weight = size*4。
func TestBlockSizeWeight(t *testing.T) {
	tx := transaction.NewCoinbaseTx([20]byte{1}, 50_000_000)
	b := NewCandidateBlock([32]byte{}, 0x1d00ffff, []*transaction.Transaction{tx})
	want := 80 + tx.SerializedSize()
	if b.Size() != want {
		t.Errorf("Size = %d, want %d", b.Size(), want)
	}
	if b.Weight() != want*4 {
		t.Errorf("Weight = %d, want %d", b.Weight(), want*4)
	}
}
