package storage

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"hundun/internal/block"
	"hundun/internal/transaction"
)

// makeTestBlock 构造一棵高度链上的测试块：每块的 Coinbase 付给不同地址，Nonce 不同，
// 保证相邻块哈希不同且链式链接（PrevBlockHash = 上一块哈希）。
func makeTestBlock(prevHash [32]byte, nonce uint32, minerByte byte) *block.Block {
	var minerHash [20]byte
	minerHash[0] = minerByte
	coinbase := transaction.NewCoinbaseTx(minerHash, 50*100_000_000)
	b := block.NewCandidateBlock(prevHash, 0x1d00ffff, []*transaction.Transaction{coinbase})
	b.Header.Nonce = nonce
	return b
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("JSON 序列化失败：%v", err)
	}
	return string(raw)
}

func TestPebbleStore_PersistAndReopen(t *testing.T) {
	dir := t.TempDir()

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open 失败：%v", err)
	}

	// 写 3 块：高度 0、1、2，链式链接。
	var prev [32]byte
	blocks := make([]*block.Block, 3)
	for i := range blocks {
		blocks[i] = makeTestBlock(prev, uint32(100+i), byte(0xA0+i))
		if err := s.SaveBlock(blocks[i]); err != nil {
			t.Fatalf("SaveBlock(%d) 失败：%v", i, err)
		}
		prev = blocks[i].Header.Hash()
	}

	if h, err := s.Height(); err != nil || h != 2 {
		t.Fatalf("关闭前 Height() = %d, err = %v，期望 2", h, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close 失败：%v", err)
	}

	// 重开，高度与区块内容必须一致。
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("重开 Open 失败：%v", err)
	}
	defer s2.Close()

	if h, err := s2.Height(); err != nil || h != 2 {
		t.Fatalf("重开后 Height() = %d, err = %v，期望 2", h, err)
	}
	for i, want := range blocks {
		got, err := s2.GetBlockByHeight(i)
		if err != nil {
			t.Fatalf("GetBlockByHeight(%d) 失败：%v", i, err)
		}
		if mustJSON(t, got) != mustJSON(t, want) {
			t.Fatalf("高度 %d 区块内容不一致：\n得到 %s\n期望 %s", i, mustJSON(t, got), mustJSON(t, want))
		}
		byHash, err := s2.GetBlockByHash(want.Header.Hash())
		if err != nil {
			t.Fatalf("GetBlockByHash(高度 %d) 失败：%v", i, err)
		}
		if !reflect.DeepEqual(byHash.Header.Hash(), want.Header.Hash()) {
			t.Fatalf("高度 %d 按哈希查到的区块哈希不一致", i)
		}
	}
	best, err := s2.BestHash()
	if err != nil {
		t.Fatalf("BestHash() 失败：%v", err)
	}
	if best != blocks[2].Header.Hash() {
		t.Fatalf("BestHash = %x，期望 %x", best, blocks[2].Header.Hash())
	}
}

func TestPebbleStore_UTXO(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open 失败：%v", err)
	}
	defer s.Close()

	var txID [32]byte
	txID[0] = 0x11
	txID[31] = 0x22
	var blockHash [32]byte
	blockHash[0] = 0x33
	var addr [20]byte
	addr[0] = 0x44

	want := UTXOEntry{
		Output:     transaction.TxOutput{Value: 12345, PubKeyHash: addr},
		Height:     7,
		IsCoinbase: true,
		BlockHash:  blockHash,
	}
	if err := s.PutUTXO(txID, 0, want); err != nil {
		t.Fatalf("PutUTXO 失败：%v", err)
	}
	if err := s.PutUTXO(txID, 1, UTXOEntry{
		Output: transaction.TxOutput{Value: 999, PubKeyHash: addr}, Height: 7,
	}); err != nil {
		t.Fatalf("PutUTXO(索引 1) 失败：%v", err)
	}

	got, err := s.GetUTXO(txID, 0)
	if err != nil {
		t.Fatalf("GetUTXO 失败：%v", err)
	}
	if mustJSON(t, got) != mustJSON(t, want) {
		t.Fatalf("GetUTXO 内容不一致：得到 %s，期望 %s", mustJSON(t, got), mustJSON(t, want))
	}

	// 遍历应看到 2 条，且能按索引区分。
	seen := map[uint32]uint64{}
	if err := s.IterateUTXO(func(id [32]byte, index uint32, e UTXOEntry) error {
		if id != txID {
			t.Errorf("IterateUTXO txID = %x，期望 %x", id, txID)
		}
		seen[index] = e.Output.Value
		return nil
	}); err != nil {
		t.Fatalf("IterateUTXO 失败：%v", err)
	}
	if len(seen) != 2 || seen[0] != 12345 || seen[1] != 999 {
		t.Fatalf("IterateUTXO 结果 = %v，期望 {0:12345 1:999}", seen)
	}

	// 删除后读不到，遍历只剩 1 条；删除不存在的键不报错。
	if err := s.DeleteUTXO(txID, 0); err != nil {
		t.Fatalf("DeleteUTXO 失败：%v", err)
	}
	if _, err := s.GetUTXO(txID, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删除后 GetUTXO 应返回 ErrNotFound，得到 err = %v", err)
	}
	if err := s.DeleteUTXO(txID, 99); err != nil {
		t.Fatalf("删除不存在的 UTXO 应成功，得到 err = %v", err)
	}
	count := 0
	if err := s.IterateUTXO(func([32]byte, uint32, UTXOEntry) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("删除后 IterateUTXO 失败：%v", err)
	}
	if count != 1 {
		t.Fatalf("删除后 IterateUTXO 数量 = %d，期望 1", count)
	}
}

func TestPebbleStore_GetBlockByHashAndHeight(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open 失败：%v", err)
	}
	defer s.Close()

	b := makeTestBlock([32]byte{}, 1, 0xB0)
	if err := s.SaveBlock(b); err != nil {
		t.Fatalf("SaveBlock 失败：%v", err)
	}

	if _, err := s.GetBlockByHeight(-1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("负高度应返回 ErrNotFound，得到 err = %v", err)
	}
	if _, err := s.GetBlockByHeight(1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("超出高度应返回 ErrNotFound，得到 err = %v", err)
	}
	var missing [32]byte
	missing[0] = 0xFF
	if _, err := s.GetBlockByHash(missing); !errors.Is(err, ErrNotFound) {
		t.Fatalf("不存在的哈希应返回 ErrNotFound，得到 err = %v", err)
	}
	if got, err := s.GetBlockByHash(b.Header.Hash()); err != nil || mustJSON(t, got) != mustJSON(t, b) {
		t.Fatalf("GetBlockByHash 内容不一致：err = %v", err)
	}
}

func TestPebbleStore_EmptyHeight(t *testing.T) {
	// 空库 Height() 返回 -1，与 MemoryBlockStore 一致。
	mem, err := NewMemoryBlockStore().Height()
	if err != nil || mem != -1 {
		t.Fatalf("Memory 空库 Height() = %d, err = %v，期望 -1", mem, err)
	}

	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open 失败：%v", err)
	}
	defer s.Close()

	if h, err := s.Height(); err != nil || h != -1 {
		t.Fatalf("Pebble 空库 Height() = %d, err = %v，期望 -1", h, err)
	}
	if _, err := s.GetBlockByHeight(0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("空库 GetBlockByHeight(0) 应返回 ErrNotFound，得到 err = %v", err)
	}
	if _, err := s.BestHash(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("空库 BestHash() 应返回 ErrNotFound，得到 err = %v", err)
	}
}
