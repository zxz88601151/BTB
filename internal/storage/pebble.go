// Pebble 持久化后端：实现 BlockStore 接口 + UTXO 持久化方法。
//
// 键设计（全部键均为字节串，前缀用于范围扫描；值说明见各键注释）：
//
//	b-<hash hex>            -> 区块 JSON（encoding/json，与 Block 结构体一致，不自造二进制格式）
//	h-<height 8 字节大端>   -> 区块哈希（32 字节原始字节；按高度查需两次查询：先 h- 取哈希，再 b- 取区块）
//	meta/height             -> 最佳高度（8 字节大端 int64；空库无此键，Height() 返回 -1）
//	meta/besthash           -> 最佳区块哈希（32 字节原始字节；与 meta/height 在同一 Batch 内原子更新）
//	utxo-<txid hex>-<index> -> UTXO JSON（UTXOEntry：输出 + 产生高度 + 是否 Coinbase + 所在区块哈希；
//	                           index 为十进制 OutIndex；前缀 "utxo-" 供 IterateUTXO 范围扫描）
//
// 语义：
//   - SaveBlock 为追加语义（与 MemoryBlockStore 一致）：写入高度 = 当前最佳高度 + 1；
//     空库第一块为高度 0。分叉块（同高度覆盖）不在本接口处理，重组逻辑由调用方负责。
//   - SaveBlock 用一个 Batch 原子提交（区块 + 高度索引 + meta），Commit 带 Sync，保证落盘。
//   - UTXO 读写各为单键操作，带 Sync；DeleteUTXO 删除不存在的键视为成功（与 map delete 一致）。
//   - 本文件不做钱包私钥存储（私钥须单独加密存储，绝不能与区块数据混放）。
package storage

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cockroachdb/pebble"

	"hundun/internal/block"
	"hundun/internal/transaction"
)

// 确认 PebbleStore 实现 BlockStore 接口。
var _ BlockStore = (*PebbleStore)(nil)

// PebbleStore 基于 Pebble 的持久化区块存储。
type PebbleStore struct {
	db *pebble.DB
}

// UTXOEntry 一个 UTXO 的持久化记录（与 utxo.Entry 同构，但定义在 storage 层，
// 避免 storage 依赖 utxo 包；集成时调用方在两者之间转换）。
type UTXOEntry struct {
	Output     transaction.TxOutput `json:"output"`      // 输出本身（金额 + 锁定地址）
	Height     int                  `json:"height"`      // 产生该输出的区块高度
	IsCoinbase bool                 `json:"is_coinbase"` // 是否来自 Coinbase 交易
	BlockHash  [32]byte             `json:"block_hash"`  // 所在区块哈希
}

var (
	metaHeightKey   = []byte("meta/height")
	metaBestHashKey = []byte("meta/besthash")
	utxoKeyPrefix   = []byte("utxo-")
)

// Open 打开 path 处的 Pebble 数据库（目录不存在则创建）。
func Open(path string) (*PebbleStore, error) {
	db, err := pebble.Open(path, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("打开 Pebble 数据库失败（%s）：%w", path, err)
	}
	return &PebbleStore{db: db}, nil
}

// Close 关闭数据库。关闭后继续调用其他方法将返回错误。
func (s *PebbleStore) Close() error {
	if s.db == nil {
		return errors.New("PebbleStore 已关闭")
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Flush 把内存表刷到 SST 文件（供关机前 / 检查点调用；正常 Close 也会落盘）。
func (s *PebbleStore) Flush() error {
	if s.db == nil {
		return errors.New("PebbleStore 已关闭")
	}
	return s.db.Flush()
}

func blockKey(hash [32]byte) []byte {
	return []byte("b-" + hex.EncodeToString(hash[:]))
}

func heightKey(height int) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(height))
	return append([]byte("h-"), buf[:]...)
}

func utxoKey(txID [32]byte, index uint32) []byte {
	return []byte("utxo-" + hex.EncodeToString(txID[:]) + "-" + strconv.FormatUint(uint64(index), 10))
}

func parseUTXOKey(key []byte) ([32]byte, uint32, error) {
	var txID [32]byte
	rest := strings.TrimPrefix(string(key), "utxo-")
	parts := strings.SplitN(rest, "-", 2)
	if len(parts) != 2 {
		return txID, 0, fmt.Errorf("UTXO 键格式非法：%q", string(key))
	}
	raw, err := hex.DecodeString(parts[0])
	if err != nil || len(raw) != 32 {
		return txID, 0, fmt.Errorf("UTXO 键 TxID 非法：%q", string(key))
	}
	copy(txID[:], raw)
	idx, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return txID, 0, fmt.Errorf("UTXO 键索引非法：%q", string(key))
	}
	return txID, uint32(idx), nil
}

func encodeHeight(height int) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(int64(height)))
	return buf[:]
}

func decodeHeight(raw []byte) (int, error) {
	if len(raw) != 8 {
		return 0, fmt.Errorf("meta/height 长度非法：%d 字节", len(raw))
	}
	return int(int64(binary.BigEndian.Uint64(raw))), nil
}

// SaveBlockAtHeight 在指定高度保存一块（重组/重放用：同高度覆盖旧块）。
// 与 SaveBlock 不同，本函数不改变 meta/height 与 meta/besthash
// （调用方在确认新最佳高度后自行调用 SetBest 推进）；若 height 超出
// 当前最佳高度 + 1，返回错误（防空洞）。
func (s *PebbleStore) SaveBlockAtHeight(b *block.Block, height int) error {
	if s.db == nil {
		return errors.New("PebbleStore 已关闭")
	}
	if b == nil {
		return errors.New("SaveBlockAtHeight：区块为 nil")
	}
	if height < 0 {
		return errors.New("SaveBlockAtHeight：高度为负")
	}
	best, err := s.Height()
	if err != nil {
		return err
	}
	if height > best+1 {
		return fmt.Errorf("SaveBlockAtHeight：高度 %d 超出最佳高度 %d + 1，存在空洞", height, best)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("区块 JSON 序列化失败：%w", err)
	}
	hash := b.Header.Hash()
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(blockKey(hash), raw, nil); err != nil {
		return err
	}
	if err := batch.Set(heightKey(height), hash[:], nil); err != nil {
		return err
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("SaveBlockAtHeight 提交失败：%w", err)
	}
	return nil
}

// SetBest 推进最佳高度与最佳哈希（与 SaveBlockAtHeight 配合，重组时调用）。
func (s *PebbleStore) SetBest(height int, hash [32]byte) error {
	if s.db == nil {
		return errors.New("PebbleStore 已关闭")
	}
	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(metaHeightKey, encodeHeight(height), nil); err != nil {
		return err
	}
	if err := batch.Set(metaBestHashKey, hash[:], nil); err != nil {
		return err
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("SetBest 提交失败：%w", err)
	}
	return nil
}

// SaveBlock 追加保存一块，高度 = 当前最佳高度 + 1（空库第一块为高度 0）。
func (s *PebbleStore) SaveBlock(b *block.Block) error {
	if s.db == nil {
		return errors.New("PebbleStore 已关闭")
	}
	if b == nil {
		return errors.New("SaveBlock：区块为 nil")
	}
	height, err := s.Height()
	if err != nil {
		return err
	}
	next := height + 1
	hash := b.Header.Hash()

	raw, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("区块 JSON 序列化失败：%w", err)
	}

	batch := s.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(blockKey(hash), raw, nil); err != nil {
		return err
	}
	if err := batch.Set(heightKey(next), hash[:], nil); err != nil {
		return err
	}
	if err := batch.Set(metaHeightKey, encodeHeight(next), nil); err != nil {
		return err
	}
	if err := batch.Set(metaBestHashKey, hash[:], nil); err != nil {
		return err
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("SaveBlock 提交失败：%w", err)
	}
	return nil
}

// GetBlockByHash 按哈希取区块；不存在返回 ErrNotFound。
func (s *PebbleStore) GetBlockByHash(hash [32]byte) (*block.Block, error) {
	if s.db == nil {
		return nil, errors.New("PebbleStore 已关闭")
	}
	raw, closer, err := s.db.Get(blockKey(hash))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer closer.Close()
	var b block.Block
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("区块 JSON 反序列化失败：%w", err)
	}
	return &b, nil
}

// GetBlockByHeight 按高度取区块；不存在（负高度 / 超出最佳高度）返回 ErrNotFound。
func (s *PebbleStore) GetBlockByHeight(height int) (*block.Block, error) {
	if s.db == nil {
		return nil, errors.New("PebbleStore 已关闭")
	}
	if height < 0 {
		return nil, ErrNotFound
	}
	raw, closer, err := s.db.Get(heightKey(height))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer closer.Close()
	if len(raw) != 32 {
		return nil, fmt.Errorf("高度 %d 对应的哈希长度非法：%d 字节", height, len(raw))
	}
	var hash [32]byte
	copy(hash[:], raw)
	return s.GetBlockByHash(hash)
}

// Height 返回最佳高度；空库返回 -1（与 MemoryBlockStore 一致）。
func (s *PebbleStore) Height() (int, error) {
	if s.db == nil {
		return 0, errors.New("PebbleStore 已关闭")
	}
	raw, closer, err := s.db.Get(metaHeightKey)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return -1, nil
		}
		return 0, err
	}
	defer closer.Close()
	return decodeHeight(raw)
}

// BestHash 返回最佳区块哈希；空库返回 ErrNotFound。
func (s *PebbleStore) BestHash() ([32]byte, error) {
	var zero [32]byte
	if s.db == nil {
		return zero, errors.New("PebbleStore 已关闭")
	}
	raw, closer, err := s.db.Get(metaBestHashKey)
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return zero, ErrNotFound
		}
		return zero, err
	}
	defer closer.Close()
	if len(raw) != 32 {
		return zero, fmt.Errorf("meta/besthash 长度非法：%d 字节", len(raw))
	}
	var hash [32]byte
	copy(hash[:], raw)
	return hash, nil
}

// PutUTXO 新增/覆盖一个 UTXO。
func (s *PebbleStore) PutUTXO(txID [32]byte, index uint32, e UTXOEntry) error {
	if s.db == nil {
		return errors.New("PebbleStore 已关闭")
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("UTXO JSON 序列化失败：%w", err)
	}
	return s.db.Set(utxoKey(txID, index), raw, pebble.Sync)
}

// GetUTXO 查询一个 UTXO；不存在返回 ErrNotFound。
func (s *PebbleStore) GetUTXO(txID [32]byte, index uint32) (UTXOEntry, error) {
	var zero UTXOEntry
	if s.db == nil {
		return zero, errors.New("PebbleStore 已关闭")
	}
	raw, closer, err := s.db.Get(utxoKey(txID, index))
	if err != nil {
		if errors.Is(err, pebble.ErrNotFound) {
			return zero, ErrNotFound
		}
		return zero, err
	}
	defer closer.Close()
	var e UTXOEntry
	if err := json.Unmarshal(raw, &e); err != nil {
		return zero, fmt.Errorf("UTXO JSON 反序列化失败：%w", err)
	}
	return e, nil
}

// DeleteUTXO 删除一个 UTXO（花费时调用）；键不存在视为成功。
func (s *PebbleStore) DeleteUTXO(txID [32]byte, index uint32) error {
	if s.db == nil {
		return errors.New("PebbleStore 已关闭")
	}
	return s.db.Delete(utxoKey(txID, index), pebble.Sync)
}

// IterateUTXO 按键序遍历全部 UTXO；fn 返回错误时立即停止并返回该错误。
func (s *PebbleStore) IterateUTXO(fn func(txID [32]byte, index uint32, e UTXOEntry) error) error {
	if s.db == nil {
		return errors.New("PebbleStore 已关闭")
	}
	if fn == nil {
		return errors.New("IterateUTXO：回调为 nil")
	}
	// 上界 "utxo0"：'0'(0x30) > '-'(0x2D)，故所有 "utxo-..." 键都小于它。
	iter, err := s.db.NewIter(&pebble.IterOptions{
		LowerBound: utxoKeyPrefix,
		UpperBound: []byte("utxo0"),
	})
	if err != nil {
		return err
	}
	defer iter.Close()
	for iter.First(); iter.Valid(); iter.Next() {
		txID, index, err := parseUTXOKey(iter.Key())
		if err != nil {
			return err
		}
		var e UTXOEntry
		if err := json.Unmarshal(iter.Value(), &e); err != nil {
			return fmt.Errorf("UTXO JSON 反序列化失败（键 %q）：%w", string(iter.Key()), err)
		}
		if err := fn(txID, index, e); err != nil {
			return err
		}
	}
	return iter.Error()
}
