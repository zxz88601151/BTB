// Package storage 定义持久化存储的接口骨架。
//
// 骨架阶段先给出接口和一个最简单的内存实现，方便先跑通主流程；
// 生产实现建议接入 LevelDB（比特币核心的选择）或 BoltDB/BadgerDB（Go 生态更常用）。
//
// 需要持久化的核心数据：
//   - 区块数据（按哈希、按高度两种索引）
//   - UTXO 集合（决定性能瓶颈所在，建议单独存储并做好索引）
//   - 节点自身的钱包私钥（务必加密存储，绝不能明文落盘）
package storage

import "p2pchain/internal/block"

// BlockStore 区块存储接口。
type BlockStore interface {
	SaveBlock(b *block.Block) error
	GetBlockByHash(hash [32]byte) (*block.Block, error)
	GetBlockByHeight(height int) (*block.Block, error)
	Height() (int, error)
}

// MemoryBlockStore 一个仅用于开发调试的内存实现，重启后数据会丢失。
type MemoryBlockStore struct {
	byHeight []*block.Block
	byHash   map[[32]byte]*block.Block
}

// NewMemoryBlockStore 创建内存存储实例。
func NewMemoryBlockStore() *MemoryBlockStore {
	return &MemoryBlockStore{
		byHash: make(map[[32]byte]*block.Block),
	}
}

func (s *MemoryBlockStore) SaveBlock(b *block.Block) error {
	s.byHeight = append(s.byHeight, b)
	s.byHash[b.Header.Hash()] = b
	return nil
}

func (s *MemoryBlockStore) GetBlockByHash(hash [32]byte) (*block.Block, error) {
	b, ok := s.byHash[hash]
	if !ok {
		return nil, ErrNotFound
	}
	return b, nil
}

func (s *MemoryBlockStore) GetBlockByHeight(height int) (*block.Block, error) {
	if height < 0 || height >= len(s.byHeight) {
		return nil, ErrNotFound
	}
	return s.byHeight[height], nil
}

func (s *MemoryBlockStore) Height() (int, error) {
	return len(s.byHeight) - 1, nil
}

// ErrNotFound 表示查询的数据不存在。
var ErrNotFound = errBlockNotFound{}

type errBlockNotFound struct{}

func (errBlockNotFound) Error() string { return "区块未找到" }

// TODO 切换到真实数据库时的建议：
//   1. 引入 go.etcd.io/bbolt 或 github.com/syndtr/goleveldb/leveldb
//   2. Key 设计：
//        b-<hash>      -> 区块序列化数据（按哈希查）
//        h-<height>    -> 对应的哈希（按高度查，需要两次查询）
//        utxo-<txid>-<index> -> 该输出是否仍未花费 + 金额 + 锁定脚本
//   3. 私钥文件单独加密存储（如用口令派生 AES 密钥），不要和区块数据放在一起
