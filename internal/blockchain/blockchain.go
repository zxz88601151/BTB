// Package blockchain 维护本地节点看到的区块链视图，负责：
//   - 区块的验证与追加
//   - 分叉处理（最长有效链原则，比特币称为"最大累积工作量"原则）
//   - 难度调整的触发
//
// 注意：这里给出的是内存版骨架，真实项目需要接入 internal/storage 做持久化，
// 并在启动时从磁盘重建内存索引。
package blockchain

import (
	"errors"
	"fmt"

	"p2pchain/internal/block"
	"p2pchain/internal/pow"
)

var (
	ErrInvalidPrevHash = errors.New("区块的前置哈希与当前链尾不匹配")
	ErrInvalidPoW      = errors.New("区块哈希未达到难度目标，工作量证明无效")
	ErrEmptyChain      = errors.New("链为空")
)

// Blockchain 内存中的区块链结构。
// blocks 按高度顺序存储；生产实现应改为哈希索引的 DAG 结构以支持分叉与重组。
type Blockchain struct {
	blocks []*block.Block
}

// NewBlockchainWithGenesis 使用给定的创世区块初始化链。
func NewBlockchainWithGenesis(genesis *block.Block) *Blockchain {
	return &Blockchain{blocks: []*block.Block{genesis}}
}

// Height 返回当前链的高度（创世区块高度为 0）。
func (bc *Blockchain) Height() int {
	return len(bc.blocks) - 1
}

// Tip 返回当前链尾（最新）区块。
func (bc *Blockchain) Tip() (*block.Block, error) {
	if len(bc.blocks) == 0 {
		return nil, ErrEmptyChain
	}
	return bc.blocks[len(bc.blocks)-1], nil
}

// CurrentBits 返回下一个待挖区块应当使用的难度目标。
// 骨架版本：只有到达调整周期的整数倍高度才重新计算，否则沿用链尾的难度。
func (bc *Blockchain) CurrentBits() uint32 {
	tip, err := bc.Tip()
	if err != nil {
		return pow.MaxTargetBits
	}
	height := bc.Height()
	if height == 0 || height%pow.DifficultyAdjustmentInterval != 0 {
		return tip.Header.Bits
	}

	periodStartHeight := height - pow.DifficultyAdjustmentInterval
	if periodStartHeight < 0 {
		periodStartHeight = 0
	}
	periodStart := bc.blocks[periodStartHeight]
	actualTimespan := tip.Header.Timestamp - periodStart.Header.Timestamp
	return pow.AdjustBits(tip.Header.Bits, actualTimespan)
}

// ValidateBlock 对一个待追加的区块做基础合法性校验：
//  1. 前置哈希是否指向当前链尾
//  2. 工作量证明是否满足难度目标
//
// 生产实现还需要校验：交易签名、UTXO 是否存在且未被双花、Coinbase 金额是否等于
// 区块奖励+手续费、时间戳是否在合理范围内等。这里先留出骨架和 TODO。
func (bc *Blockchain) ValidateBlock(b *block.Block) error {
	tip, err := bc.Tip()
	if err != nil {
		return err
	}
	if b.Header.PrevBlockHash != tip.Header.Hash() {
		return ErrInvalidPrevHash
	}
	if !pow.Validate(&b.Header) {
		return ErrInvalidPoW
	}

	// TODO: 校验每笔交易的输入签名（内含 ECDSA/Ed25519 验签逻辑）
	// TODO: 校验交易输入引用的 UTXO 确实存在且未被花费（维护一个 UTXO 集合）
	// TODO: 校验 Coinbase 输出金额 <= 当前区块奖励 + 交易手续费总和
	// TODO: 校验区块大小、交易数量等限制

	return nil
}

// AddBlock 校验并把区块追加到链尾。
func (bc *Blockchain) AddBlock(b *block.Block) error {
	if err := bc.ValidateBlock(b); err != nil {
		return fmt.Errorf("添加区块失败: %w", err)
	}
	bc.blocks = append(bc.blocks, b)
	return nil
}

// TODO: 分叉处理（重要，先在骨架中标注设计要点）：
//
// 真实网络中，不同节点可能几乎同时挖出不同的区块，形成临时分叉。
// 处理原则（最长有效链 / 最大累积工作量）：
//  1. 节点收到一个新区块时，如果它的 PrevBlockHash 不指向当前链尾，
//     说明可能存在分叉，需要判断这个新区块所在的链累积难度是否更高。
//  2. 如果更高，则执行"链重组"（reorg）：回滚当前链尾部分区块，
//     切换到新的、更长（工作量更大）的链，并把被回滚区块中的交易重新放回内存池。
//  3. 需要维护一个区块索引（哈希 -> 区块、高度、累积难度），而不只是线性数组，
//     才能支持多分支并存和比较。
//
// 建议下一步：把 blocks []*block.Block 换成 map[[32]byte]*BlockNode 的树状结构。
