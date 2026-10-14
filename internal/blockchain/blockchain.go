// Package blockchain 维护本地节点看到的区块链视图，负责：
//   - 区块的验证与追加
//   - 分叉处理（最长有效链原则，比特币称为"最大累积工作量"原则）
//   - 难度调整的触发
//
// 注意：这里给出的是内存版骨架，真实项目需要接入 internal/storage 做持久化，
// 并在启动时从磁盘重建内存索引。
//
// 冻结规则（冻结表 V2 §2/§7）：补贴上限、Coinbase 成熟 100、时间戳（中位数 + 未来 2 小时）、
// 块大小/权重、费校验（共识）与粉尘/中继（策略层分离）。
// 仍待 UTXO 集合（任务卡片 1）的校验：非 Coinbase 交易的手续费（需输入金额）、
// 签名验签、双花、Coinbase 成熟花费检查——本文件显式标注 TODO，不静默声称已实现。
package blockchain

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"hundun/internal/block"
	"hundun/internal/params"
	"hundun/internal/pow"
)

var (
	ErrInvalidPrevHash      = errors.New("区块的前置哈希与当前链尾不匹配")
	ErrInvalidPoW           = errors.New("区块哈希未达到难度目标，工作量证明无效")
	ErrEmptyChain           = errors.New("链为空")
	ErrEmptyTransactions    = errors.New("区块不含任何交易")
	ErrInvalidCoinbase      = errors.New("Coinbase 交易无效：首笔须为 Coinbase、其余不得为 Coinbase")
	ErrInvalidCoinbaseValue = errors.New("Coinbase 金额超限：输出和 > 补贴 + 手续费")
	ErrInvalidFee           = errors.New("手续费无效：输入和 < 输出和")
	ErrInvalidTx            = errors.New("交易无效：输入/输出为空或金额超限")
	ErrInvalidTimestamp     = errors.New("时间戳无效：须 > 前 11 块中位数且 < 网络时间 + 7200 秒")
	ErrBlockTooLarge        = errors.New("区块过大：尺寸 > 1_000_000 或权重 > 4_000_000")
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

// BlockAt 返回指定高度的区块（高度越界时返回错误）。
func (bc *Blockchain) BlockAt(height int) (*block.Block, error) {
	if height < 0 || height >= len(bc.blocks) {
		return nil, fmt.Errorf("高度越界: %d", height)
	}
	return bc.blocks[height], nil
}

// MedianTimestamp 返回最近最多 11 个块时间戳的中位数（冻结表 §2.5）。
// 链为空时返回 0。
func (bc *Blockchain) MedianTimestamp() uint32 {
	n := len(bc.blocks)
	if n == 0 {
		return 0
	}
	start := n - params.MedianTimeSpan
	if start < 0 {
		start = 0
	}
	ts := make([]uint32, 0, n-start)
	for _, b := range bc.blocks[start:] {
		ts = append(ts, b.Header.Timestamp)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	return ts[len(ts)/2]
}

// IsCoinbaseMature 判断某高度的 Coinbase 产出在花费高度是否已成熟（冻结表 §2.4）。
// 成熟规则：spendHeight - coinbaseHeight >= 100。
// 注意：花费检查须配合 UTXO 集合（任务卡片 1）实施；本函数仅为纯规则 helper。
func IsCoinbaseMature(coinbaseHeight, spendHeight int) bool {
	return spendHeight-coinbaseHeight >= params.CoinbaseMaturity
}

// CurrentBits 返回下一个待挖区块应当使用的难度目标。
// 冻结逻辑（BTC）：仅当链高为 2016 的整数倍时重算，否则沿用链尾难度。
func (bc *Blockchain) CurrentBits() uint32 {
	tip, err := bc.Tip()
	if err != nil {
		return params.GenesisBits
	}
	height := bc.Height()
	if height == 0 || height%params.DifficultyAdjustmentInterval != 0 {
		return tip.Header.Bits
	}

	periodStartHeight := height - params.DifficultyAdjustmentInterval
	if periodStartHeight < 0 {
		periodStartHeight = 0
	}
	periodStart := bc.blocks[periodStartHeight]
	actualTimespan := int64(tip.Header.Timestamp) - int64(periodStart.Header.Timestamp)
	return pow.AdjustBits(tip.Header.Bits, actualTimespan)
}

// ValidateGenesisBlock 校验候选创世块的结构规则（不含报文/归属的完整比对，完整比对见 genesis 包）。
// 要求：前置哈希全零、Bits == GenesisBits、首笔为 Coinbase、Coinbase 金额 == height 0 补贴、PoW 有效。
func ValidateGenesisBlock(b *block.Block) error {
	if b.Header.PrevBlockHash != ([32]byte{}) {
		return ErrInvalidPrevHash
	}
	if b.Header.Bits != params.GenesisBits {
		return fmt.Errorf("创世块 Bits 须为 0x%08x", params.GenesisBits)
	}
	if len(b.Transactions) == 0 || !b.Transactions[0].IsCoinbase() {
		return ErrInvalidCoinbase
	}
	outSum, ok := b.Transactions[0].TotalOutputValue()
	if !ok {
		return ErrInvalidTx
	}
	if outSum != params.GetBlockSubsidy(0) {
		return ErrInvalidCoinbaseValue
	}
	if !pow.Validate(&b.Header) {
		return ErrInvalidPoW
	}
	return nil
}

// ValidateBlock 对一个待追加的区块做合法性校验（冻结表 §2/§7 共识部分）：
//  1. 前置哈希是否指向当前链尾
//  2. 工作量证明是否满足难度目标
//  3. 时间戳：> 前 11 块中位数 且 < 网络时间 + 7200 秒
//  4. 块尺寸 <= 1_000_000，权重 <= 4_000_000
//  5. 首笔为 Coinbase、其余非 Coinbase；Coinbase 输出和 <= 补贴 + 手续费
//  6. 每笔交易输入/输出非空、输出金额在 [0, 2^63) 内且单笔输出和不溢出
//
// 明确未实现（须 UTXO 集合，任务卡片 1）：
//   - 非 Coinbase 交易的手续费（需输入 UTXO 金额）；当前实现按手续费 = 0 保守校验，
//     即 Coinbase 输出和 <= 补贴。含非 Coinbase 交易的块若 Coinbase 申领了手续费，将被拒绝，
//     直至 UTXO 集合落地后按 补贴 + 实际手续费重算。
//   - 签名验签、双花、Coinbase 成熟花费检查。
//
// 粉尘 / 最低中继为策略层（§7.2），不进入本共识校验：含粉尘输出的块仍为共识有效，
// 节点可按策略拒绝转发/打包，但不得因粉尘拒块。
func (bc *Blockchain) ValidateBlock(b *block.Block) error {
	tip, err := bc.Tip()
	if err != nil {
		return err
	}
	if len(b.Transactions) == 0 {
		return ErrEmptyTransactions
	}
	if b.Header.PrevBlockHash != tip.Header.Hash() {
		return ErrInvalidPrevHash
	}
	if !pow.Validate(&b.Header) {
		return ErrInvalidPoW
	}

	// 时间戳（冻结表 §2.5）。
	median := bc.MedianTimestamp()
	if b.Header.Timestamp <= median {
		return ErrInvalidTimestamp
	}
	if int64(b.Header.Timestamp) > time.Now().Unix()+params.MaxFutureSeconds {
		return ErrInvalidTimestamp
	}

	// 块尺寸 / 权重（冻结表 §2.6）。
	if b.Size() > params.MaxBlockSize || b.Weight() > params.MaxBlockWeight {
		return ErrBlockTooLarge
	}

	// Coinbase 结构。
	if !b.Transactions[0].IsCoinbase() {
		return ErrInvalidCoinbase
	}
	for _, tx := range b.Transactions[1:] {
		if tx.IsCoinbase() {
			return ErrInvalidCoinbase
		}
	}

	// 每笔交易的输入/输出非空与金额范围。
	for _, tx := range b.Transactions {
		if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
			return ErrInvalidTx
		}
		for _, out := range tx.Outputs {
			if out.Value > params.MaxMoney {
				return ErrInvalidTx
			}
		}
		if _, ok := tx.TotalOutputValue(); !ok {
			return ErrInvalidTx
		}
	}

	// Coinbase 金额：输出和 <= 补贴 + 手续费。
	// TODO(UTXO)：手续费需输入 UTXO 金额，当前按 0 保守校验（见函数注释）。
	height := bc.Height() + 1
	subsidy := params.GetBlockSubsidy(uint64(height))
	coinbaseOut, _ := b.Transactions[0].TotalOutputValue()
	if coinbaseOut > subsidy {
		// 含非 Coinbase 交易时，理论上可申领手续费；UTXO 未落地前按 0 处理，拒绝超补贴申领。
		return ErrInvalidCoinbaseValue
	}
	_ = params.DustThreshold // 粉尘为策略层，此处显式不判（防误删入共识）。

	// TODO: 校验每笔交易的输入签名（内含 ECDSA 验签逻辑，需 UTXO 的 PubKeyHash 匹配）
	// TODO: 校验交易输入引用的 UTXO 确实存在且未被花费（维护一个 UTXO 集合）
	// TODO: 校验 Coinbase 成熟花费（IsCoinbaseMature + UTXO 高度记录）

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
//  2. 如果更高，则执行"链重组"（reorg）：回滚旧链上的区块（其交易放回 Mempool），切换到新链
//  3. 需要维护一个区块索引（哈希 -> 区块、高度、累积难度），而不只是线性数组，
//     才能支持多分支并存和比较。
//
// 建议下一步：把 blocks []*block.Block 换成 map[[32]byte]*BlockNode 的树状结构。
