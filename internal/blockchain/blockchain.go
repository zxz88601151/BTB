// Package blockchain 维护本地节点看到的区块链视图，负责：
//   - 区块的验证与追加（含 UTXO、签名、手续费真实校验）
//   - 分叉处理与链重组（Fork-choice：累计工作量最大链）
//   - 难度调整的触发
//   - 孤块池（父块未到的块暂存）
//
// 冻结规则（冻结表 V2 §2/§7）：补贴上限、Coinbase 成熟 100、时间戳（中位数 + 未来 2 小时）、
// 块大小/权重、费校验（共识）与粉尘/中继（策略层分离）。
//
// 注意：交易 Hash() 为单次 SHA-256（沿用骨架语义），与区块头双 SHA-256 不同。
package blockchain

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"hundun/internal/block"
	"hundun/internal/params"
	"hundun/internal/pow"
	"hundun/internal/transaction"
	"hundun/internal/utxo"
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
	ErrDoubleSpend          = errors.New("双花：同一输出被花费两次")
	ErrImmatureCoinbase     = errors.New("Coinbase 未成熟花费")
	ErrBadSignature         = errors.New("签名无效")
	ErrOrphan               = errors.New("孤块：父块未知，已暂存孤块池")
	ErrDuplicateBlock       = errors.New("重复区块：该哈希的块已在索引中")
	ErrUnknownParent        = errors.New("分叉父块未知")
	ErrReorgFailed          = errors.New("重组失败：分叉块校验未通过，已保留原主链")
)

// 孤块池上限（策略参数）：超限时丢弃最旧的孤块。
const MaxOrphans = 100

// BlockNode 区块索引节点：记录哈希、高度、累计工作量与父哈希，支撑分叉比较与重组。
type BlockNode struct {
	Hash       [32]byte
	Height     int
	Work       *big.Int // 本链从创世到本块的累计工作量
	ParentHash [32]byte
	Block      *block.Block // 仅主链块与已校验的分叉块持有；孤块不进索引
}

// Blockchain 内存中的区块链结构。
// blocks 为主链（按高度顺序）；index 为全量区块索引（含分叉块）；
// utxoSet 为主链状态下的 UTXO 集合；undo 按块哈希记录 UTXO 逆操作（供重组回滚）。
type Blockchain struct {
	blocks         []*block.Block
	index          map[[32]byte]*BlockNode
	orphans        map[[32]byte]*block.Block
	orphanOrder    [][32]byte
	utxoSet        *utxo.Set
	undo           map[[32]byte]*utxo.BlockUndo
	cumulativeWork *big.Int
}

// NewBlockchainWithGenesis 使用给定的创世区块初始化链。
// 创世块的 Coinbase 输出计入 UTXO；创世块不做 PoW 以外校验（调用方已用 ValidateGenesisBlock 校验）。
func NewBlockchainWithGenesis(genesis *block.Block) *Blockchain {
	bc := &Blockchain{
		blocks:         []*block.Block{genesis},
		index:          make(map[[32]byte]*BlockNode),
		orphans:        make(map[[32]byte]*block.Block),
		undo:           make(map[[32]byte]*utxo.BlockUndo),
		utxoSet:        utxo.NewSet(),
		cumulativeWork: new(big.Int),
	}
	h := genesis.Header.Hash()
	bc.index[h] = &BlockNode{Hash: h, Height: 0, Work: new(big.Int).Set(WorkOf(genesis.Header.Bits)), ParentHash: genesis.Header.PrevBlockHash, Block: genesis}
	bc.cumulativeWork.Set(bc.index[h].Work)
	// 创世 Coinbase 输出入 UTXO（高度 0）。
	if len(genesis.Transactions) > 0 && genesis.Transactions[0].IsCoinbase() {
		txID := genesis.Transactions[0].Hash()
		for outIdx, out := range genesis.Transactions[0].Outputs {
			bc.utxoSet.Put(utxo.Key{TxID: txID, OutIndex: uint32(outIdx)},
				utxo.Entry{Output: out, Height: 0, IsCoinbase: true, BlockHash: h})
		}
	}
	return bc
}

// WorkOf 返回单个块的工作量：2^256 / (target+1)（BTC 惯例）。
// target <= 0 时返回 0；target >= 2^256 时返回 0（无效难度）。
// 用 2^256 而非 MaxTarget 做分子，保证易难度（如测试用 0x207fffff）的工作量仍 >= 1，
// 分叉比较不会把所有易难度块的工作量都塌成 0。
func WorkOf(bits uint32) *big.Int {
	target := pow.BitsToTarget(bits)
	if target == nil || target.Sign() <= 0 {
		return big.NewInt(0)
	}
	if target.BitLen() > 256 {
		return big.NewInt(0)
	}
	two256 := new(big.Int).Lsh(big.NewInt(1), 256)
	denom := new(big.Int).Add(target, big.NewInt(1))
	return new(big.Int).Div(two256, denom)
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

// BlockAt 返回指定高度的主链区块（高度越界时返回错误）。
func (bc *Blockchain) BlockAt(height int) (*block.Block, error) {
	if height < 0 || height >= len(bc.blocks) {
		return nil, fmt.Errorf("高度越界: %d", height)
	}
	return bc.blocks[height], nil
}

// GetBlockByHash 按哈希查区块（主链 + 已索引分叉块；孤块不含）。
func (bc *Blockchain) GetBlockByHash(h [32]byte) (*block.Block, bool) {
	n, ok := bc.index[h]
	if !ok || n.Block == nil {
		return nil, false
	}
	return n.Block, true
}

// HasBlock 判断哈希是否已在索引中（主链 / 分叉 / 孤块任一）。
func (bc *Blockchain) HasBlock(h [32]byte) bool {
	if _, ok := bc.index[h]; ok {
		return true
	}
	_, ok := bc.orphans[h]
	return ok
}

// CumulativeWork 返回主链累计工作量。
func (bc *Blockchain) CumulativeWork() *big.Int {
	return new(big.Int).Set(bc.cumulativeWork)
}

// UTXOSet 返回主链 UTXO 集合（调用方只读，不得直接改；改状态须走 AddBlock / 重组）。
func (bc *Blockchain) UTXOSet() *utxo.Set {
	return bc.utxoSet
}

// OrphanCount 返回孤块池当前数量。
func (bc *Blockchain) OrphanCount() int {
	return len(bc.orphans)
}

// MedianTimestamp 返回最近最多 11 个块时间戳的中位数（冻结表 §2.5）。
func (bc *Blockchain) MedianTimestamp() uint32 {
	return medianOf(bc.blocks)
}

// medianOf 计算给定块序列尾部最多 11 个块时间戳的中位数。
func medianOf(blocks []*block.Block) uint32 {
	n := len(blocks)
	if n == 0 {
		return 0
	}
	start := n - params.MedianTimeSpan
	if start < 0 {
		start = 0
	}
	ts := make([]uint32, 0, n-start)
	for _, b := range blocks[start:] {
		ts = append(ts, b.Header.Timestamp)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	return ts[len(ts)/2]
}

// IsCoinbaseMature 判断某高度的 Coinbase 产出在花费高度是否已成熟（冻结表 §2.4）。
func IsCoinbaseMature(coinbaseHeight, spendHeight int) bool {
	return spendHeight-coinbaseHeight >= params.CoinbaseMaturity
}

// CurrentBits 返回下一个待挖区块应当使用的难度目标。
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

// validateTxSet 对一块的非 Coinbase 交易做 UTXO 校验，返回总手续费。
// spentInBlock 由调用方传入空 map，本函数填充（防同块内双花）。
func (bc *Blockchain) validateTxSet(b *block.Block, height int) (uint64, error) {
	spent := make(map[utxo.Key]bool)
	var totalFee uint64
	for _, tx := range b.Transactions[1:] {
		fee, err := utxo.ValidateTx(tx, height, bc.utxoSet, spent)
		if err != nil {
			return 0, mapUTXOError(err)
		}
		totalFee += fee
	}
	return totalFee, nil
}

// mapUTXOError 把 utxo 包错误映射为 blockchain 包的公开错误（便于调用方用 errors.Is 判断）。
func mapUTXOError(err error) error {
	switch {
	case errors.Is(err, utxo.ErrDoubleSpend):
		return fmt.Errorf("%w: %v", ErrDoubleSpend, err)
	case errors.Is(err, utxo.ErrUTXONotFound):
		return fmt.Errorf("%w: %v", ErrInvalidTx, err)
	case errors.Is(err, utxo.ErrImmatureCoinbase):
		return fmt.Errorf("%w: %v", ErrImmatureCoinbase, err)
	case errors.Is(err, utxo.ErrBadSignature):
		return fmt.Errorf("%w: %v", ErrBadSignature, err)
	case errors.Is(err, utxo.ErrNegativeFee):
		return fmt.Errorf("%w: %v", ErrInvalidFee, err)
	default:
		return err
	}
}

// validateStateless 校验与 UTXO 无关的块规则：PoW、尺寸/权重、Coinbase 结构、金额范围。
// 分叉块进索引前与主链校验共用本函数；时间戳与手续费在调用方按上下文补验。
func validateStateless(b *block.Block) error {
	if len(b.Transactions) == 0 {
		return ErrEmptyTransactions
	}
	if !pow.Validate(&b.Header) {
		return ErrInvalidPoW
	}
	if b.Size() > params.MaxBlockSize || b.Weight() > params.MaxBlockWeight {
		return ErrBlockTooLarge
	}
	if !b.Transactions[0].IsCoinbase() {
		return ErrInvalidCoinbase
	}
	for _, tx := range b.Transactions[1:] {
		if tx.IsCoinbase() {
			return ErrInvalidCoinbase
		}
	}
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
	return nil
}

// validateTimestamp 校验块时间戳：> 给定链尾序列的中位数 且 < 网络时间 + 7200 秒。
func validateTimestamp(b *block.Block, chainTail []*block.Block) error {
	median := medianOf(chainTail)
	if b.Header.Timestamp <= median {
		return ErrInvalidTimestamp
	}
	if int64(b.Header.Timestamp) > time.Now().Unix()+params.MaxFutureSeconds {
		return ErrInvalidTimestamp
	}
	return nil
}

// ValidateBlock 对一个待追加到主链尾的区块做完整校验（冻结表 §2/§7 共识部分 + UTXO）。
// 校验项：前置哈希=链尾、PoW、时间戳、尺寸/权重、Coinbase 结构与上限、
// 每笔交易金额范围、UTXO 存在、成熟花费、签名验签、同块/跨块双花、手续费真实值。
// 粉尘 / 最低中继为策略层（§7.2），不进入本共识校验：含粉尘输出的块仍为共识有效。
func (bc *Blockchain) ValidateBlock(b *block.Block) error {
	tip, err := bc.Tip()
	if err != nil {
		return err
	}
	if b.Header.PrevBlockHash != tip.Header.Hash() {
		return ErrInvalidPrevHash
	}
	if err := validateStateless(b); err != nil {
		return err
	}
	if err := validateTimestamp(b, bc.blocks); err != nil {
		return err
	}
	height := bc.Height() + 1
	// BIP-30 式防重复：Coinbase 无输入，相同 Coinbase 在不同块重复出现时 TxID 相同，
	// 其输出 Key (TxID, OutIndex) 会碰撞、静默覆盖已存在的未花费 UTXO（丢币）。
	// 若 Coinbase 任一输出 Key 已在 UTXO 中，拒绝本块。UTXO 花光后重现相同 Coinbase 则允许。
	coinbaseTxID := b.Transactions[0].Hash()
	for outIdx := range b.Transactions[0].Outputs {
		if bc.utxoSet.Has(utxo.Key{TxID: coinbaseTxID, OutIndex: uint32(outIdx)}) {
			return fmt.Errorf("%w: Coinbase TxID %x 的输出已存在未花费 UTXO（重复 Coinbase）", ErrInvalidTx, coinbaseTxID)
		}
	}
	totalFee, err := bc.validateTxSet(b, height)
	if err != nil {
		return err
	}
	subsidy := params.GetBlockSubsidy(uint64(height))
	coinbaseOut, _ := b.Transactions[0].TotalOutputValue()
	if coinbaseOut > subsidy+totalFee {
		return ErrInvalidCoinbaseValue
	}
	_ = params.DustThreshold // 粉尘为策略层，此处显式不判（防误删入共识）。
	return nil
}

// AddBlock 校验并把区块追加到链尾（或作为分叉块进索引、孤块进孤块池）。
// 主链延伸时直接应用；分叉块若累计工作量超过主链则触发重组。
// 返回的 displaced 为重组时被挤出主链的非 Coinbase 交易（调用方应放回 Mempool）。
func (bc *Blockchain) AddBlock(b *block.Block) error {
	_, _, err := bc.AddBlockWithResult(b)
	return err
}

// AddBlockWithResult 与 AddBlock 相同，另返回重组信息。
func (bc *Blockchain) AddBlockWithResult(b *block.Block) (displaced []*transaction.Transaction, reorged bool, err error) {
	h := b.Header.Hash()
	if bc.HasBlock(h) {
		return nil, false, ErrDuplicateBlock
	}
	parentHash := b.Header.PrevBlockHash
	parentNode, parentKnown := bc.index[parentHash]
	if !parentKnown {
		// 父块未知：孤块暂存；调用方可据此向对端请求父块（同步）。
		bc.addOrphan(b)
		return nil, false, ErrOrphan
	}

	tip, _ := bc.Tip()
	if parentHash == tip.Header.Hash() {
		// 主链延伸：完整校验 + 应用。
		if err := bc.ValidateBlock(b); err != nil {
			return nil, false, fmt.Errorf("添加区块失败: %w", err)
		}
		if err := bc.applyMainBlock(b); err != nil {
			return nil, false, err
		}
		// 孤块可能因此获得父块：尝试依次接入。
		bc.tryConnectOrphans()
		return nil, false, nil
	}

	// 分叉块：先做无状态校验 + 分叉链时间戳校验，进索引后再比较工作量。
	if err := validateStateless(b); err != nil {
		return nil, false, err
	}
	forkChain := bc.chainToAncestor(parentHash)
	if err := validateTimestamp(b, forkChain); err != nil {
		return nil, false, err
	}
	cumWork := new(big.Int).Add(parentNode.Work, WorkOf(b.Header.Bits))
	bc.index[h] = &BlockNode{Hash: h, Height: parentNode.Height + 1, Work: cumWork, ParentHash: parentHash, Block: b}
	// Fork-choice：累计工作量更大才重组；平局先到先赢（不重组）。
	if cumWork.Cmp(bc.cumulativeWork) > 0 {
		displaced, err := bc.reorgTo(h)
		if err != nil {
			return nil, false, err
		}
		bc.tryConnectOrphans()
		return displaced, true, nil
	}
	return nil, false, nil
}

// chainToAncestor 返回从创世到给定哈希的链上块序列（沿父指针回溯再正序）。
// 哈希不在索引中时返回空。
func (bc *Blockchain) chainToAncestor(h [32]byte) []*block.Block {
	var rev []*block.Block
	cur := h
	for {
		n, ok := bc.index[cur]
		if !ok || n.Block == nil {
			break
		}
		rev = append(rev, n.Block)
		if n.Height == 0 {
			break
		}
		cur = n.ParentHash
	}
	out := make([]*block.Block, len(rev))
	for i, b := range rev {
		out[len(rev)-1-i] = b
	}
	return out
}

// applyMainBlock 把已校验的块应用到主链：UTXO 变更 + 索引 + 累计工作量。
func (bc *Blockchain) applyMainBlock(b *block.Block) error {
	height := bc.Height() + 1
	undo, err := bc.utxoSet.ApplyBlock(b, height)
	if err != nil {
		return err
	}
	h := b.Header.Hash()
	parentWork := big.NewInt(0)
	if tip, err := bc.Tip(); err == nil {
		if n, ok := bc.index[tip.Header.Hash()]; ok {
			parentWork = n.Work
		}
	}
	work := new(big.Int).Add(parentWork, WorkOf(b.Header.Bits))
	bc.index[h] = &BlockNode{Hash: h, Height: height, Work: work, ParentHash: b.Header.PrevBlockHash, Block: b}
	bc.undo[h] = undo
	bc.blocks = append(bc.blocks, b)
	bc.cumulativeWork.Set(work)
	return nil
}

// rollbackTip 回滚主链尾块：恢复 UTXO，弹出块，返回被挤出的非 Coinbase 交易。
func (bc *Blockchain) rollbackTip() []*transaction.Transaction {
	if len(bc.blocks) <= 1 {
		return nil // 创世块永不回滚
	}
	tip := bc.blocks[len(bc.blocks)-1]
	h := tip.Header.Hash()
	bc.utxoSet.RollbackBlock(bc.undo[h])
	delete(bc.undo, h)
	bc.blocks = bc.blocks[:len(bc.blocks)-1]
	// 累计工作量回退到新链尾。
	if newTip, err := bc.Tip(); err == nil {
		if n, ok := bc.index[newTip.Header.Hash()]; ok {
			bc.cumulativeWork.Set(n.Work)
		}
	}
	var displaced []*transaction.Transaction
	for _, tx := range tip.Transactions[1:] {
		displaced = append(displaced, tx)
	}
	return displaced
}

// reorgTo 将主链重组到指定分叉尖端（其累计工作量已确认大于主链）。
// 步骤：找共同祖先 → 逆序回滚主链 → 正序应用分叉块（逐块完整校验）。
// 任一分叉块校验失败时，尝试恢复原主链并返回 ErrReorgFailed，原主链不受损。
func (bc *Blockchain) reorgTo(forkTipHash [32]byte) ([]*transaction.Transaction, error) {
	forkNode, ok := bc.index[forkTipHash]
	if !ok {
		return nil, ErrUnknownParent
	}
	// 收集分叉链：从尖端回溯到共同祖先（不含祖先）。
	var forkBlocks []*block.Block
	cur := forkTipHash
	ancestorHash := [32]byte{}
	for {
		n, ok := bc.index[cur]
		if !ok {
			return nil, ErrUnknownParent
		}
		// 祖先判定：该高度的主链块哈希等于 cur。
		if n.Height < len(bc.blocks) && bc.blocks[n.Height].Header.Hash() == cur {
			ancestorHash = cur
			break
		}
		forkBlocks = append(forkBlocks, n.Block)
		if n.Height == 0 {
			return nil, ErrUnknownParent
		}
		cur = n.ParentHash
	}
	// 正序分叉块。
	for i, j := 0, len(forkBlocks)-1; i < j; i, j = i+1, j-1 {
		forkBlocks[i], forkBlocks[j] = forkBlocks[j], forkBlocks[i]
	}
	ancestorHeight := bc.index[ancestorHash].Height

	// 备份原主链（祖先之后），供失败恢复用。
	var oldBlocks []*block.Block
	for h := ancestorHeight + 1; h < len(bc.blocks); h++ {
		oldBlocks = append(oldBlocks, bc.blocks[h])
	}

	// 逆序回滚主链到祖先。
	var displaced []*transaction.Transaction
	for bc.Height() > ancestorHeight {
		displaced = append(displaced, bc.rollbackTip()...)
	}

	// 正序应用分叉块，逐块完整校验。
	for _, fb := range forkBlocks {
		if err := bc.ValidateBlock(fb); err != nil {
			// 恢复原主链：回滚已应用的分叉块，再按序重应用原主链块。
			for bc.Height() > ancestorHeight {
				bc.rollbackTip()
			}
			for _, ob := range oldBlocks {
				// 原主链块此前已校验通过；若重应用失败，链已不一致，返回致命错误。
				if err := bc.ValidateBlock(ob); err != nil {
					return nil, fmt.Errorf("%w：恢复原主链失败 %v（链状态不一致，需人工干预）", ErrReorgFailed, err)
				}
				if err := bc.applyMainBlock(ob); err != nil {
					return nil, fmt.Errorf("%w：恢复原主链失败 %v", ErrReorgFailed, err)
				}
			}
			return nil, fmt.Errorf("%w：分叉块 %x 校验失败 %v", ErrReorgFailed, fb.Header.Hash(), err)
		}
		if err := bc.applyMainBlock(fb); err != nil {
			return nil, fmt.Errorf("%w：应用分叉块失败 %v", ErrReorgFailed, err)
		}
	}
	_ = forkNode

	// 排除已在分叉块中确认的交易（它们不是“被挤出”，无需放回 Mempool）。
	confirmed := make(map[[32]byte]bool)
	for _, fb := range forkBlocks {
		for _, tx := range fb.Transactions[1:] {
			confirmed[tx.Hash()] = true
		}
	}
	var filtered []*transaction.Transaction
	for _, tx := range displaced {
		if !confirmed[tx.Hash()] {
			filtered = append(filtered, tx)
		}
	}
	return filtered, nil
}

// addOrphan 暂存孤块，超限丢最旧。
func (bc *Blockchain) addOrphan(b *block.Block) {
	h := b.Header.Hash()
	if _, ok := bc.orphans[h]; ok {
		return
	}
	if len(bc.orphans) >= MaxOrphans {
		oldest := bc.orphanOrder[0]
		bc.orphanOrder = bc.orphanOrder[1:]
		delete(bc.orphans, oldest)
	}
	bc.orphans[h] = b
	bc.orphanOrder = append(bc.orphanOrder, h)
}

// tryConnectOrphans 尝试接入父块已到的孤块（循环直到无进展）。
func (bc *Blockchain) tryConnectOrphans() {
	for {
		progress := false
		for _, h := range append([][32]byte(nil), bc.orphanOrder...) {
			ob, ok := bc.orphans[h]
			if !ok {
				continue
			}
			if _, parentKnown := bc.index[ob.Header.PrevBlockHash]; !parentKnown {
				continue
			}
			delete(bc.orphans, h)
			bc.orphanOrder = removeHash(bc.orphanOrder, h)
			// 接入时不触发嵌套孤块循环：直接走 AddBlockWithResult（它会再次调用 tryConnectOrphans，
			// 但孤块已删除，不会死循环）。
			_, _, _ = bc.AddBlockWithResult(ob)
			progress = true
			break // 链状态已变，重新扫描
		}
		if !progress {
			return
		}
	}
}

func removeHash(list [][32]byte, h [32]byte) [][32]byte {
	out := list[:0]
	for _, x := range list {
		if x != h {
			out = append(out, x)
		}
	}
	return out
}
