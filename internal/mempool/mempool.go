// Package mempool 实现交易内存池：任务卡片 3。
//
// 规则（冻结表 §7 策略层 + 本包策略参数）：
//   - 排序：费率（fee/size）降序，费率相同先到先得。
//   - 容量：默认 100_000 笔 / 100MB，任一超限触发驱逐（策略参数，可调）。
//   - 过期：默认 72 小时未打包丢弃（策略参数）。
//   - 拒绝：重复、双花（池内冲突）、粉尘输出、低于最低中继费率、手续费为负、
//     签名无效、Coinbase 入池。RBF 本轮不支持：冲突交易直接拒绝（待以后决策）。
//   - 祖先交易：父交易未确认时允许子交易入池（输入可引用池内父交易的输出）；
//     打包时按费率排序并跳过输入未满足的交易，下一轮再试。
//   - 打包：按费率取交易直到块重上限，Coinbase = 补贴 + 选中交易费和（由调用方组装）。
//
// 注意：Mempool 是策略层，不是共识。共识校验见 blockchain / utxo。
package mempool

import (
	"errors"
	"sort"
	"sync"
	"time"

	"hundun/internal/params"
	"hundun/internal/transaction"
	"hundun/internal/utxo"
	"hundun/internal/wallet"
)

var (
	ErrDuplicateTx  = errors.New("Mempool 已含该交易")
	ErrDoubleSpend  = errors.New("Mempool 内双花：输入已被池内另一笔交易花费（本轮不支持 RBF）")
	ErrDust         = errors.New("含粉尘输出：任一输出 < 546")
	ErrLowFee       = errors.New("费率低于最低中继费率 1/字节")
	ErrNegativeFee  = errors.New("手续费无效：输入和 < 输出和")
	ErrMissingInput = errors.New("输入既不在 UTXO 中，也不在池内父交易输出中")
	ErrBadSignature = errors.New("签名无效")
	ErrImmature     = errors.New("花费了未成熟的 Coinbase")
	ErrCoinbase     = errors.New("Coinbase 交易不得入池")
	ErrPoolFull     = errors.New("Mempool 已满且新交易费率不高于池内最低费率")
	ErrInvalidTx    = errors.New("交易无效：输入/输出为空或金额超限")
)

// 策略参数（可调，非共识）。
const (
	DefaultMaxTx      = 100_000           // 最大笔数
	DefaultMaxBytes   = 100 * 1024 * 1024 // 最大总字节 100MB
	DefaultExpiry     = 72 * time.Hour    // 过期时间
	DefaultMaxTxBytes = 1_000_000         // 单笔最大尺寸（与最大块等宽，策略参数）
)

// Entry 池内一笔交易的记录。
type Entry struct {
	Tx      *transaction.Transaction
	Fee     uint64 // 手续费（base units）
	FeeRate uint64 // 费率 = fee / size（base units / 字节）
	AddedAt time.Time
	Seq     uint64 // 入池序号（费率相同先到先得）
	Size    int
}

// Pool 交易内存池。
type Pool struct {
	mu         sync.Mutex
	entries    map[[32]byte]*Entry
	spent      map[utxo.Key][32]byte // 池内已花费的 UTXO -> 花费它的交易 TxID
	totalBytes int
	seq        uint64
	maxTx      int
	maxBytes   int
	expiry     time.Duration
}

// New 返回默认参数的 Pool。
func New() *Pool {
	return NewWithLimits(DefaultMaxTx, DefaultMaxBytes, DefaultExpiry)
}

// NewWithLimits 返回指定容量/过期参数的 Pool（测试与调参用）。
func NewWithLimits(maxTx, maxBytes int, expiry time.Duration) *Pool {
	return &Pool{
		entries:  make(map[[32]byte]*Entry),
		spent:    make(map[utxo.Key][32]byte),
		maxTx:    maxTx,
		maxBytes: maxBytes,
		expiry:   expiry,
	}
}

// Len 返回池内笔数。
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// TotalBytes 返回池内总字节。
func (p *Pool) TotalBytes() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.totalBytes
}

// Get 按 TxID 查询池内交易。
func (p *Pool) Get(txID [32]byte) (*transaction.Transaction, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[txID]
	if !ok {
		return nil, false
	}
	return e.Tx, true
}

// resolveInput 解析一笔交易的单个输入金额与锁定地址：
// 先查 UTXO，再查池内父交易的输出（祖先交易）。均无则返回 ErrMissingInput。
func (p *Pool) resolveInput(in transaction.TxInput, utxoSet *utxo.Set) (value uint64, pkh [20]byte, isCoinbase bool, coinbaseHeight int, err error) {
	k := utxo.Key{TxID: in.PrevTxHash, OutIndex: in.OutIndex}
	if entry, ok := utxoSet.Get(k); ok {
		return entry.Output.Value, entry.Output.PubKeyHash, entry.IsCoinbase, entry.Height, nil
	}
	// 池内父交易：其输出即为本输入的来源。
	if parent, ok := p.entries[in.PrevTxHash]; ok {
		if int(in.OutIndex) < len(parent.Tx.Outputs) {
			out := parent.Tx.Outputs[in.OutIndex]
			return out.Value, out.PubKeyHash, false, 0, nil
		}
	}
	return 0, [20]byte{}, false, 0, ErrMissingInput
}

// Add 校验并把交易放入池中。height 为当前链高 + 1（待打包高度，供成熟检查用）。
func (p *Pool) Add(tx *transaction.Transaction, utxoSet *utxo.Set, height int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(time.Now())

	if tx.IsCoinbase() {
		return ErrCoinbase
	}
	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
		return ErrInvalidTx
	}
	txID := tx.Hash()
	if _, ok := p.entries[txID]; ok {
		return ErrDuplicateTx
	}
	size := tx.SerializedSize()
	if size > DefaultMaxTxBytes {
		return ErrInvalidTx
	}
	// 粉尘：任一输出 < 546 拒绝（策略层）。
	for _, out := range tx.Outputs {
		if out.Value > params.MaxMoney {
			return ErrInvalidTx
		}
		if transaction.IsDustOutput(out) {
			return ErrDust
		}
	}
	// 逐输入解析金额 + 验签 + 池内双花。
	var inSum uint64
	for _, in := range tx.Inputs {
		k := utxo.Key{TxID: in.PrevTxHash, OutIndex: in.OutIndex}
		if spender, ok := p.spent[k]; ok && spender != txID {
			return ErrDoubleSpend
		}
		value, pkh, isCoinbase, cbHeight, err := p.resolveInput(in, utxoSet)
		if err != nil {
			return err
		}
		if isCoinbase && height-cbHeight < params.CoinbaseMaturity {
			return ErrImmature
		}
		if utxo.PubKeyHashOf(in.PubKey) != pkh {
			return ErrBadSignature
		}
		okSig, err := verifySig(in.PubKey, tx.Hash(), in.Signature)
		if err != nil || !okSig {
			return ErrBadSignature
		}
		if value > params.MaxMoney || inSum > params.MaxMoney-value {
			return ErrInvalidTx
		}
		inSum += value
	}
	outSum, ok := tx.TotalOutputValue()
	if !ok {
		return ErrInvalidTx
	}
	if inSum < outSum {
		return ErrNegativeFee
	}
	fee := inSum - outSum
	feeRate := fee / uint64(size)
	// 最低中继费率：fee >= size * 1/字节。
	if fee < uint64(size)*params.MinRelayFeeRate {
		return ErrLowFee
	}
	// 容量：超限时驱逐最低费率交易；若新交易费率不高于最低，则拒绝。
	for (len(p.entries) >= p.maxTx || p.totalBytes+size > p.maxBytes) && len(p.entries) > 0 {
		lowest := p.lowestLocked()
		if lowest == nil || feeRate <= lowest.FeeRate {
			return ErrPoolFull
		}
		p.removeLocked(lowest.Tx.Hash())
	}
	p.seq++
	p.entries[txID] = &Entry{Tx: tx, Fee: fee, FeeRate: feeRate, AddedAt: time.Now(), Seq: p.seq, Size: size}
	for _, in := range tx.Inputs {
		p.spent[utxo.Key{TxID: in.PrevTxHash, OutIndex: in.OutIndex}] = txID
	}
	p.totalBytes += size
	return nil
}

// verifySig 调用 wallet.Verify（P-256 ECDSA，与 UTXO 校验一致）。
func verifySig(pubKey []byte, msgHash [32]byte, sig []byte) (bool, error) {
	return wallet.Verify(pubKey, msgHash, sig)
}

// lowestLocked 返回费率最低（费率相同最晚入池）的条目；调用方须持锁。
func (p *Pool) lowestLocked() *Entry {
	var lowest *Entry
	for _, e := range p.entries {
		if lowest == nil || e.FeeRate < lowest.FeeRate ||
			(e.FeeRate == lowest.FeeRate && e.Seq > lowest.Seq) {
			lowest = e
		}
	}
	return lowest
}

// removeLocked 删除一笔池内交易并释放其 spent 标记；调用方须持锁。
func (p *Pool) removeLocked(txID [32]byte) {
	e, ok := p.entries[txID]
	if !ok {
		return
	}
	delete(p.entries, txID)
	p.totalBytes -= e.Size
	for _, in := range e.Tx.Inputs {
		k := utxo.Key{TxID: in.PrevTxHash, OutIndex: in.OutIndex}
		if p.spent[k] == txID {
			delete(p.spent, k)
		}
	}
}

// Remove 删除一笔池内交易（打包确认 / 显式移除用）。
func (p *Pool) Remove(txID [32]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.removeLocked(txID)
}

// RemoveConfirmed 移除已在块中确认的交易（打包后调用）。
func (p *Pool) RemoveConfirmed(txs []*transaction.Transaction) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tx := range txs {
		p.removeLocked(tx.Hash())
	}
}

// expireLocked 删除过期交易；调用方须持锁。
func (p *Pool) expireLocked(now time.Time) {
	for txID, e := range p.entries {
		if now.Sub(e.AddedAt) > p.expiry {
			p.removeLocked(txID)
		}
	}
}

// Expire 删除过期交易（对外接口）。
func (p *Pool) Expire(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(now)
}

// Prune 按当前 UTXO 集合清理失效交易：输入既不在 UTXO 中、也不在池内父交易中时删除。
// 块上链 / 重组后调用（重组时被挤出的交易由调用方重新 Add，Prune 只删已无效的）。
func (p *Pool) Prune(utxoSet *utxo.Set) {
	p.mu.Lock()
	defer p.mu.Unlock()
	// 反复扫描直到无删除（删除父交易可能使子交易失效）。
	for {
		var doomed [][32]byte
		for txID, e := range p.entries {
			bad := false
			for _, in := range e.Tx.Inputs {
				k := utxo.Key{TxID: in.PrevTxHash, OutIndex: in.OutIndex}
				if _, ok := utxoSet.Get(k); ok {
					continue
				}
				if _, ok := p.entries[in.PrevTxHash]; ok && int(in.OutIndex) < len(p.entries[in.PrevTxHash].Tx.Outputs) {
					continue
				}
				bad = true
				break
			}
			if bad {
				doomed = append(doomed, txID)
			}
		}
		if len(doomed) == 0 {
			return
		}
		for _, txID := range doomed {
			p.removeLocked(txID)
		}
	}
}

// Sorted 返回按费率降序、入池顺序升序的全部条目（打包 / 调试用）。
func (p *Pool) Sorted() []*Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*Entry, 0, len(p.entries))
	for _, e := range p.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FeeRate != out[j].FeeRate {
			return out[i].FeeRate > out[j].FeeRate
		}
		return out[i].Seq < out[j].Seq
	})
	return out
}

// SelectForBlock 按费率从高到低挑选交易，直到块重上限 maxWeight（不含 Coinbase 与 80 字节头，
// 调用方组装时须把 Coinbase + 头计入总重）。输入未满足的交易跳过，下一轮再试。
// 返回选中的交易与手续费总和。
func (p *Pool) SelectForBlock(maxWeight int, utxoSet *utxo.Set) ([]*transaction.Transaction, uint64) {
	sorted := p.Sorted()
	var selected []*transaction.Transaction
	var totalFee uint64
	weight := 0
	// 模拟 UTXO：池内已选交易的输出可作为后续交易的输入（祖先打包）。
	available := make(map[utxo.Key]bool)
	for _, e := range sorted {
		txWeight := e.Size * 4
		if weight+txWeight > maxWeight {
			continue
		}
		ok := true
		for _, in := range e.Tx.Inputs {
			k := utxo.Key{TxID: in.PrevTxHash, OutIndex: in.OutIndex}
			if available[k] {
				continue
			}
			if _, exists := utxoSet.Get(k); !exists {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		selected = append(selected, e.Tx)
		totalFee += e.Fee
		weight += txWeight
		txID := e.Tx.Hash()
		for outIdx := range e.Tx.Outputs {
			available[utxo.Key{TxID: txID, OutIndex: uint32(outIdx)}] = true
		}
	}
	return selected, totalFee
}

// PackBlock 组装候选块的交易列表：Coinbase（补贴 + 选中交易费和）+ 选中的 Mempool 交易。
// weightLimit 为块重上限（含 80 字节头 + Coinbase，调用方须保证 Coinbase 尺寸计入）。
func PackBlock(coinbaseValue uint64, coinbasePKH [20]byte, selected []*transaction.Transaction) []*transaction.Transaction {
	coinbase := transaction.NewCoinbaseTx(coinbasePKH, coinbaseValue)
	out := make([]*transaction.Transaction, 0, len(selected)+1)
	out = append(out, coinbase)
	out = append(out, selected...)
	return out
}

// BlockWeight 返回候选块的权重（80 字节头 + 各交易尺寸之和，再 ×4）。
func BlockWeight(txs []*transaction.Transaction) int {
	size := 80
	for _, tx := range txs {
		size += tx.SerializedSize()
	}
	return size * 4
}
