// Package utxo 实现 UTXO（未花费交易输出）集合：任务卡片 1 的核心状态。
//
// 设计：
//   - Key = (TxID, OutIndex)，唯一标识一个输出。
//   - Entry 记录输出本身 + 产生它的高度 / 是否 Coinbase / 所在区块哈希（后两者供成熟花费校验与调试）。
//   - ApplyBlock / RollbackBlock 成对出现：Apply 消费输入、新增输出并返回 BlockUndo；
//     Rollback 用 BlockUndo 恢复被消费的输入、删除本块新增的输出。重组（任务卡片 2）
//     依赖这对操作做到“回滚旧链、应用新链”。
//
// 注意：交易 Hash() 为单次 SHA-256（沿用骨架语义），与区块头双 SHA-256 不同。
package utxo

import (
	"errors"
	"fmt"

	"hundun/internal/block"
	"hundun/internal/params"
	"hundun/internal/transaction"
	"hundun/internal/wallet"
)

var (
	ErrUTXONotFound     = errors.New("UTXO 不存在：输入引用了不存在或已花费的输出")
	ErrDoubleSpend      = errors.New("双花：同一输出在同一块内被花费两次")
	ErrImmatureCoinbase = errors.New("Coinbase 未成熟：花费高度 - 产生高度 < 100")
	ErrBadSignature     = errors.New("签名无效：签名验签失败或公钥哈希与 UTXO 锁定地址不符")
	ErrInvalidTx        = errors.New("交易无效：输入/输出为空或金额超限")
	ErrNegativeFee      = errors.New("手续费无效：输入和 < 输出和")
)

// Key 唯一标识一个 UTXO。
type Key struct {
	TxID     [32]byte
	OutIndex uint32
}

// Entry 一个 UTXO 的完整记录。
type Entry struct {
	Output     transaction.TxOutput
	Height     int      // 产生该输出的区块高度
	IsCoinbase bool     // 是否来自 Coinbase 交易
	BlockHash  [32]byte // 所在区块哈希
}

// SpentEntry 被某块消费的 UTXO（用于回滚恢复）。
type SpentEntry struct {
	Key   Key
	Entry Entry
}

// BlockUndo 一块的 UTXO 变更逆操作：被消费的输入 + 本块新增的输出 Key。
type BlockUndo struct {
	Spent   []SpentEntry
	Created []Key
}

// Set UTXO 集合（内存版，接口与 storage 内存版一致，后续持久化可替换实现）。
type Set struct {
	m map[Key]Entry
}

// NewSet 返回空 UTXO 集合。
func NewSet() *Set {
	return &Set{m: make(map[Key]Entry)}
}

// Get 查询一个 UTXO。
func (s *Set) Get(k Key) (Entry, bool) {
	e, ok := s.m[k]
	return e, ok
}

// Has 判断 UTXO 是否存在（未花费）。
func (s *Set) Has(k Key) bool {
	_, ok := s.m[k]
	return ok
}

// Put 新增/覆盖一个 UTXO。
func (s *Set) Put(k Key, e Entry) {
	s.m[k] = e
}

// Delete 删除一个 UTXO（花费时）。
func (s *Set) Delete(k Key) {
	delete(s.m, k)
}

// Len 返回 UTXO 数量。
func (s *Set) Len() int {
	return len(s.m)
}

// Snapshot 返回集合的浅拷贝（调试 / 测试用）。
func (s *Set) Snapshot() map[Key]Entry {
	out := make(map[Key]Entry, len(s.m))
	for k, v := range s.m {
		out[k] = v
	}
	return out
}

// PubKeyHashOf 计算公钥哈希（wallet.PubKeyHashOf 的别名，SHA256 截断 20 字节）。
func PubKeyHashOf(pubKey []byte) [20]byte {
	return wallet.PubKeyHashOf(pubKey)
}

// ValidateTx 对一笔非 Coinbase 交易做完整校验（不修改集合）。
// spentInBlock 记录本块内已花费的 UTXO（防同块内双花），调用方传入并由本函数填充。
// 返回手续费 fee = 输入和 - 输出和。
// 校验项：输入/输出非空、金额范围、UTXO 存在、成熟花费、签名验签。
func ValidateTx(tx *transaction.Transaction, height int, s *Set, spentInBlock map[Key]bool) (uint64, error) {
	if tx.IsCoinbase() {
		return 0, fmt.Errorf("ValidateTx 不接受 Coinbase 交易")
	}
	if len(tx.Inputs) == 0 || len(tx.Outputs) == 0 {
		return 0, ErrInvalidTx
	}
	var inSum uint64
	for _, in := range tx.Inputs {
		k := Key{TxID: in.PrevTxHash, OutIndex: in.OutIndex}
		if spentInBlock != nil && spentInBlock[k] {
			return 0, ErrDoubleSpend
		}
		entry, ok := s.Get(k)
		if !ok {
			return 0, ErrUTXONotFound
		}
		// Coinbase 成熟花费：花费高度 - 产生高度 >= 100。
		if entry.IsCoinbase && height-entry.Height < params.CoinbaseMaturity {
			return 0, ErrImmatureCoinbase
		}
		// 签名验签：签名对象 = TxID（交易 Hash，签名/公钥本身不计入 TxID，故签名前后 TxID 稳定）。
		// 公钥哈希必须等于 UTXO 锁定的地址，否则任何人可用自己的签名花别人的币。
		if PubKeyHashOf(in.PubKey) != entry.Output.PubKeyHash {
			return 0, ErrBadSignature
		}
		okSig, err := wallet.Verify(in.PubKey, tx.Hash(), in.Signature)
		if err != nil || !okSig {
			return 0, ErrBadSignature
		}
		if entry.Output.Value > params.MaxMoney {
			return 0, ErrInvalidTx
		}
		if inSum > params.MaxMoney-entry.Output.Value {
			return 0, ErrInvalidTx
		}
		inSum += entry.Output.Value
		if spentInBlock != nil {
			spentInBlock[k] = true
		}
	}
	outSum, ok := tx.TotalOutputValue()
	if !ok {
		return 0, ErrInvalidTx
	}
	if inSum < outSum {
		return 0, ErrNegativeFee
	}
	return inSum - outSum, nil
}

// ApplyBlock 把一块的 UTXO 变更应用到集合（调用方须先完成 ValidateBlock）。
// 返回 BlockUndo（供 RollbackBlock）。手续费在 Validate 阶段算出，本函数只做状态变更。
// 注意：ApplyBlock 不是原子的——调用方须保证块已校验通过；若中途返回错误，集合可能处于
// 部分应用状态，调用方应丢弃该集合（重组失败路径会整体恢复，见 blockchain）。
func (s *Set) ApplyBlock(b *block.Block, height int) (*BlockUndo, error) {
	undo := &BlockUndo{}
	blockHash := b.Header.Hash()
	for i, tx := range b.Transactions {
		if i == 0 {
			// Coinbase：只新增输出，不消费输入。
			// 防御：输出 Key 已存在说明 ValidateBlock 的 BIP-30 检查被绕过，拒绝应用，不静默覆盖。
			if !tx.IsCoinbase() {
				return nil, fmt.Errorf("ApplyBlock：首笔须为 Coinbase")
			}
			txID := tx.Hash()
			for outIdx, out := range tx.Outputs {
				k := Key{TxID: txID, OutIndex: uint32(outIdx)}
				if _, exists := s.Get(k); exists {
					return nil, fmt.Errorf("ApplyBlock：Coinbase 输出 Key 已存在（重复 Coinbase），拒绝覆盖")
				}
				s.Put(k, Entry{Output: out, Height: height, IsCoinbase: true, BlockHash: blockHash})
				undo.Created = append(undo.Created, k)
			}
			continue
		}
		for _, in := range tx.Inputs {
			k := Key{TxID: in.PrevTxHash, OutIndex: in.OutIndex}
			entry, ok := s.Get(k)
			if !ok {
				return nil, ErrUTXONotFound
			}
			undo.Spent = append(undo.Spent, SpentEntry{Key: k, Entry: entry})
			s.Delete(k)
		}
		txID := tx.Hash()
		for outIdx, out := range tx.Outputs {
			k := Key{TxID: txID, OutIndex: uint32(outIdx)}
			s.Put(k, Entry{Output: out, Height: height, IsCoinbase: false, BlockHash: blockHash})
			undo.Created = append(undo.Created, k)
		}
	}
	return undo, nil
}

// RollbackBlock 用 BlockUndo 逆转一块的 UTXO 变更（重组时按逆序调用）。
func (s *Set) RollbackBlock(undo *BlockUndo) {
	if undo == nil {
		return
	}
	for _, k := range undo.Created {
		s.Delete(k)
	}
	for _, spent := range undo.Spent {
		s.Put(spent.Key, spent.Entry)
	}
}
