// Package transaction 实现 UTXO（未花费交易输出）模型下的交易结构。
//
// UTXO 模型的核心思想：
//   - 每一笔交易消费若干「输入」（引用之前某笔交易的输出），产生若干「输出」
//   - 一个输出一旦被消费，就不能再被引用（防止双花）
//   - 账户余额 = 属于该地址、尚未被消费的所有输出金额之和
//
// 这是比特币采用的模型，相比账户模型（以太坊）更天然支持并行验证。
package transaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// TxInput 交易输入：引用上一笔交易的某个输出作为本次花费的来源。
type TxInput struct {
	PrevTxHash [32]byte // 被引用的交易哈希
	OutIndex   uint32   // 被引用输出在那笔交易中的索引
	Signature  []byte   // 花费者对本交易的签名，证明其拥有该输出的花费权
	PubKey     []byte   // 花费者的公钥，用于验签
}

// TxOutput 交易输出：一定数量的币，被锁定给某个地址（公钥哈希）。
type TxOutput struct {
	Value      uint64   // 输出金额（建议使用最小单位整数，避免浮点误差）
	PubKeyHash [20]byte // 接收方地址对应的公钥哈希，只有对应私钥持有者能花费
}

// Transaction 一笔交易 = 若干输入 + 若干输出。
// Coinbase 交易（挖矿奖励）没有真实输入，通常用一个空引用的输入占位。
type Transaction struct {
	Inputs  []TxInput
	Outputs []TxOutput
}

// IsCoinbase 判断是否为矿工出块奖励交易：没有输入引用任何真实的前置交易。
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Inputs) == 1 && tx.Inputs[0].PrevTxHash == [32]byte{} && tx.Inputs[0].OutIndex == 0xFFFFFFFF
}

// NewCoinbaseTx 构造一笔出块奖励交易，付给矿工地址 reward 数量的新币。
func NewCoinbaseTx(minerPubKeyHash [20]byte, reward uint64) *Transaction {
	return &Transaction{
		Inputs: []TxInput{
			{
				PrevTxHash: [32]byte{},
				OutIndex:   0xFFFFFFFF,
			},
		},
		Outputs: []TxOutput{
			{Value: reward, PubKeyHash: minerPubKeyHash},
		},
	}
}

// serializeForHash 将交易序列化为字节流用于计算哈希（TxID）。
// 注意：这里不包含签名（否则会形成"签名依赖自身哈希"的循环问题），
// 实际生产实现建议参考 BIP-143 的 SegWit 序列化方案以避免延展性攻击。
func (tx *Transaction) serializeForHash() []byte {
	buf := new(bytes.Buffer)
	for _, in := range tx.Inputs {
		buf.Write(in.PrevTxHash[:])
		_ = binary.Write(buf, binary.LittleEndian, in.OutIndex)
	}
	for _, out := range tx.Outputs {
		_ = binary.Write(buf, binary.LittleEndian, out.Value)
		buf.Write(out.PubKeyHash[:])
	}
	return buf.Bytes()
}

// Hash 计算交易 ID（TxID）。
func (tx *Transaction) Hash() [32]byte {
	return sha256.Sum256(tx.serializeForHash())
}
