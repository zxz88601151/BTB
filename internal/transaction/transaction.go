// Package transaction 实现 UTXO（未花费交易输出）模型下的交易结构。
//
// UTXO 模型的核心思想：
//   - 每一笔交易消费若干「输入」（引用之前某笔交易的输出），产生若干「输出」
//   - 一个输出一旦被消费，就不能再被引用（防止双花）
//   - 账户余额 = 属于该地址、尚未被消费的所有输出金额之和
//
// 这是比特币采用的模型，相比账户模型（以太坊）更天然支持并行验证。
// 金额一律用整数 base units（1 HUNDUN = 100_000_000 base units），禁止浮点。
// 手续费与粉尘见冻结表 §7：fee = sum(Inputs) - sum(Outputs) >= 0（共识）；
// 最低中继 1/字节、粉尘线 546（策略层，非共识）。
package transaction

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"

	"hundun/internal/params"
)

// TxInput 交易输入：引用上一笔交易的某个输出作为本次花费的来源。
type TxInput struct {
	PrevTxHash [32]byte // 被引用的交易哈希
	OutIndex   uint32   // 被引用输出在那笔交易中的索引
	Signature  []byte   // 花费者对本交易的签名，证明其拥有该输出的花费权；
	// 对 Coinbase 输入，本字段为任意附带数据（例如创世报文），不是真实签名，见 serializeForHash 注释。
	PubKey []byte // 花费者的公钥，用于验签
}

// TxOutput 交易输出：一定数量的币，被锁定给某个地址（公钥哈希）。
type TxOutput struct {
	Value      uint64   // 输出金额（base units 整数，最小单位）
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

// NewCoinbaseTx 构造一笔出块奖励交易，付给矿工地址 reward 数量的新币（无附带数据）。
func NewCoinbaseTx(minerPubKeyHash [20]byte, reward uint64) *Transaction {
	return NewCoinbaseTxWithData(minerPubKeyHash, reward, nil)
}

// NewCoinbaseTxWithData 构造带附带数据（例如创世报文）的 Coinbase 交易。
// data 会放进 Coinbase 输入的 Signature 字段，并计入 TxID（见 serializeForHash）。
func NewCoinbaseTxWithData(minerPubKeyHash [20]byte, reward uint64, data []byte) *Transaction {
	return &Transaction{
		Inputs: []TxInput{
			{
				PrevTxHash: [32]byte{},
				OutIndex:   0xFFFFFFFF,
				Signature:  append([]byte(nil), data...),
			},
		},
		Outputs: []TxOutput{
			{Value: reward, PubKeyHash: minerPubKeyHash},
		},
	}
}

// TotalOutputValue 返回所有输出金额之和（溢出时返回 false；调用方须处理）。
func (tx *Transaction) TotalOutputValue() (uint64, bool) {
	var sum uint64
	for _, out := range tx.Outputs {
		if out.Value > params.MaxMoney {
			return 0, false
		}
		if sum > params.MaxMoney-out.Value {
			return 0, false
		}
		sum += out.Value
	}
	return sum, true
}

// FeeFromInputValues 根据输入 UTXO 金额列表计算手续费：fee = sum(inputValues) - sum(outputs)。
// 输入金额须由调用方从 UTXO 集合查得（交易本身不携带输入金额）。
// 若输入和 < 输出和，返回 false（凭空印钱，无效）。
func (tx *Transaction) FeeFromInputValues(inputValues []uint64) (uint64, bool) {
	if len(inputValues) != len(tx.Inputs) {
		return 0, false
	}
	var inSum uint64
	for _, v := range inputValues {
		if v > params.MaxMoney {
			return 0, false
		}
		if inSum > params.MaxMoney-v {
			return 0, false
		}
		inSum += v
	}
	outSum, ok := tx.TotalOutputValue()
	if !ok {
		return 0, false
	}
	if inSum < outSum {
		return 0, false
	}
	return inSum - outSum, true
}

// SerializedSize 返回交易序列化尺寸（确定性定义，用于费率与块大小/权重）。
// 编码：4 字节输入计数 + 每输入 (32 PrevTxHash + 4 OutIndex + 4 SigLen + len(Sig) + 4 PubKeyLen + len(PubKey))
// + 4 字节输出计数 + 每输出 (8 Value + 20 PubKeyHash)。
// 注意：本尺寸定义与 serializeForHash 不同——后者为 TxID 用，不含普通签名；前者为尺寸用，含全部字段。
func (tx *Transaction) SerializedSize() int {
	size := 4 + 4
	for _, in := range tx.Inputs {
		size += 32 + 4 + 4 + len(in.Signature) + 4 + len(in.PubKey)
	}
	for range tx.Outputs {
		size += 8 + 20
	}
	return size
}

// FeeRate 返回费率：fee / SerializedSize（base units / 字节，向下取整）。
func (tx *Transaction) FeeRate(fee uint64) uint64 {
	size := tx.SerializedSize()
	if size <= 0 {
		return 0
	}
	return fee / uint64(size)
}

// MeetsMinRelayFee 判断给定手续费是否满足最低中继费率：fee >= size * MinRelayFeeRate。
func (tx *Transaction) MeetsMinRelayFee(fee uint64) bool {
	return fee >= uint64(tx.SerializedSize())*params.MinRelayFeeRate
}

// IsDustOutput 判断单个输出是否为粉尘：Value < DustThreshold（546，策略层）。
func IsDustOutput(out TxOutput) bool {
	return out.Value < params.DustThreshold
}

// ContainsDust 判断交易是否含任一粉尘输出。
func (tx *Transaction) ContainsDust() bool {
	for _, out := range tx.Outputs {
		if IsDustOutput(out) {
			return true
		}
	}
	return false
}

// serializeForHash 将交易序列化为字节流用于计算哈希（TxID）。
// 普通交易：不包含签名与公钥（否则会形成"签名依赖自身哈希"的循环问题），
// 实际生产实现建议参考 BIP-143 的 SegWit 序列化方案以避免延展性攻击。
// Coinbase 交易：必须包含输入的 Signature 附带数据（例如创世报文），与 BTC 的
// scriptSig 计入 TxID 对齐；否则报文可被篡改而不改 TxID，创世报文将失去承诺效力。
// Coinbase 的 Signature 不是真实签名，不验签。
func (tx *Transaction) serializeForHash() []byte {
	buf := new(bytes.Buffer)
	isCoinbase := tx.IsCoinbase()
	for _, in := range tx.Inputs {
		buf.Write(in.PrevTxHash[:])
		_ = binary.Write(buf, binary.LittleEndian, in.OutIndex)
		if isCoinbase {
			_ = binary.Write(buf, binary.LittleEndian, uint32(len(in.Signature)))
			buf.Write(in.Signature)
		}
	}
	for _, out := range tx.Outputs {
		_ = binary.Write(buf, binary.LittleEndian, out.Value)
		buf.Write(out.PubKeyHash[:])
	}
	return buf.Bytes()
}

// Hash 计算交易 ID（TxID）。
// 注意：本函数为单次 SHA-256（沿用骨架原实现，未改成双 SHA-256，避免静默改变已有 TxID 语义）。
// 与区块头 Hash（双 SHA-256）不同，实施与审计时不得混淆。
func (tx *Transaction) Hash() [32]byte {
	return sha256.Sum256(tx.serializeForHash())
}
