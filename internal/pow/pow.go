// Package pow 实现工作量证明（Proof of Work）挖矿与难度调整算法。
//
// 挖矿的本质：不断修改区块头中的 Nonce（以及必要时的时间戳/coinbase extra nonce），
// 使区块头哈希值在数值上小于当前难度目标（Target）。由于哈希函数的不可预测性，
// 唯一的办法就是暴力枚举，这也是"工作量"的来源。
package pow

import (
	"math/big"

	"p2pchain/internal/block"
)

const (
	// MaxTargetBits 表示最低难度对应的目标值的前导零位数（可按需调整）。
	// 数值越小，初始难度越低，适合个人 CPU 挖矿测试网。
	MaxTargetBits = 20

	// TargetBlockTimeSeconds 期望的平均出块间隔（秒）。
	// 比特币是 600 秒（10分钟），测试阶段可以设置更短，比如 30-60 秒，便于调试。
	TargetBlockTimeSeconds = 60

	// DifficultyAdjustmentInterval 每隔多少个区块重新计算一次难度。
	// 比特币是 2016，个人项目初期建议设置得小一些（如 20~50）以便更快看到难度变化效果。
	DifficultyAdjustmentInterval = 20
)

// BitsToTarget 将压缩格式的难度（Bits）还原为大整数目标值。
// 简化实现：这里假设 bits 直接表示目标值前导零的位数（而不是比特币真实的浮点式编码），
// 便于初期理解和调试；后续可以替换成与比特币兼容的 nBits 编码。
func BitsToTarget(bits uint32) *big.Int {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-bits))
	return target
}

// MaxTarget 返回初始（最低）难度对应的目标值。
func MaxTarget() *big.Int {
	return BitsToTarget(MaxTargetBits)
}

// Validate 校验区块头的哈希是否满足难度目标：hash 数值必须小于 target。
func Validate(h *block.Header) bool {
	target := BitsToTarget(h.Bits)
	hash := h.Hash()
	hashInt := new(big.Int).SetBytes(hash[:])
	return hashInt.Cmp(target) == -1
}

// Mine 对候选区块执行工作量证明搜索：不断递增 Nonce，直到哈希满足难度要求。
// maxIterations 用于防止死循环（例如需要更新时间戳/交易时提前退出重新组装区块）；
// 传 0 表示不限制迭代次数。
// 返回是否找到解，以及尝试的次数（可用于统计算力）。
func Mine(b *block.Block, maxIterations uint64) (found bool, attempts uint64) {
	target := BitsToTarget(b.Header.Bits)

	var nonce uint64
	for maxIterations == 0 || nonce < maxIterations {
		b.Header.Nonce = nonce
		hash := b.Header.Hash()
		hashInt := new(big.Int).SetBytes(hash[:])

		if hashInt.Cmp(target) == -1 {
			return true, nonce + 1
		}
		nonce++
	}
	return false, nonce
}

// AdjustBits 根据最近一个难度调整周期实际耗费的时间，计算下一周期的难度（Bits）。
//
// 逻辑与比特币一致：
//   - 若实际用时比期望用时短（矿工太多/算力太强），提高难度（增大 bits）
//   - 若实际用时比期望用时长（矿工太少/算力下降），降低难度（减小 bits）
//
// 为避免难度剧烈波动，比特币将单次调整幅度限制在 4 倍以内，这里同样做了限制。
func AdjustBits(currentBits uint32, actualTimespanSeconds int64) uint32 {
	expected := int64(TargetBlockTimeSeconds * DifficultyAdjustmentInterval)

	// 限制调整幅度在 [expected/4, expected*4] 之间，防止极端值造成难度失控
	minTimespan := expected / 4
	maxTimespan := expected * 4
	if actualTimespanSeconds < minTimespan {
		actualTimespanSeconds = minTimespan
	}
	if actualTimespanSeconds > maxTimespan {
		actualTimespanSeconds = maxTimespan
	}

	currentTarget := BitsToTarget(currentBits)
	newTarget := new(big.Int).Mul(currentTarget, big.NewInt(actualTimespanSeconds))
	newTarget.Div(newTarget, big.NewInt(expected))

	// 难度不能低于初始最低难度（即 target 不能超过 MaxTarget）
	if newTarget.Cmp(MaxTarget()) == 1 {
		return MaxTargetBits
	}

	// 将 newTarget 换算回近似的 bits：找到使 2^(256-bits) 最接近 newTarget 的 bits
	newBits := uint32(256 - newTarget.BitLen())
	if newBits < 1 {
		newBits = 1
	}
	if newBits > MaxTargetBits {
		newBits = MaxTargetBits
	}
	return newBits
}
