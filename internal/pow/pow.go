// Package pow 实现工作量证明（Proof of Work）挖矿与难度调整算法。
//
// 冻结规则（冻结表 V2 §2）：nBits 紧凑编码、600 秒出块、2016 块调整、
// 单次钳制 [302400, 4838400]、MaxTarget = 0x1d00ffff、难度比较用小端解释。
// 挖矿的本质：不断修改区块头中的 Nonce（以及必要时的时间戳/coinbase extra nonce），
// 使区块头哈希值在数值上小于等于当前难度目标（Target）。
package pow

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"hundun/internal/block"
	"hundun/internal/params"
)

// sha256Sum 返回 data 的单次 SHA-256（供 Mine 快路径使用）。
func sha256Sum(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// 冻结常量（params 的别名，保持旧调用点可读；以 params 为准）。
const (
	// TargetBlockTimeSeconds 期望的平均出块间隔（秒）：600。
	TargetBlockTimeSeconds = params.TargetBlockTimeSeconds

	// DifficultyAdjustmentInterval 每隔多少个区块重新计算一次难度：2016。
	DifficultyAdjustmentInterval = params.DifficultyAdjustmentInterval

	// GenesisBits 创世 / 最低难度 nBits：0x1d00ffff。
	GenesisBits = params.GenesisBits

	// MaxBits 最低难度 nBits（与 GenesisBits 相同）。
	MaxBits = params.MaxBits
)

// BitsToTarget 将 nBits 紧凑编码还原为大整数目标值（BTC GetCompact 逆操作）。
// exponent = bits>>24，mantissa = bits & 0xFFFFFF。
// exponent <= 3: target = mantissa >> (8*(3-exponent))；
// exponent > 3: target = mantissa << (8*(exponent-3))。
func BitsToTarget(bits uint32) *big.Int {
	exponent := bits >> 24
	mantissa := bits & 0xFFFFFF
	if mantissa == 0 {
		return big.NewInt(0)
	}
	m := big.NewInt(int64(mantissa))
	if exponent <= 3 {
		m.Rsh(m, uint(8*(3-exponent)))
		return m
	}
	m.Lsh(m, uint(8*(exponent-3)))
	return m
}

// TargetToBits 将目标值编码为 nBits（BTC GetCompact 规则）。
// 取目标值的有效字节，反向推导 exponent + mantissa；mantissa 最高位为 1 时需进位。
func TargetToBits(target *big.Int) uint32 {
	if target == nil || target.Sign() <= 0 {
		return 0
	}
	// nSize = 所需字节数 = (bitlen+7)/8。
	nSize := (target.BitLen() + 7) / 8
	var mantissa uint32
	if nSize <= 3 {
		// target << (8*(3-nSize))，取低 24 位即 mantissa。
		shifted := new(big.Int).Lsh(target, uint(8*(3-nSize)))
		mantissa = uint32(shifted.Uint64() & 0xFFFFFF)
	} else {
		shifted := new(big.Int).Rsh(target, uint(8*(nSize-3)))
		mantissa = uint32(shifted.Uint64() & 0xFFFFFF)
	}
	// mantissa 最高位（0x00800000）为 1 时右移 8 位、尺寸 +1（BTC GetCompact 进位规则）。
	if mantissa&0x00800000 != 0 {
		mantissa >>= 8
		nSize++
	}
	return (uint32(nSize) << 24) | mantissa
}

// MaxTarget 返回初始（最低）难度对应的目标值。
func MaxTarget() *big.Int {
	return BitsToTarget(params.MaxBits)
}

// targetBytes32 将目标值转为 32 字节大端数组；若目标 > 2^256-1 则返回全 0xFF（任意哈希通过）。
func targetBytes32(target *big.Int) [32]byte {
	var out [32]byte
	if target == nil || target.Sign() <= 0 {
		return out
	}
	if target.BitLen() > 256 {
		for i := range out {
			out[i] = 0xFF
		}
		return out
	}
	target.FillBytes(out[:])
	return out
}

// reverseHash 将哈希按字节反转（小端解释转大端比较用）。
func reverseHash(hash [32]byte) [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = hash[31-i]
	}
	return out
}

// HashMeetsTarget 判断哈希（小端解释）是否 <= 目标值。
func HashMeetsTarget(hash [32]byte, target *big.Int) bool {
	if target == nil || target.Sign() <= 0 {
		return false
	}
	rev := reverseHash(hash)
	targetB := targetBytes32(target)
	return bytes.Compare(rev[:], targetB[:]) <= 0
}

// Validate 校验区块头的哈希是否满足难度目标：uint256LE(hash) <= target。
func Validate(h *block.Header) bool {
	target := BitsToTarget(h.Bits)
	return HashMeetsTarget(h.Hash(), target)
}

// Mine 对候选区块执行工作量证明搜索：不断递增 Nonce，直到哈希满足难度要求。
// Nonce 为 uint32（冻结表 §2.3）；maxIterations 为尝试上限，传 0 表示扫满整个 uint32 空间。
// 返回是否找到解，以及尝试的次数。
// 性能说明：本函数按冻结的 80 字节头布局（Nonce 在最后 4 字节小端）复用序列化缓冲，
// 避免每轮重建头；正确性由 Validate（走完整 Hash()）复核。
// Nonce 空间耗尽未找到时返回 false，调用方须 Timestamp+1 或换 coinbase extra nonce 后重试。
func Mine(b *block.Block, maxIterations uint64) (found bool, attempts uint64) {
	target := BitsToTarget(b.Header.Bits)
	targetB := targetBytes32(target)

	// 一次性序列化头，之后只改最后 4 字节 Nonce（冻结布局：Nonce 在 [76:80] 小端）。
	header := b.Header.SerializeHeader()
	if len(header) != 80 {
		// 防御：布局异常时退回慢速路径（逐轮 Hash()）。
		return mineSlow(b, target, maxIterations)
	}

	var limit uint64 = 1 << 32
	if maxIterations != 0 && maxIterations < limit {
		limit = maxIterations
	}
	for nonce := uint64(0); nonce < limit; nonce++ {
		binary.LittleEndian.PutUint32(header[76:80], uint32(nonce))
		first := sha256Sum(header)
		second := sha256Sum(first[:])
		rev := reverseHash(second)
		if bytes.Compare(rev[:], targetB[:]) <= 0 {
			b.Header.Nonce = uint32(nonce)
			return true, nonce + 1
		}
	}
	// 未找到：将 Nonce 置为 0，避免残留中间值。
	b.Header.Nonce = 0
	return false, limit
}

// mineSlow 慢速兜底：逐轮调用 Header.Hash()（与 Validate 同路径）。
func mineSlow(b *block.Block, target *big.Int, maxIterations uint64) (bool, uint64) {
	var limit uint64 = 1 << 32
	if maxIterations != 0 && maxIterations < limit {
		limit = maxIterations
	}
	for nonce := uint64(0); nonce < limit; nonce++ {
		b.Header.Nonce = uint32(nonce)
		if HashMeetsTarget(b.Header.Hash(), target) {
			return true, nonce + 1
		}
	}
	b.Header.Nonce = 0
	return false, limit
}

// AdjustBits 根据最近一个难度调整周期实际耗费的时间，计算下一周期的难度（nBits）。
//
// 逻辑与比特币一致：实际用时短则提高难度（目标变小），实际用时长则降低难度。
// 单次调整钳制：实际周期时长限制在 [302400, 4838400]（期望值 1209600 的 [1/4, 4×]）。
// 难度不能低于初始最低难度（newTarget > MaxTarget 时返回 MaxBits）。
func AdjustBits(currentBits uint32, actualTimespanSeconds int64) uint32 {
	expected := int64(params.ExpectedTimespanSeconds)
	minTimespan := int64(params.MinTimespanSeconds)
	maxTimespan := int64(params.MaxTimespanSeconds)
	if actualTimespanSeconds < minTimespan {
		actualTimespanSeconds = minTimespan
	}
	if actualTimespanSeconds > maxTimespan {
		actualTimespanSeconds = maxTimespan
	}

	currentTarget := BitsToTarget(currentBits)
	newTarget := new(big.Int).Mul(currentTarget, big.NewInt(actualTimespanSeconds))
	newTarget.Div(newTarget, big.NewInt(expected))

	if newTarget.Cmp(MaxTarget()) == 1 {
		return params.MaxBits
	}
	return TargetToBits(newTarget)
}
