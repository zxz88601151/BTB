// Package params 集中存放混沌（HUNDUN）冻结的经济与共识核心常量。
//
// 来源：冻结表 V2 + §7 费/粉尘补篇 + 创世块设计（均已由 Owner 拍板）。
// 本包必须是叶子包：不得 import hundun/internal 下的任何包，避免循环依赖。
// 金额一律用整数 base units（1 HUNDUN = COIN base units），禁止浮点。
package params

// 经济参数（冻结表 §1）。
const (
	// COIN 1 HUNDUN = 100_000_000 base units（对应 BTC 的 1 BTC = 100_000_000 sats）。
	COIN = 100_000_000

	// InitialSubsidy 初始补贴 50 HUNDUN。
	InitialSubsidy = 50 * COIN

	// HalvingInterval 减半间隔 210_000 块。
	HalvingInterval = 210_000

	// MaxHalvings 补贴函数保护上限（BTC 原式 >=64 返回 0；实际 33 次后已为 0）。
	MaxHalvings = 64

	// MaxMoney 金额有效范围 [0, 2^63)，即最大值 2^63-1（防溢出，共识规则）。
	MaxMoney = uint64(1<<63 - 1)
)

// GetBlockSubsidy 返回给定高度的区块补贴（BTC 原式）。
// halvings = height / 210000；halvings >= 64 返回 0；否则 (50*COIN) >> halvings。
func GetBlockSubsidy(height uint64) uint64 {
	halvings := height / HalvingInterval
	if halvings >= MaxHalvings {
		return 0
	}
	return uint64(InitialSubsidy) >> halvings
}

// TotalSupply 返回 33 个 era 的实际发行总量（取整后校验值）。
// 2_099_999_997_690_000 base units = 20_999_999.9769 HUNDUN。
func TotalSupply() uint64 {
	var total uint64
	for era := uint64(0); era < 33; era++ {
		subsidy := uint64(InitialSubsidy) >> era
		if subsidy == 0 {
			break
		}
		total += HalvingInterval * subsidy
	}
	return total
}

// 共识核心参数（冻结表 §2）。
const (
	// TargetBlockTimeSeconds 目标出块间隔 600 秒。
	TargetBlockTimeSeconds = 600

	// DifficultyAdjustmentInterval 难度调整间隔 2016 块。
	DifficultyAdjustmentInterval = 2016

	// ExpectedTimespanSeconds 期望周期时长 2016*600 = 1_209_600 秒（14 天）。
	ExpectedTimespanSeconds = 1_209_600

	// MinTimespanSeconds 单次调整钳制下限 = 期望值 / 4。
	MinTimespanSeconds = 302_400

	// MaxTimespanSeconds 单次调整钳制上限 = 期望值 * 4。
	MaxTimespanSeconds = 4_838_400

	// GenesisBits 创世 / 最低难度 nBits。
	GenesisBits = 0x1d00ffff

	// MaxBits 最低难度 nBits（与 GenesisBits 相同）。
	MaxBits = 0x1d00ffff

	// CoinbaseMaturity Coinbase 成熟期 100 块。
	CoinbaseMaturity = 100

	// MaxBlockWeight 区块权重上限 4_000_000（无见证时 weight = size*4）。
	MaxBlockWeight = 4_000_000

	// MaxBlockSize 区块最大尺寸 1_000_000 字节（无见证时等价）。
	MaxBlockSize = 1_000_000

	// MaxFutureSeconds 块时间戳不得超过网络调整时间 + 7200 秒。
	MaxFutureSeconds = 7200

	// MedianTimeSpan 时间戳中位数窗口：前 11 个块。
	MedianTimeSpan = 11
)

// 手续费与粉尘（冻结表 §7）。
const (
	// MinRelayFeeRate 最低中继费率：1 base unit / 字节（1000 / kB）。策略层，非共识。
	MinRelayFeeRate = 1

	// DustRelayFee 粉尘费率：3 base units / 字节（3000 / kB）。策略层，非共识。
	DustRelayFee = 3

	// DustThreshold 粉尘线：546 base units（BTC 1:1 常量，直接冻结）。策略层，非共识。
	DustThreshold = 546

	// WalletMinOutput 钱包默认最低输出：1000 base units（建议，非共识，实施时作默认）。
	WalletMinOutput = 1000
)
