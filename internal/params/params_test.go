package params

import "testing"

// 补贴五点：冻结表 §1，height 0 / 209999 / 210000 / 6929999 / 6930000。
func TestGetBlockSubsidyPoints(t *testing.T) {
	cases := []struct {
		height uint64
		want   uint64
	}{
		{0, 5_000_000_000},
		{209_999, 5_000_000_000},
		{210_000, 2_500_000_000},
		{6_929_999, 1},    // 最后一个非零补贴（33 era 的最后高度）
		{6_930_000, 0},    // 补贴有效高度 0–6,929,999，之后为 0
		{33 * 210_000, 0}, // halvings = 33 时已为 0（实际 33 era 后）
		{64 * 210_000, 0}, // halvings >= 64 返回 0
	}
	for _, c := range cases {
		if got := GetBlockSubsidy(c.height); got != c.want {
			t.Errorf("GetBlockSubsidy(%d) = %d, want %d", c.height, got, c.want)
		}
	}
}

// 总量：33 era 实际发行 = 2_099_999_997_690_000 base units。
func TestTotalSupply(t *testing.T) {
	const want = uint64(2_099_999_997_690_000)
	if got := TotalSupply(); got != want {
		t.Errorf("TotalSupply() = %d, want %d", got, want)
	}
}

// 费/粉尘常量（冻结表 §7）。
func TestFeeDustConstants(t *testing.T) {
	if COIN != 100_000_000 {
		t.Errorf("COIN = %d, want 100000000", COIN)
	}
	if MinRelayFeeRate != 1 {
		t.Errorf("MinRelayFeeRate = %d, want 1", MinRelayFeeRate)
	}
	if DustRelayFee != 3 {
		t.Errorf("DustRelayFee = %d, want 3", DustRelayFee)
	}
	if DustThreshold != 546 {
		t.Errorf("DustThreshold = %d, want 546", DustThreshold)
	}
	if CoinbaseMaturity != 100 {
		t.Errorf("CoinbaseMaturity = %d, want 100", CoinbaseMaturity)
	}
}
