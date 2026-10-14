package pow

import (
	"math/big"
	"testing"

	"hundun/internal/block"
	"hundun/internal/params"
	"hundun/internal/transaction"
)

// nBits 0x1d00ffff 解码 = MaxTarget（bitlen 224，冻结表 §2.2）。
func TestBitsToTargetGenesis(t *testing.T) {
	got := BitsToTarget(0x1d00ffff)
	if got.Cmp(MaxTarget()) != 0 {
		t.Errorf("BitsToTarget(0x1d00ffff) != MaxTarget")
	}
	if got.BitLen() != 224 {
		t.Errorf("MaxTarget bitlen = %d, want 224", got.BitLen())
	}
}

// nBits 编码往返：解码再编码应还原（对 GenesisBits 与常见难度）。
func TestTargetToBitsRoundTrip(t *testing.T) {
	for _, bits := range []uint32{0x1d00ffff, 0x1c00ffff, 0x1e00ffff, 0x207fffff} {
		round := TargetToBits(BitsToTarget(bits))
		if round != bits {
			t.Errorf("round-trip bits 0x%08x -> 0x%08x", bits, round)
		}
	}
}

// Validate 小端比较：构造头，Nonce=0 时不满足，再用 Mine 挖出解并 Validate 通过。
func TestValidateAndMine(t *testing.T) {
	// 用易难度 0x207fffff（约 1/512 概率）快速挖出，避免测试过慢。
	coinbase := transaction.NewCoinbaseTx([20]byte{1, 2, 3}, params.GetBlockSubsidy(1))
	b := block.NewCandidateBlock([32]byte{}, 0x207fffff, []*transaction.Transaction{coinbase})
	// 注意：Nonce=0 有约 1/512 概率恰好满足 0x207fffff 难度，不作前置断言（避免抖动）。
	found, attempts := Mine(b, 100_000)
	if !found {
		t.Fatalf("Mine 在 100k 次内未找到解")
	}
	if attempts == 0 {
		t.Fatalf("attempts 应 > 0")
	}
	if !Validate(&b.Header) {
		t.Fatalf("Mine 挖出的解 Validate 应通过")
	}
	// 快路径与慢路径一致性：Mine 写入的 Nonce 经 Hash() 复核。
	if !HashMeetsTarget(b.Header.Hash(), BitsToTarget(b.Header.Bits)) {
		t.Fatalf("Mine 解经 Hash() 复核应满足目标")
	}
}

// MineParallel：多 worker 挖出的解 Validate 通过；结果与单线程 Mine 等价（同难度下均满足目标）。
func TestMineParallel(t *testing.T) {
	coinbase := transaction.NewCoinbaseTx([20]byte{1, 2, 3}, params.GetBlockSubsidy(1))
	b := block.NewCandidateBlock([32]byte{}, 0x207fffff, []*transaction.Transaction{coinbase})
	found, attempts := MineParallel(b, 4)
	if !found {
		t.Fatalf("MineParallel 未找到解")
	}
	if attempts == 0 {
		t.Fatalf("attempts 应 > 0")
	}
	if !Validate(&b.Header) {
		t.Fatalf("MineParallel 挖出的解 Validate 应通过")
	}
}

// MineParallel 单 worker 应与 Mine 等价（退化为单线程路径）。
func TestMineParallelSingleWorker(t *testing.T) {
	coinbase := transaction.NewCoinbaseTx([20]byte{1, 2, 3}, params.GetBlockSubsidy(1))
	b := block.NewCandidateBlock([32]byte{}, 0x207fffff, []*transaction.Transaction{coinbase})
	found, _ := MineParallel(b, 1)
	if !found || !Validate(&b.Header) {
		t.Fatalf("MineParallel(1) 应找到有效解")
	}
}

// HashMeetsTarget 小端语义：全零哈希通过任何正目标；目标 0 拒绝任何哈希。
func TestHashMeetsTargetEdge(t *testing.T) {
	var zero [32]byte
	if !HashMeetsTarget(zero, big.NewInt(1)) {
		t.Errorf("全零哈希应满足目标 1")
	}
	if HashMeetsTarget(zero, big.NewInt(0)) {
		t.Errorf("目标 0 应拒绝任何哈希")
	}
}

// AdjustBits 钳制：
// - 实际用时 = 期望 -> 难度不变；
// - 实际用时极短 -> 钳制到 1/4 期望，难度 4 倍；
// - 实际用时极长 -> 钳制到 4 倍期望，难度 1/4；
// - 实际用时极长到目标超 MaxTarget -> 返回 MaxBits。
func TestAdjustBitsClamp(t *testing.T) {
	if got := AdjustBits(0x1d00ffff, params.ExpectedTimespanSeconds); got != 0x1d00ffff {
		t.Errorf("期望用时应难度不变，got 0x%08x", got)
	}
	// 极短：钳制到 302400，目标 = MaxTarget/4 = 0x00ffff<<206，
	// 编码：nSize=28，mantissa = (0x00ffff<<206)>>200 = 0x3fffc0，故 0x1c3fffc0。
	if got := AdjustBits(0x1d00ffff, 1); got != 0x1c3fffc0 {
		t.Errorf("极短用时应钳制到 0x1c3fffc0，got 0x%08x", got)
	}
	// 极长：钳制到 4838400，目标 = MaxTarget*4，超 MaxTarget -> MaxBits。
	if got := AdjustBits(0x1d00ffff, 1<<60); got != 0x1d00ffff {
		t.Errorf("极长用时应钳制到 MaxBits，got 0x%08x", got)
	}
	// 中间难度：当前 0x1c00ffff（比创世难 256 倍），实际用时 = 期望/4 -> 目标 /4 = 0x00ffff<<198，
	// 编码：nSize=27，mantissa = (0x00ffff<<198)>>192 = 0x3fffc0，故 0x1b3fffc0。
	if got := AdjustBits(0x1c00ffff, params.ExpectedTimespanSeconds/4); got != 0x1b3fffc0 {
		t.Errorf("中间难度 1/4 用时应得 0x1b3fffc0，got 0x%08x", got)
	}
}
