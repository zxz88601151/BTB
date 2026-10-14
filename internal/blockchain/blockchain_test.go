package blockchain

import (
	"testing"
	"time"

	"hundun/internal/block"
	"hundun/internal/params"
	"hundun/internal/pow"
	"hundun/internal/transaction"
)

// 构造一个易难度（0x207fffff）的有效链：创世块 + 1 个后续块。
func mustChain(t *testing.T) *Blockchain {
	t.Helper()
	genesisCoinbase := transaction.NewCoinbaseTx([20]byte{1}, params.GetBlockSubsidy(0))
	genesis := block.NewCandidateBlock([32]byte{}, 0x207fffff, []*transaction.Transaction{genesisCoinbase})
	genesis.Header.Timestamp = uint32(time.Now().Unix())
	if found, _ := pow.Mine(genesis, 100_000); !found {
		t.Fatalf("创世块挖矿失败")
	}
	bc := NewBlockchainWithGenesis(genesis)
	return bc
}

func nextBlock(t *testing.T, bc *Blockchain, coinbaseValue uint64) *block.Block {
	t.Helper()
	tip, _ := bc.Tip()
	coinbase := transaction.NewCoinbaseTx([20]byte{2}, coinbaseValue)
	b := block.NewCandidateBlock(tip.Header.Hash(), bc.CurrentBits(), []*transaction.Transaction{coinbase})
	b.Header.Timestamp = tip.Header.Timestamp + 600
	if found, _ := pow.Mine(b, 100_000); !found {
		t.Fatalf("后续块挖矿失败")
	}
	return b
}

// 超额 Coinbase（> 补贴 + 费）拒绝；等于补贴通过。
func TestValidateBlockCoinbaseCap(t *testing.T) {
	bc := mustChain(t)
	over := nextBlock(t, bc, params.GetBlockSubsidy(1)+1)
	if err := bc.ValidateBlock(over); err == nil {
		t.Errorf("超额 Coinbase 应被拒绝")
	}
	ok := nextBlock(t, bc, params.GetBlockSubsidy(1))
	if err := bc.ValidateBlock(ok); err != nil {
		t.Errorf("等于补贴的 Coinbase 应通过，err=%v", err)
	}
}

// 时间戳：<= 前 11 块中位数拒绝；> 网络时间 + 7200 拒绝。
func TestValidateBlockTimestamp(t *testing.T) {
	bc := mustChain(t)
	tip, _ := bc.Tip()

	medianBlock := nextBlock(t, bc, params.GetBlockSubsidy(1))
	medianBlock.Header.Timestamp = bc.MedianTimestamp() // <= 中位数
	// 重新挖矿（Timestamp 改了，PoW 失效）
	if found, _ := pow.Mine(medianBlock, 100_000); !found {
		t.Fatalf("时间戳测试块挖矿失败")
	}
	if err := bc.ValidateBlock(medianBlock); err == nil {
		t.Errorf("时间戳 <= 中位数应被拒绝")
	}

	futureBlock := nextBlock(t, bc, params.GetBlockSubsidy(1))
	futureBlock.Header.Timestamp = uint32(time.Now().Unix()) + 7200 + 3600
	if found, _ := pow.Mine(futureBlock, 100_000); !found {
		t.Fatalf("未来时间戳测试块挖矿失败")
	}
	if err := bc.ValidateBlock(futureBlock); err == nil {
		t.Errorf("时间戳 > 网络时间+7200 应被拒绝")
	}
	_ = tip
}

// 块尺寸 / 权重：塞入超大交易使 Size > 1M 时拒绝。
// 注意：ValidateBlock 先验 PoW，本测试用易难度挖出后再验尺寸。
func TestValidateBlockTooLarge(t *testing.T) {
	bc := mustChain(t)
	tip, _ := bc.Tip()
	// 1,100,000 字节报文的 Coinbase，使块尺寸 > 1M。
	bigData := make([]byte, 1_100_000)
	coinbase := transaction.NewCoinbaseTxWithData([20]byte{2}, params.GetBlockSubsidy(1), bigData)
	b := block.NewCandidateBlock(tip.Header.Hash(), bc.CurrentBits(), []*transaction.Transaction{coinbase})
	b.Header.Timestamp = tip.Header.Timestamp + 600
	if found, _ := pow.Mine(b, 1_000_000); !found {
		t.Skip("超大块挖矿未在 1M 次内找到解（概率事件），跳过尺寸断言")
	}
	if err := bc.ValidateBlock(b); err != ErrBlockTooLarge {
		t.Errorf("超大块应被 ErrBlockTooLarge 拒绝，err=%v", err)
	}
}

// CurrentBits：非调整高度沿用链尾难度；height 0 返回 GenesisBits（空链语义）。
func TestCurrentBitsNonAdjustment(t *testing.T) {
	bc := mustChain(t)
	if got := bc.CurrentBits(); got != 0x207fffff {
		t.Errorf("非调整高度应沿用链尾难度，got 0x%08x", got)
	}
}

// IsCoinbaseMature：100 块成熟边界。
func TestIsCoinbaseMature(t *testing.T) {
	if IsCoinbaseMature(0, 99) {
		t.Errorf("99 块应未成熟")
	}
	if !IsCoinbaseMature(0, 100) {
		t.Errorf("100 块应成熟")
	}
}
