package sync

import (
	"fmt"
	"testing"
	"time"

	"hundun/internal/block"
	"hundun/internal/blockchain"
	"hundun/internal/params"
	"hundun/internal/pow"
	"hundun/internal/transaction"
)

// fakeFetcher 用内存块列表实现 Fetcher。
type fakeFetcher struct {
	blocks []*block.Block // 按高度顺序（不含创世）
	height int
	failAt int // GetBlocks 在 fromHeight==failAt 时失败（-1 表示不失败）
}

func (f *fakeFetcher) PeerHeight(peer string) (int, error) { return f.height, nil }
func (f *fakeFetcher) GetBlocks(peer string, fromHeight, count int) ([]*block.Block, error) {
	if fromHeight == f.failAt {
		return nil, fmt.Errorf("模拟网络失败")
	}
	// 每批最多返回 2 块，模拟多批次同步（Syncer 的 BatchSize 为 100，Fetcher 可少返回）。
	if count > 2 {
		count = 2
	}
	var out []*block.Block
	for h := fromHeight; h <= f.height && len(out) < count; h++ {
		out = append(out, f.blocks[h-1])
	}
	return out, nil
}

func testChain(t *testing.T, n int) (*blockchain.Blockchain, []*block.Block) {
	t.Helper()
	genesis := block.NewCandidateBlock([32]byte{}, 0x207fffff,
		[]*transaction.Transaction{transaction.NewCoinbaseTx([20]byte{1}, params.GetBlockSubsidy(0))})
	genesis.Header.Timestamp = uint32(time.Now().Unix()) - 10000
	if found, _ := pow.Mine(genesis, 100_000); !found {
		t.Fatalf("创世挖矿失败")
	}
	bc := blockchain.NewBlockchainWithGenesis(genesis)
	var blocks []*block.Block
	tip := genesis
	for h := 1; h <= n; h++ {
		cb := transaction.NewCoinbaseTxWithData([20]byte{2}, params.GetBlockSubsidy(uint64(h)), []byte(fmt.Sprintf("sync-%d", h)))
		b := block.NewCandidateBlock(tip.Header.Hash(), 0x207fffff, []*transaction.Transaction{cb})
		b.Header.Timestamp = tip.Header.Timestamp + 600
		if found, _ := pow.Mine(b, 100_000); !found {
			t.Fatalf("高度 %d 挖矿失败", h)
		}
		blocks = append(blocks, b)
		tip = b
	}
	return bc, blocks
}

func TestSyncFromPeerAndResume(t *testing.T) {
	bc, blocks := testChain(t, 5)
	sy := New(bc)
	fetcher := &fakeFetcher{blocks: blocks, height: 5, failAt: -1}
	n, err := sy.SyncFromPeer("peer1", fetcher)
	if err != nil {
		t.Fatalf("同步失败: %v", err)
	}
	if n != 5 || bc.Height() != 5 {
		t.Errorf("同步后高度 = %d（同步 %d 块），want 5", bc.Height(), n)
	}
	// 已同步时再次调用：不重复同步。
	n2, err := sy.SyncFromPeer("peer1", fetcher)
	if err != nil || n2 != 0 {
		t.Errorf("已同步时应返回 0，got n=%d err=%v", n2, err)
	}
}

func TestSyncResumeAfterFailure(t *testing.T) {
	bc, blocks := testChain(t, 5)
	sy := New(bc)
	// 第一次在 from=3 处失败（已同步 2 块），第二次从高度 2 续传。
	fetcher := &fakeFetcher{blocks: blocks, height: 5, failAt: 3}
	_, err := sy.SyncFromPeer("peer1", fetcher)
	if err == nil {
		t.Fatalf("应返回模拟失败")
	}
	if bc.Height() != 2 {
		t.Fatalf("失败后高度应为 2（断点），got %d", bc.Height())
	}
	fetcher.failAt = -1
	n, err := sy.SyncFromPeer("peer1", fetcher)
	if err != nil {
		t.Fatalf("续传失败: %v", err)
	}
	if n != 3 || bc.Height() != 5 {
		t.Errorf("续传后高度 = %d（同步 %d 块），want 5/3", bc.Height(), n)
	}
}

func TestNeedsSync(t *testing.T) {
	bc, _ := testChain(t, 0)
	sy := New(bc)
	if sy.NeedsSync() {
		t.Errorf("无对端高度时不应需要同步")
	}
	sy.NotePeerHeight(3)
	if !sy.NeedsSync() {
		t.Errorf("对端更高时应需要同步")
	}
}
