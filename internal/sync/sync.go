// Package sync 实现全节点同步（IBD）：任务卡片 5。
//
// 流程：连接后比高度 → 落后则按高度区间批量请求缺失块（每批 100 块）→
// 按高度顺序逐块 ValidateBlock + Apply（经 blockchain.AddBlock，分叉自动走重组）→
// 失败则返回错误，调用方断开该对端、尝试下一对端。
// 断点续传：每次从本地当前高度续传，不从头来；同步完成前矿工不挖矿
// （MINING-SYNC-GATE-1 语义：落后时 WAITING_SYNC，由上层按 IsSyncing() 判断）。
//
// 本包不依赖 p2p 包：通过 Fetcher 接口取块，上层（cmd/node）用 P2P 消息实现 Fetcher。
package sync

import (
	"errors"
	"fmt"
	"sync"

	"hundun/internal/block"
	"hundun/internal/blockchain"
)

// BatchSize 每批请求的块数。
const BatchSize = 100

// Fetcher 同步取块接口（上层用 P2P 实现）。
type Fetcher interface {
	// PeerHeight 返回对端当前链高。
	PeerHeight(peer string) (int, error)
	// GetBlocks 返回从 fromHeight 开始的至多 count 个块（按高度升序）。
	GetBlocks(peer string, fromHeight, count int) ([]*block.Block, error)
}

// Syncer 同步器（持有链引用与同步状态）。
type Syncer struct {
	chain      *blockchain.Blockchain
	mu         sync.Mutex
	syncing    bool
	bestHeight int // 已知的全网最高高度（握手时更新，供挖矿门禁判断）
}

// New 返回绑定给定链的 Syncer。
func New(chain *blockchain.Blockchain) *Syncer {
	return &Syncer{chain: chain}
}

// IsSyncing 返回是否正在同步。
func (s *Syncer) IsSyncing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.syncing
}

// NotePeerHeight 记录对端高度（握手时调用），用于挖矿门禁。
func (s *Syncer) NotePeerHeight(h int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h > s.bestHeight {
		s.bestHeight = h
	}
}

// BestHeight 返回已知全网最高高度。
func (s *Syncer) BestHeight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bestHeight
}

// NeedsSync 判断是否落后（本地高度 < 已知最高高度）。
func (s *Syncer) NeedsSync() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chain.Height() < s.bestHeight
}

// SyncFromPeer 从指定对端同步到其高度。返回新同步的块数。
// 中途失败返回已同步数与错误（调用方应换对端重试；下次调用从本地高度续传）。
func (s *Syncer) SyncFromPeer(peer string, fetcher Fetcher) (int, error) {
	s.mu.Lock()
	if s.syncing {
		s.mu.Unlock()
		return 0, errors.New("已有同步在进行中")
	}
	s.syncing = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.syncing = false
		s.mu.Unlock()
	}()

	synced := 0
	for {
		localHeight := s.chain.Height()
		peerHeight, err := fetcher.PeerHeight(peer)
		if err != nil {
			return synced, fmt.Errorf("获取对端高度失败: %w", err)
		}
		if peerHeight <= localHeight {
			return synced, nil
		}
		blocks, err := fetcher.GetBlocks(peer, localHeight+1, BatchSize)
		if err != nil {
			return synced, fmt.Errorf("请求区块失败（from=%d）: %w", localHeight+1, err)
		}
		if len(blocks) == 0 {
			return synced, nil // 对端无更多块
		}
		for _, b := range blocks {
			// 按高度顺序应用；AddBlock 内含完整校验，分叉自动重组。
			if _, _, err := s.chain.AddBlockWithResult(b); err != nil {
				return synced, fmt.Errorf("应用高度 %d 的块失败: %w", localHeight+1+synced, err)
			}
			synced++
		}
	}
}
