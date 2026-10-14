// Package block 定义区块链中最基本的数据单元：区块。
//
// 一个区块由「区块头」和「交易列表」组成：
//   - 区块头包含链接前一区块的哈希、Merkle 根、时间戳、难度目标和 Nonce
//   - 交易列表是本区块打包的所有交易
//
// 区块头单独定义是为了方便挖矿时只对区块头做哈希运算（不必每次都对全部交易重新哈希）。
package block

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"p2pchain/internal/transaction"
)

// Header 区块头，挖矿时反复哈希的就是这部分内容序列化后的字节。
type Header struct {
	Version       uint32 // 协议版本号，用于未来升级共识规则
	PrevBlockHash [32]byte // 前一个区块头的哈希，构成链式结构
	MerkleRoot    [32]byte // 本区块所有交易的 Merkle 根
	Timestamp     int64    // 出块时间（Unix 秒）
	Bits          uint32   // 压缩格式表示的难度目标（参考比特币的 nBits 编码）
	Nonce         uint64   // 矿工在挖矿时不断调整的随机数
}

// Block 完整区块 = 区块头 + 交易列表
type Block struct {
	Header       Header
	Transactions []*transaction.Transaction
}

// NewCandidateBlock 生成一个待挖矿的候选区块（Nonce 尚未求解，Timestamp 为当前时间）。
// prevHash 为父区块头哈希，bits 为当前难度目标。
func NewCandidateBlock(prevHash [32]byte, bits uint32, txs []*transaction.Transaction) *Block {
	b := &Block{
		Header: Header{
			Version:       1,
			PrevBlockHash: prevHash,
			Timestamp:     time.Now().Unix(),
			Bits:          bits,
			Nonce:         0,
		},
		Transactions: txs,
	}
	b.Header.MerkleRoot = ComputeMerkleRoot(txs)
	return b
}

// SerializeHeader 将区块头序列化为定长字节数组，供哈希函数使用。
// 字段顺序和长度必须固定，否则不同节点计算出的哈希会不一致。
func (h *Header) SerializeHeader() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, h.Version)
	buf.Write(h.PrevBlockHash[:])
	buf.Write(h.MerkleRoot[:])
	_ = binary.Write(buf, binary.LittleEndian, h.Timestamp)
	_ = binary.Write(buf, binary.LittleEndian, h.Bits)
	_ = binary.Write(buf, binary.LittleEndian, h.Nonce)
	return buf.Bytes()
}

// Hash 计算区块头的双 SHA-256 哈希（沿用比特币的做法，可按需换成单次哈希或其它算法）。
func (h *Header) Hash() [32]byte {
	first := sha256.Sum256(h.SerializeHeader())
	second := sha256.Sum256(first[:])
	return second
}

// HashHex 返回十六进制字符串形式的哈希，便于日志打印和调试。
func (h *Header) HashHex() string {
	hash := h.Hash()
	return hex.EncodeToString(hash[:])
}

// ComputeMerkleRoot 计算交易列表的 Merkle 根。
// 若交易数为奇数，最后一笔交易会与自身拼接（比特币的经典处理方式）。
func ComputeMerkleRoot(txs []*transaction.Transaction) [32]byte {
	if len(txs) == 0 {
		return sha256.Sum256(nil)
	}

	layer := make([][32]byte, 0, len(txs))
	for _, tx := range txs {
		layer = append(layer, tx.Hash())
	}

	for len(layer) > 1 {
		if len(layer)%2 == 1 {
			layer = append(layer, layer[len(layer)-1])
		}
		next := make([][32]byte, 0, len(layer)/2)
		for i := 0; i < len(layer); i += 2 {
			combined := append(layer[i][:], layer[i+1][:]...)
			next = append(next, sha256.Sum256(combined))
		}
		layer = next
	}
	return layer[0]
}
