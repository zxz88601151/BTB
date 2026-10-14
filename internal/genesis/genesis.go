// Package genesis 定义混沌（HUNDUN）创世块的冻结常量与硬编码校验。
//
// 冻结依据：创世块设计（已冻结，2026-10-14）
//   - 报文（54 字节 ASCII）：HUNDUN 2026-10-14: Nvidia to invest $2B more in Europe
//   - 归属 PubKeyHash：39e4b3cd8ef0430956ec4435b76a99abd8745284（创始人地址，私钥绝不进代码/聊天）
//   - 时间戳：真实挖矿时间；Bits = 0x1d00ffff；Version = 1；PrevHash 全零；输出 50 HUNDUN。
//
// 本包只定义创世块，不挖矿。Timestamp / Nonce / Hash / TxID 为挖矿输出，
// 已于 2026-10-14 挖出并回填为常量。
// GenesisBlock() 会逐项校验常量与重算结果一致，不一致则拒绝启动。
package genesis

import (
	"encoding/hex"
	"errors"
	"fmt"

	"hundun/internal/block"
	"hundun/internal/params"
	"hundun/internal/transaction"
)

// 冻结的创世报文与归属。
const (
	// Message 创世报文，精确 54 字节 ASCII，冻结值。
	Message = "HUNDUN 2026-10-14: Nvidia to invest $2B more in Europe"

	// PubKeyHashHex 创世地址 PubKeyHash（40 hex = 20 字节）。
	PubKeyHashHex = "39e4b3cd8ef0430956ec4435b76a99abd8745284"

	// Version 创世块 Version。
	Version = 1
)

// 挖矿输出（2026-10-14 挖出，已回填为常量；独立 Python 复算验证 TxID / 哈希 / PoW 均一致）。
// Timestamp = 2026-10-14T09:45:42Z（UTC），挖矿开始时当前 Unix 秒；总尝试 1,423,550,769 次，耗时 1939.4s。
var (
	// Timestamp 创世块时间戳（真实挖矿时间的 Unix 秒）。
	Timestamp uint32 = 1791971142

	// Nonce 创世块 Nonce（挖矿输出）。
	Nonce uint32 = 423499407

	// Hash 创世块哈希（SHA256d(80 字节头)）。
	Hash = mustDecodeHash("2debb787685ceee2b8e41cf3aab3cf4332976e9bea00b0b3600c32e600000000")

	// TxID 创世 Coinbase 交易 ID。
	TxID = mustDecodeHash("bb9b3ff2619a25ebe8663a3181fc302932219e5818edebf9f3383f91a3e88f0b")
)

func mustDecodeHash(s string) [32]byte {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		panic("创世哈希常量解析失败")
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// ErrGenesisNotMined 创世块尚未挖出/回填。
var ErrGenesisNotMined = errors.New("创世块尚未挖出回填：Timestamp/Nonce/Hash/TxID 仍为零值，请先挖矿回填")

// PubKeyHash 解析创世地址 PubKeyHash。
func PubKeyHash() ([20]byte, error) {
	var out [20]byte
	b, err := hex.DecodeString(PubKeyHashHex)
	if err != nil {
		return out, err
	}
	if len(b) != 20 {
		return out, fmt.Errorf("创世 PubKeyHash 长度须为 20 字节，实得 %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// CoinbaseTx 构造创世 Coinbase 交易（冻结值）。
// 输出 50 HUNDUN，输入附带数据为创世报文（计入 TxID，见 transaction 包注释）。
func CoinbaseTx() (*transaction.Transaction, error) {
	pkh, err := PubKeyHash()
	if err != nil {
		return nil, err
	}
	return transaction.NewCoinbaseTxWithData(pkh, params.GetBlockSubsidy(0), []byte(Message)), nil
}

// CandidateBlock 构造给定时间戳的创世候选块（Nonce = 0，待挖矿）。
// 供一次性挖矿脚本使用；节点启动不用本函数，用 GenesisBlock()。
func CandidateBlock(timestamp uint32) (*block.Block, error) {
	coinbase, err := CoinbaseTx()
	if err != nil {
		return nil, err
	}
	b := &block.Block{
		Header: block.Header{
			Version:       Version,
			PrevBlockHash: [32]byte{},
			Timestamp:     timestamp,
			Bits:          params.GenesisBits,
			Nonce:         0,
		},
		Transactions: []*transaction.Transaction{coinbase},
	}
	b.Header.MerkleRoot = block.ComputeMerkleRoot(b.Transactions)
	return b, nil
}

// GenesisBlock 返回硬编码的创世块（回填后）。
// 回填前（Timestamp/Nonce/Hash 仍为零值）直接返回 ErrGenesisNotMined，拒绝启动。
// 回填后逐项校验：报文、归属、金额、Merkle 根、Bits、PoW、哈希与 TxID 均须与常量一致。
func GenesisBlock() (*block.Block, error) {
	if Timestamp == 0 || Hash == ([32]byte{}) || TxID == ([32]byte{}) {
		return nil, ErrGenesisNotMined
	}
	coinbase, err := CoinbaseTx()
	if err != nil {
		return nil, err
	}
	if coinbase.Hash() != TxID {
		return nil, fmt.Errorf("创世 Coinbase TxID 与常量不符")
	}
	b := &block.Block{
		Header: block.Header{
			Version:       Version,
			PrevBlockHash: [32]byte{},
			MerkleRoot:    TxID, // 仅 1 笔交易，Merkle 根 = TxID
			Timestamp:     Timestamp,
			Bits:          params.GenesisBits,
			Nonce:         Nonce,
		},
		Transactions: []*transaction.Transaction{coinbase},
	}
	if b.Header.Hash() != Hash {
		return nil, fmt.Errorf("创世块哈希与常量不符")
	}
	if b.Header.MerkleRoot != block.ComputeMerkleRoot(b.Transactions) {
		return nil, fmt.Errorf("创世块 Merkle 根与交易不符")
	}
	return b, nil
}
