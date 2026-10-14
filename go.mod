module p2pchain

go 1.22

// 骨架阶段刻意只用标准库（crypto/ecdsa + elliptic.P256），方便零依赖直接编译运行。
// 后续如果要与比特币生态兼容（相同的 secp256k1 曲线、Base58Check 地址格式等），
// 建议引入 github.com/btcsuite/btcd/btcec/v2 和 github.com/btcsuite/btcutil/base58。
