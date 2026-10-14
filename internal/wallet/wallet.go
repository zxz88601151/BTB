// Package wallet 实现最基础的密钥管理：生成密钥对、派生地址、对交易签名与验签。
//
// 骨架阶段使用标准库的 P-256 椭圆曲线（crypto/elliptic），实现简单、无需外部依赖。
// 真实的比特币系列项目使用 secp256k1 曲线，如果未来要和比特币生态兼容，
// 需要换成 github.com/btcsuite/btcd/btcec/v2。
//
// 地址生成也做了简化：真实比特币是 RIPEMD160(SHA256(pubkey)) 再做 Base58Check 编码，
// 这里先用 SHA256 截断代替 RIPEMD160（标准库没有内置 RIPEMD160），
// 并保留 TODO 说明如何升级为完全兼容版本。
package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// Wallet 持有一对密钥：私钥用于签名（必须保密），公钥用于生成地址、供他人验签。
type Wallet struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  []byte // 未压缩格式公钥字节：0x04 || X || Y
}

// NewWallet 生成一个新的密钥对。
func NewWallet() (*Wallet, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	return &Wallet{PrivateKey: priv, PublicKey: pub}, nil
}

// PubKeyHash 计算公钥哈希（简化版地址核心内容）。
// TODO: 生产实现请替换为 RIPEMD160(SHA256(pubkey))，并加上版本号 + 校验和做 Base58Check 编码，
// 这样地址就能像比特币一样直接肉眼分辨、且能检测出输入错误。
func (w *Wallet) PubKeyHash() [20]byte {
	sum := sha256.Sum256(w.PublicKey)
	var hash [20]byte
	copy(hash[:], sum[:20])
	return hash
}

// Sign 对任意消息哈希做 ECDSA 签名，返回 (r, s) 拼接后的字节。
func (w *Wallet) Sign(msgHash [32]byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, w.PrivateKey, msgHash[:])
	if err != nil {
		return nil, err
	}
	sig := append(r.Bytes(), s.Bytes()...)
	return sig, nil
}

// Verify 用给定公钥字节验证签名是否有效。
func Verify(pubKeyBytes []byte, msgHash [32]byte, sig []byte) (bool, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
	if x == nil {
		return false, errors.New("非法公钥字节，无法解析曲线坐标")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	return ecdsa.Verify(pub, msgHash[:], r, s), nil
}
