// secp256k1 地址与签名：比特币同款曲线 + RIPEMD160 + Base58Check。
//
// 地址格式（沿 BTC 主网版）：Base58Check(0x00 || RIPEMD160(SHA256(压缩公钥)))，
// 其中 0x00 为版本字节，校验和为 DoubleSHA256(版本字节 || 公钥哈希) 的前 4 字节。
// 签名格式固定为 64 字节 r||s 拼接（r、s 各 32 字节大端补零），与 P-256 签名格式一致；
// 不接受 DER 格式签名（Verify 收到非 64 字节 secp256k1 签名时返回错误）。
// 签名算法用 decred secp256k1/ecdsa 的确定性签名（RFC 6979 + 低 S，符合 BIP 62），
// 再经 DER 解析提取 r、s 转为 64 字节 r||s；验签用标准库 ecdsa.Verify（曲线为 S256）。
package wallet

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/ripemd160"
)

// Base58 字母表（比特币版，已排除 0、O、I、l，避免肉眼混淆）。
const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// Base58CheckVersion 为 Base58Check 地址的版本字节：0x00，沿 BTC 主网版，地址以 '1' 开头。
const Base58CheckVersion byte = 0x00

// NewSecp256k1Wallet 生成一个新的 secp256k1 密钥对（新地址路径）。
// 公钥为 33 字节压缩格式。
func NewSecp256k1Wallet() (*Wallet, error) {
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, err
	}
	return &Wallet{
		SecpPrivateKey: priv,
		PublicKey:      priv.PubKey().SerializeCompressed(),
		Curve:          CurveSecp256k1,
	}, nil
}

// hash160 计算 RIPEMD160(SHA256(data))，即比特币地址的公钥哈希核心。
func hash160(data []byte) [20]byte {
	sha := sha256.Sum256(data)
	h := ripemd160.New()
	_, _ = h.Write(sha[:])
	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out
}

// PubKeyHashSecp256k1 计算 secp256k1 公钥的公钥哈希：RIPEMD160(SHA256(pubkey))，20 字节。
// 入参应为 33 字节压缩公钥（本包 NewSecp256k1Wallet / HD 派生均存压缩格式）；
// 若传入 65 字节未压缩公钥，本函数会先压缩后再哈希，保证两种形式对应同一地址。
func PubKeyHashSecp256k1(pubKey []byte) [20]byte {
	if len(pubKey) == 65 && pubKey[0] == 0x04 {
		if parsed, err := btcec.ParsePubKey(pubKey); err == nil {
			return hash160(parsed.SerializeCompressed())
		}
	}
	return hash160(pubKey)
}

// AddressSecp256k1 返回 secp256k1 公钥的 Base58Check 地址（版本字节 0x00，以 '1' 开头）。
func AddressSecp256k1(pubKey []byte) string {
	h := PubKeyHashSecp256k1(pubKey)
	return Base58CheckEncode(Base58CheckVersion, h)
}

// Base58Encode 将字节编码为 Base58 字符串（自己实现，不另引依赖）。
// 前导零字节按每字节一个 '1' 保留。
func Base58Encode(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	// 数前导零字节。
	zeros := 0
	for zeros < len(data) && data[zeros] == 0 {
		zeros++
	}
	n := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)
	var encoded []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		encoded = append(encoded, base58Alphabet[mod.Int64()])
	}
	// 倒序 + 前导 '1'。
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	for i := 0; i < zeros; i++ {
		encoded = append([]byte{'1'}, encoded...)
	}
	return string(encoded)
}

// Base58Decode 将 Base58 字符串解码为字节（Base58Encode 的逆操作）。
// 含非法字符时返回错误；前导 '1' 按每字符一个零字节还原。
func Base58Decode(s string) ([]byte, error) {
	if s == "" {
		return []byte{}, nil
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	n := new(big.Int)
	base := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		idx := -1
		for j := 0; j < len(base58Alphabet); j++ {
			if base58Alphabet[j] == s[i] {
				idx = j
				break
			}
		}
		if idx < 0 {
			return nil, errors.New("Base58 解码失败：含非法字符")
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}
	decoded := n.Bytes()
	out := make([]byte, zeros+len(decoded))
	copy(out[zeros:], decoded)
	return out, nil
}

// Base58CheckEncode 编码 Base58Check：version || hash || checksum[0:4]，
// checksum = DoubleSHA256(version || hash) 的前 4 字节。
func Base58CheckEncode(version byte, hash [20]byte) string {
	payload := make([]byte, 0, 25)
	payload = append(payload, version)
	payload = append(payload, hash[:]...)
	first := sha256.Sum256(payload)
	second := sha256.Sum256(first[:])
	payload = append(payload, second[:4]...)
	return Base58Encode(payload)
}

// DecodeBase58Check 解码 Base58Check 地址，返回（版本字节，20 字节公钥哈希）。
// 校验和错误、长度错误、版本字节错误均拒绝（返回错误），绝不返回脏数据。
func DecodeBase58Check(addr string) (byte, [20]byte, error) {
	var hash [20]byte
	decoded, err := Base58Decode(addr)
	if err != nil {
		return 0, hash, err
	}
	if len(decoded) != 25 {
		return 0, hash, errors.New("Base58Check 解码失败：长度须为 25 字节")
	}
	version := decoded[0]
	first := sha256.Sum256(decoded[:21])
	second := sha256.Sum256(first[:])
	if decoded[21] != second[0] || decoded[22] != second[1] || decoded[23] != second[2] || decoded[24] != second[3] {
		return 0, hash, errors.New("Base58Check 校验和错误：地址可能输错或被篡改")
	}
	copy(hash[:], decoded[1:21])
	return version, hash, nil
}

// derSignature 为 DER 编码签名的 ASN.1 结构（仅用于从确定性签名的 DER 输出中提取 r、s）。
type derSignature struct {
	R, S *big.Int
}

// signSecp256k1 对消息哈希做 secp256k1 确定性签名，返回固定 64 字节 r||s。
func signSecp256k1(priv *btcec.PrivateKey, msgHash [32]byte) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("钱包无 secp256k1 私钥，无法签名")
	}
	sig := secpECDSA.Sign(priv, msgHash[:])
	var der derSignature
	if _, err := asn1.Unmarshal(sig.Serialize(), &der); err != nil {
		return nil, err
	}
	if der.R == nil || der.S == nil {
		return nil, errors.New("secp256k1 签名 DER 解析失败")
	}
	return concatRS(der.R, der.S), nil
}

// verifySecp256k1 验 secp256k1 签名：公钥须为 33 字节压缩格式，签名须为 64 字节 r||s。
func verifySecp256k1(pubKeyBytes []byte, msgHash [32]byte, sig []byte) (bool, error) {
	if len(sig) != 64 {
		return false, errors.New("secp256k1 签名须为 64 字节 r||s 拼接格式")
	}
	pub, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return false, errors.New("非法 secp256k1 公钥字节，无法解析")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub.ToECDSA(), msgHash[:], r, s), nil
}
