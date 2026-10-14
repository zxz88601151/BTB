// 口令加密钱包文件：Argon2id 派生密钥 + AES-256-GCM 加密。
//
// 格式（自描述、无魔数头）：salt(16) || nonce(12) || ciphertext。
// ciphertext 为 AES-256-GCM 加密后的 JSON 明文；GCM 自带认证标签，
// 口令错误或密文被篡改时 Decrypt 直接失败（返回错误，绝不返回脏明文）。
// JSON 明文结构：{version, curve, private_key(32 字节标量), public_key, mnemonic?}。
// 只存私钥标量 + 可选助记词，不存种子原文；助记词存在时可据此完整恢复钱包。
//
// 密钥派生参数（Argon2id，OWASP 推荐）：t=3 轮，m=64 MiB，p=4 并行度，
// 输出 32 字节作 AES-256 密钥。salt 16 字节、nonce 12 字节均为密码学随机。
//
// 兼容：现有未加密钱包仍可读（不强制迁移）；新钱包默认走加密路径
// （提供 EncryptWalletFile / DecryptWalletFile 函数即可，不改 cmd/node 行为）。
// 迁移：EncryptLegacyWallet 把 v1 明文（从未加密过的）钱包转为加密格式。
package wallet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2id 参数（OWASP 推荐，见文件头）。
const (
	// Argon2Time 迭代轮数。
	Argon2Time = 3
	// Argon2Memory 内存用量，单位 KiB：64 * 1024 = 64 MiB。
	Argon2Memory = 64 * 1024
	// Argon2Threads 并行度。
	Argon2Threads = 4
	// Argon2KeyLen 派生密钥长度（字节）：32 = AES-256。
	Argon2KeyLen = 32
	// encryptSaltLen salt 长度（字节）。
	encryptSaltLen = 16
	// encryptNonceLen GCM nonce 长度（字节）。
	encryptNonceLen = 12
)

// 加密载荷版本：v1 = 由 EncryptLegacyWallet 迁移的旧钱包；v2 = EncryptWalletFile 新钱包。
// Decrypt 接受 v1 与 v2；版本仅用于追溯来源，不影响解密流程。
const (
	encryptedWalletVersionLegacy = 1
	encryptedWalletVersionNew    = 2
)

// encryptedWalletPayload 为加密前的 JSON 明文结构。
type encryptedWalletPayload struct {
	Version    int    `json:"version"`
	Curve      string `json:"curve"`
	PrivateKey []byte `json:"private_key"` // 32 字节私钥标量
	PublicKey  []byte `json:"public_key"`
	Mnemonic   string `json:"mnemonic,omitempty"`
}

// deriveKey 由口令 + salt 派生 AES-256 密钥（Argon2id）。
func deriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)
}

// encryptPayload 加密 JSON 载荷，输出 salt || nonce || ciphertext。
func encryptPayload(payload *encryptedWalletPayload, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("口令为空，拒绝加密：空口令钱包等同明文")
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, encryptSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, encryptNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(deriveKey(password, salt))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	out := make([]byte, 0, encryptSaltLen+encryptNonceLen+len(ciphertext))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

// encryptWallet 构造载荷并加密；version 区分新钱包（v2）与迁移旧钱包（v1）。
func encryptWallet(w *Wallet, password string, version int) ([]byte, error) {
	if w == nil {
		return nil, errors.New("钱包为空，无法加密")
	}
	scalar, err := w.privateScalar()
	if err != nil {
		return nil, err
	}
	if w.Curve != CurveP256 && w.Curve != CurveSecp256k1 {
		return nil, fmt.Errorf("未知曲线 %q，无法加密", w.Curve)
	}
	return encryptPayload(&encryptedWalletPayload{
		Version:    version,
		Curve:      w.Curve,
		PrivateKey: scalar,
		PublicKey:  append([]byte(nil), w.PublicKey...),
		Mnemonic:   w.Mnemonic,
	}, password)
}

// EncryptWalletFile 加密新钱包：口令 + Argon2id + AES-256-GCM，输出 salt||nonce||ciphertext。
func EncryptWalletFile(w *Wallet, password string) ([]byte, error) {
	return encryptWallet(w, password, encryptedWalletVersionNew)
}

// EncryptLegacyWallet 迁移函数：把 v1 明文（从未加密过的）钱包转为加密格式。
// 与 EncryptWalletFile 相同密文格式，仅载荷版本标为 v1 以追溯来源；
// 解密时 v1/v2 一视同仁。
func EncryptLegacyWallet(w *Wallet, password string) ([]byte, error) {
	return encryptWallet(w, password, encryptedWalletVersionLegacy)
}

// DecryptWalletFile 解密钱包文件，返回恢复出的钱包（含 Mnemonic，如加密时携带）。
// 口令错误、密文被篡改、格式错误均返回错误，绝不返回半解密的钱包。
func DecryptWalletFile(data []byte, password string) (*Wallet, error) {
	if password == "" {
		return nil, errors.New("口令为空，拒绝解密")
	}
	if len(data) < encryptSaltLen+encryptNonceLen {
		return nil, errors.New("加密钱包文件过短，格式错误")
	}
	salt := data[:encryptSaltLen]
	nonce := data[encryptSaltLen : encryptSaltLen+encryptNonceLen]
	ciphertext := data[encryptSaltLen+encryptNonceLen:]

	block, err := aes.NewCipher(deriveKey(password, salt))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("解密失败：口令错误或密文被篡改")
	}
	var payload encryptedWalletPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		return nil, errors.New("解密后载荷不是合法钱包 JSON")
	}
	if payload.Version != encryptedWalletVersionLegacy && payload.Version != encryptedWalletVersionNew {
		return nil, fmt.Errorf("未知加密钱包版本 %d", payload.Version)
	}
	var w *Wallet
	switch payload.Curve {
	case CurveP256:
		w, err = walletFromP256Scalar(payload.PrivateKey)
	case CurveSecp256k1:
		w, err = walletFromSecpScalar(payload.PrivateKey)
	default:
		return nil, fmt.Errorf("未知曲线 %q，无法恢复钱包", payload.Curve)
	}
	if err != nil {
		return nil, fmt.Errorf("恢复钱包私钥失败：%w", err)
	}
	// 完整性校验：由标量重算的公钥须与载荷内公钥一致，否则密文载荷不一致。
	if string(w.PublicKey) != string(payload.PublicKey) {
		return nil, errors.New("解密后公钥与载荷不一致，钱包文件已损坏")
	}
	w.Mnemonic = payload.Mnemonic
	return w, nil
}
