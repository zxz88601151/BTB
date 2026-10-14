// 钱包文件存取：明文 JSON 与加密格式的落盘/加载。
//
// 文件格式：
//   - 未加密：JSON {version:0, curve, private_key(32 字节标量), public_key, mnemonic?}，文件权限须 0600。
//   - 加密：EncryptWalletFile 的输出（salt||nonce||ciphertext），文件权限须 0600。
//
// 加载时按 password 是否为空 + 内容能否 JSON 解析自动区分：password 非空时
// 按加密格式解密；password 为空时按明文 JSON 解析；密文文件配空口令时返回
// 明确错误（要求提供口令文件），绝不把密文当明文返回。
//
// 私钥绝不打日志；本文件只负责读写，不持有口令（口令由调用方从
// --wallet-password-file 读取后传入）。
package wallet

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
)

const walletFileMode = 0o600

// plainWalletFile 明文钱包文件结构（与加密载荷同字段，version=0 表示明文）。
type plainWalletFile struct {
	Version    int    `json:"version"`
	Curve      string `json:"curve"`
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
	Mnemonic   string `json:"mnemonic,omitempty"`
}

// SaveWalletFile 保存钱包到 path：password 非空时加密保存，否则明文 JSON 保存。
// 文件以 0600 权限写入（新建与覆盖均强制 0600）。
func SaveWalletFile(path string, w *Wallet, password string) error {
	if w == nil {
		return errors.New("钱包为空，无法保存")
	}
	var data []byte
	var err error
	if password != "" {
		data, err = EncryptWalletFile(w, password)
		if err != nil {
			return err
		}
	} else {
		scalar, err := w.privateScalar()
		if err != nil {
			return err
		}
		data, err = json.Marshal(&plainWalletFile{
			Version:    0,
			Curve:      w.Curve,
			PrivateKey: scalar,
			PublicKey:  append([]byte(nil), w.PublicKey...),
			Mnemonic:   w.Mnemonic,
		})
		if err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, walletFileMode)
}

// LoadWalletFile 从 path 加载钱包：password 非空时按加密格式解密；
// password 为空时按明文 JSON 解析；密文文件配空口令时返回明确错误。
func LoadWalletFile(path, password string) (*Wallet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if password != "" {
		return DecryptWalletFile(data, password)
	}
	var plain plainWalletFile
	if err := json.Unmarshal(data, &plain); err != nil {
		return nil, errors.New("钱包文件不是明文 JSON 且未提供口令：请用 --wallet-password-file 提供口令文件解密")
	}
	if plain.Version != 0 {
		return nil, fmt.Errorf("未知明文钱包版本 %d", plain.Version)
	}
	var w *Wallet
	switch plain.Curve {
	case CurveP256:
		w, err = walletFromP256Scalar(plain.PrivateKey)
	case CurveSecp256k1:
		w, err = walletFromSecpScalar(plain.PrivateKey)
	default:
		return nil, fmt.Errorf("未知曲线 %q，无法加载钱包", plain.Curve)
	}
	if err != nil {
		return nil, fmt.Errorf("恢复钱包私钥失败：%w", err)
	}
	if string(w.PublicKey) != string(plain.PublicKey) {
		return nil, errors.New("钱包文件公钥与私钥不一致，已损坏")
	}
	w.Mnemonic = plain.Mnemonic
	return w, nil
}

// MigrateWalletFileToEncrypted 把 path 处的明文钱包文件迁移为加密格式
// （v1 迁移路径：读明文 → EncryptLegacyWallet → 原地覆盖为密文，0600）。
// 文件已是加密格式时返回错误，不重复加密。
func MigrateWalletFileToEncrypted(path, password string) error {
	if password == "" {
		return errors.New("口令为空，拒绝迁移")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var probe plainWalletFile
	if json.Unmarshal(data, &probe) != nil {
		return errors.New("钱包文件已是加密格式，无需迁移")
	}
	w, err := LoadWalletFile(path, "")
	if err != nil {
		return err
	}
	enc, err := EncryptLegacyWallet(w, password)
	if err != nil {
		return err
	}
	// 原地覆盖前校验：加密结果须能用同一口令解密回同一钱包。
	back, err := DecryptWalletFile(enc, password)
	if err != nil {
		return fmt.Errorf("迁移校验失败：%w", err)
	}
	if new(big.Int).SetBytes(mustScalar(back)).Cmp(new(big.Int).SetBytes(mustScalar(w))) != 0 {
		return errors.New("迁移校验失败：解密后私钥不一致")
	}
	return os.WriteFile(path, enc, walletFileMode)
}

func mustScalar(w *Wallet) []byte {
	s, err := w.privateScalar()
	if err != nil {
		return nil
	}
	return s
}
