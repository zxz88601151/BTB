// BIP-39 助记词 + BIP-32 HD 派生。
//
// BIP-39：用 github.com/tyler-smith/go-bip39（内嵌完整 2048 英文词表，不自己手写词表）。
// 助记词为 128 位熵 → 12 词；种子 = PBKDF2(助记词, "mnemonic"+passphrase, 2048 轮)，
// 由 go-bip39.NewSeedWithErrorChecking 实现（BIP-39 标准）。
// BIP-32：用 github.com/tyler-smith/go-bip32 派生私钥标量。
// 派生路径：P-256 与 secp256k1 均为 m/44'/0'/0'/0/0（同路径、不同曲线实现分开函数）。
// coin_type 0 为临时值：沿用比特币主网 coin_type 占位，待以后分配 HUNDUN 专属
// coin_type 后再迁移；迁移时旧路径钱包须保留兼容（新路径钱包与旧路径钱包地址不同，
// 迁移须由 Owner 另行拍板，不在本文件静默切换）。
// 注意：go-bip32 的标量推导按 secp256k1 阶取模；P-256 派生时本文件会额外校验
// 标量 < P-256 阶（超限概率约 2^-32，实际几乎不可能发生，超限则报错不强行取模）。
package wallet

import (
	"errors"
	"fmt"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// BIP44Path 为 HD 派生路径（BIP-44）：m/44'/0'/0'/0/0。
// 44' = BIP-44 用途；0' = coin_type（临时，见文件头注释）；0' = 账户；0 = 外部链；0 = 地址索引。
const BIP44Path = "m/44'/0'/0'/0/0"

// bip44PathIndices 为 BIP44Path 的数字表示，' 表示硬化（+ FirstHardenedChild）。
var bip44PathIndices = []uint32{
	bip32.FirstHardenedChild + 44,
	bip32.FirstHardenedChild + 0, // coin_type：临时 0，待分配 HUNDUN 专属 coin_type
	bip32.FirstHardenedChild + 0, // 账户 0
	0,                            // 外部链
	0,                            // 地址索引 0
}

// NewMnemonic 生成一组新的 12 词助记词（128 位熵）。
func NewMnemonic() (string, error) {
	entropy, err := bip39.NewEntropy(128)
	if err != nil {
		return "", err
	}
	return bip39.NewMnemonic(entropy)
}

// MnemonicToSeed 由助记词 + 可选 passphrase 派生 64 字节种子（BIP-39 标准）。
// 助记词无效时返回错误；passphrase 为空即 BIP-39 的空口令（与有口令派生出不同种子）。
func MnemonicToSeed(mnemonic, passphrase string) ([]byte, error) {
	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, passphrase)
	if err != nil {
		return nil, fmt.Errorf("助记词无效或派生失败：%w", err)
	}
	return seed, nil
}

// ValidateMnemonic 校验助记词是否合法（词表 + 校验和）。
func ValidateMnemonic(mnemonic string) bool {
	return bip39.IsMnemonicValid(mnemonic)
}

// deriveBIP32Scalar 由种子按 BIP44Path 派生 32 字节私钥标量（BIP-32 标准推导）。
func deriveBIP32Scalar(seed []byte) ([]byte, error) {
	if len(seed) == 0 {
		return nil, errors.New("BIP-32 派生失败：种子为空")
	}
	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("BIP-32 主密钥派生失败：%w", err)
	}
	for _, idx := range bip44PathIndices {
		key, err = key.NewChildKey(idx)
		if err != nil {
			return nil, fmt.Errorf("BIP-32 子密钥派生失败（路径 %s）：%w", BIP44Path, err)
		}
	}
	if !key.IsPrivate || len(key.Key) != 32 {
		return nil, errors.New("BIP-32 派生失败：未得到 32 字节私钥标量")
	}
	return append([]byte(nil), key.Key...), nil
}

// WalletFromSeed 由种子按 BIP44Path 派生钱包。
// curve = "p256" | "secp256k1"：同路径、不同曲线实现分开构造；其他取值返回错误。
func WalletFromSeed(seed []byte, curve string) (*Wallet, error) {
	scalar, err := deriveBIP32Scalar(seed)
	if err != nil {
		return nil, err
	}
	switch curve {
	case CurveP256:
		return walletFromP256Scalar(scalar)
	case CurveSecp256k1:
		return walletFromSecpScalar(scalar)
	default:
		return nil, fmt.Errorf("未知曲线 %q，须为 %q 或 %q", curve, CurveP256, CurveSecp256k1)
	}
}

// WalletFromMnemonic 由助记词 + passphrase + 曲线派生钱包（BIP-39 种子 → BIP-32 派生）。
// 返回的钱包会携带 Mnemonic 字段，便于加密备份时一并保存助记词；
// 助记词本身即全部恢复信息，须按私钥同等保密，绝不进日志。
func WalletFromMnemonic(mnemonic, passphrase, curve string) (*Wallet, error) {
	seed, err := MnemonicToSeed(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}
	w, err := WalletFromSeed(seed, curve)
	if err != nil {
		return nil, err
	}
	w.Mnemonic = mnemonic
	return w, nil
}
