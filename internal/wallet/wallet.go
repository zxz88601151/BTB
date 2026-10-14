// Package wallet 实现密钥管理：生成密钥对、派生地址、对交易签名与验签。
//
// 双曲线支持（P3）：
//   - 旧曲线 P-256（crypto/elliptic）：地址 = SHA256(pubkey) 截断 20 字节，
//     公钥为 65 字节未压缩格式（0x04 || X || Y），签名为 64 字节 r||s 拼接。
//     旧钱包、旧地址、旧验签路径全部保留有效。
//   - 新曲线 secp256k1（github.com/btcsuite/btcd/btcec/v2）：地址 =
//     RIPEMD160(SHA256(pubkey)) + Base58Check（版本字节 0x00，沿 BTC 主网版），
//     公钥为 33 字节压缩格式（0x02/0x03 || X），签名同样固定为 64 字节 r||s 拼接。
//
// 创世保护：创世 PubKeyHash 的生成曲线未知，双支持是唯一正确做法——
// 本包绝不假设创世地址属于哪条曲线，绝不改创世常量、绝不重挖创世块。
// 两种曲线都映射到 20 字节 PubKeyHash，UTXO / Mempool 无需改动即可校验两种地址。
package wallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"

	"hundun/internal/transaction"
)

// 曲线标识：Wallet.Curve 的取值，也是 WalletFromSeed / WalletFromMnemonic 的 curve 参数。
const (
	// CurveP256 旧曲线：标准库 P-256，公钥 65 字节未压缩。
	CurveP256 = "p256"
	// CurveSecp256k1 新曲线：比特币同款 secp256k1，公钥 33 字节压缩。
	CurveSecp256k1 = "secp256k1"
)

// Wallet 持有一对密钥：私钥用于签名（必须保密），公钥用于生成地址、供他人验签。
// 双曲线：P-256 钱包填充 PrivateKey；secp256k1 钱包填充 SecpPrivateKey；
// 两者必居其一。PublicKey 按曲线存放：P-256 为 65 字节未压缩，secp256k1 为 33 字节压缩。
// Mnemonic 仅当钱包由助记词派生时填充（WalletFromMnemonic），用于加密备份时一并保存。
type Wallet struct {
	PrivateKey     *ecdsa.PrivateKey // P-256 私钥；secp256k1 钱包为 nil
	SecpPrivateKey *btcec.PrivateKey // secp256k1 私钥；P-256 钱包为 nil
	PublicKey      []byte            // P-256：65 字节未压缩；secp256k1：33 字节压缩
	Curve          string            // CurveP256 或 CurveSecp256k1
	Mnemonic       string            // 可选：派生本钱包的 BIP-39 助记词
}

// isSecp256k1 按私钥类型判曲线（不依赖 Curve 字符串，避免手写 Wallet 漏填字段时误判）。
func (w *Wallet) isSecp256k1() bool {
	return w != nil && w.SecpPrivateKey != nil
}

// NewWallet 生成一个新的 P-256 密钥对（旧路径，保持兼容）。
func NewWallet() (*Wallet, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	pub := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	return &Wallet{PrivateKey: priv, PublicKey: pub, Curve: CurveP256}, nil
}

// PubKeyHash 计算本钱包的公钥哈希（20 字节）。
// 分发规则：secp256k1 钱包返回 RIPEMD160(SHA256(pubkey))；
// P-256 钱包返回旧规则 SHA256(pubkey) 截断 20 字节。P-256 行为与旧版完全一致。
func (w *Wallet) PubKeyHash() [20]byte {
	if w.isSecp256k1() {
		return PubKeyHashSecp256k1(w.PublicKey)
	}
	sum := sha256.Sum256(w.PublicKey)
	var hash [20]byte
	copy(hash[:], sum[:20])
	return hash
}

// PubKeyHashOf 计算给定公钥的公钥哈希（20 字节），供 UTXO / Mempool 校验时用
// （验签前先确认公钥哈希等于 UTXO 锁定的地址）。
// 分发规则（与 Verify 的公钥分发一致）：33 字节且首字节 0x02/0x03 → secp256k1，
// 返回 RIPEMD160(SHA256(pubkey))；其余（包括 65 字节 0x04 的 P-256 公钥）→
// 旧规则 SHA256 截断 20 字节。注意：secp256k1 在本包内一律用压缩公钥，
// 65 字节 0x04 一律按 P-256 处理；secp256k1 未压缩公钥不在本包产生。
func PubKeyHashOf(pubKey []byte) [20]byte {
	if len(pubKey) == btcec.PubKeyBytesLenCompressed && (pubKey[0] == 0x02 || pubKey[0] == 0x03) {
		return PubKeyHashSecp256k1(pubKey)
	}
	sum := sha256.Sum256(pubKey)
	var hash [20]byte
	copy(hash[:], sum[:20])
	return hash
}

// SignTx 对一笔普通交易的所有输入签名：签名对象为 TxID（交易 Hash，
// 签名/公钥本身不计入 TxID，故签名前后 TxID 稳定）。每个输入填入相同的签名与本钱包公钥。
// 调用方须保证交易内容（输入引用 + 输出）已最终确定，签名后再改交易将使签名失效。
// Coinbase 交易不调用本函数（Coinbase 的 Signature 为附带数据，不是签名）。
func (w *Wallet) SignTx(tx *transaction.Transaction) error {
	sig, err := w.Sign(tx.Hash())
	if err != nil {
		return err
	}
	for i := range tx.Inputs {
		tx.Inputs[i].Signature = append([]byte(nil), sig...)
		tx.Inputs[i].PubKey = append([]byte(nil), w.PublicKey...)
	}
	return nil
}

// Sign 对任意消息哈希做 ECDSA 签名，返回固定 64 字节 r||s 拼接（r、s 各 32 字节大端补零）。
// 固定 64 字节是本包的签名格式约定（secp256k1 与 P-256 相同）：
// 旧版 P-256 Sign 返回 r.Bytes()||s.Bytes() 变长拼接（r、s 前导零被截掉，
// 长度歧义）；新版统一补零到 64 字节，Verify 同时接受 64 字节与旧变长格式，
// 故旧签名仍可验、新签名长度确定。
func (w *Wallet) Sign(msgHash [32]byte) ([]byte, error) {
	if w.isSecp256k1() {
		return signSecp256k1(w.SecpPrivateKey, msgHash)
	}
	if w.PrivateKey == nil {
		return nil, errors.New("钱包无 P-256 私钥，无法签名")
	}
	r, s, err := ecdsa.Sign(rand.Reader, w.PrivateKey, msgHash[:])
	if err != nil {
		return nil, err
	}
	return concatRS(r, s), nil
}

// concatRS 把 r、s 各补零到 32 字节后拼接为 64 字节 r||s。
func concatRS(r, s *big.Int) []byte {
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig
}

// Verify 用给定公钥字节验证签名是否有效。
// 公钥分发规则（不许猜，严格按长度+首字节）：
//   - 33 字节且首字节 0x02/0x03 → 压缩 secp256k1 公钥，签名须为 64 字节 r||s；
//   - 65 字节且首字节 0x04 → 未压缩 P-256 公钥，签名为 64 字节 r||s（兼容旧变长格式）；
//   - 其他长度/首字节 → 返回错误。
func Verify(pubKeyBytes []byte, msgHash [32]byte, sig []byte) (bool, error) {
	switch {
	case len(pubKeyBytes) == btcec.PubKeyBytesLenCompressed && (pubKeyBytes[0] == 0x02 || pubKeyBytes[0] == 0x03):
		return verifySecp256k1(pubKeyBytes, msgHash, sig)
	case len(pubKeyBytes) == 65 && pubKeyBytes[0] == 0x04:
		return verifyP256(pubKeyBytes, msgHash, sig)
	default:
		return false, errors.New("无法识别的公钥格式：须为 33 字节压缩 secp256k1（0x02/0x03 开头）或 65 字节未压缩 P-256（0x04 开头）")
	}
}

// verifyP256 验 P-256 签名：64 字节按 32/32 切分；旧变长签名按全部切分点尝试验签。
// 旧变长格式 r.Bytes()||s.Bytes() 本身不记录 r、s 各自长度，半长切分在 r、s
// 字节长度不等时必然错切；本函数对非 64 字节签名尝试全部切分点，任一切分验签通过即接受，
// 既兼容旧版产物，又不接受伪造签名（ECDSA 验签通过的概率可忽略）。
func verifyP256(pubKeyBytes []byte, msgHash [32]byte, sig []byte) (bool, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
	if x == nil {
		return false, errors.New("非法 P-256 公钥字节，无法解析曲线坐标")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	switch {
	case len(sig) == 64:
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(pub, msgHash[:], r, s), nil
	case len(sig) > 0 && len(sig) <= 64:
		// 兼容旧版变长 r.Bytes()||s.Bytes() 签名：尝试全部切分点。
		for k := 1; k < len(sig); k++ {
			r := new(big.Int).SetBytes(sig[:k])
			s := new(big.Int).SetBytes(sig[k:])
			if ecdsa.Verify(pub, msgHash[:], r, s) {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, errors.New("非法 P-256 签名长度：须为 64 字节或不大于 64 字节的旧变长格式")
	}
}

// privateScalar 返回私钥标量（32 字节大端），供加密备份与 HD 派生使用。
// 调用方须保证钱包持有私钥。
func (w *Wallet) privateScalar() ([]byte, error) {
	if w.isSecp256k1() {
		return w.SecpPrivateKey.Serialize(), nil
	}
	if w.PrivateKey == nil || w.PrivateKey.D == nil {
		return nil, errors.New("钱包无私钥")
	}
	scalar := make([]byte, 32)
	w.PrivateKey.D.FillBytes(scalar)
	return scalar, nil
}

// walletFromP256Scalar 由 32 字节标量构造 P-256 钱包（HD 派生 / 加密恢复用）。
// 标量须满足 1 <= scalar < P-256 阶，否则返回错误。
func walletFromP256Scalar(scalar []byte) (*Wallet, error) {
	if len(scalar) != 32 {
		return nil, errors.New("P-256 私钥标量须为 32 字节")
	}
	d := new(big.Int).SetBytes(scalar)
	n := elliptic.P256().Params().N
	if d.Sign() <= 0 || d.Cmp(n) >= 0 {
		return nil, errors.New("P-256 私钥标量超出合法范围")
	}
	x, y := elliptic.P256().ScalarBaseMult(scalar)
	return &Wallet{
		PrivateKey: &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
			D:         d,
		},
		PublicKey: elliptic.Marshal(elliptic.P256(), x, y),
		Curve:     CurveP256,
	}, nil
}

// walletFromSecpScalar 由 32 字节标量构造 secp256k1 钱包（HD 派生 / 加密恢复用）。
// 标量须满足 1 <= scalar < secp256k1 阶，否则返回错误。
func walletFromSecpScalar(scalar []byte) (*Wallet, error) {
	if len(scalar) != 32 {
		return nil, errors.New("secp256k1 私钥标量须为 32 字节")
	}
	d := new(big.Int).SetBytes(scalar)
	if d.Sign() <= 0 || d.Cmp(btcec.S256().Params().N) >= 0 {
		return nil, errors.New("secp256k1 私钥标量超出合法范围")
	}
	priv, pub := btcec.PrivKeyFromBytes(scalar)
	return &Wallet{
		SecpPrivateKey: priv,
		PublicKey:      pub.SerializeCompressed(),
		Curve:          CurveSecp256k1,
	}, nil
}
