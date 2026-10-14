package wallet

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// TestSecp256k1GenerateAddressSignVerify：secp256k1 生成 → 地址 → 签名 → 验签全链路。
func TestSecp256k1GenerateAddressSignVerify(t *testing.T) {
	w, err := NewSecp256k1Wallet()
	if err != nil {
		t.Fatalf("NewSecp256k1Wallet: %v", err)
	}
	if len(w.PublicKey) != 33 || (w.PublicKey[0] != 0x02 && w.PublicKey[0] != 0x03) {
		t.Fatalf("secp256k1 公钥须为 33 字节压缩格式，实得 %d 字节首字节 0x%02x", len(w.PublicKey), w.PublicKey[0])
	}
	if w.Curve != CurveSecp256k1 {
		t.Fatalf("Curve = %q， want %q", w.Curve, CurveSecp256k1)
	}
	if got := len(w.PubKeyHash()); got != 20 {
		t.Fatalf("PubKeyHash 长度 = %d， want 20", got)
	}
	addr := AddressSecp256k1(w.PublicKey)
	if !strings.HasPrefix(addr, "1") {
		t.Fatalf("secp256k1 地址应以 '1' 开头（版本字节 0x00），实得 %s", addr)
	}
	version, hash, err := DecodeBase58Check(addr)
	if err != nil {
		t.Fatalf("DecodeBase58Check: %v", err)
	}
	if version != Base58CheckVersion {
		t.Fatalf("版本字节 = 0x%02x， want 0x%02x", version, Base58CheckVersion)
	}
	if hash != w.PubKeyHash() {
		t.Fatalf("解码出的公钥哈希与钱包 PubKeyHash 不一致")
	}
	// 统一验签入口：PubKeyHashOf(压缩公钥) 须等于钱包地址哈希（UTXO 校验依赖此一致性）。
	if PubKeyHashOf(w.PublicKey) != w.PubKeyHash() {
		t.Fatalf("PubKeyHashOf(压缩公钥) 与钱包 PubKeyHash 不一致")
	}

	msg := sha256.Sum256([]byte("hello hundun"))
	sig, err := w.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("secp256k1 签名长度 = %d， want 64（固定 r||s）", len(sig))
	}
	ok, err := Verify(w.PublicKey, msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatalf("secp256k1 签名验签失败")
	}
	// 篡改消息 → 验签失败。
	bad := sha256.Sum256([]byte("hello hundun!"))
	ok, err = Verify(w.PublicKey, bad, sig)
	if err != nil {
		t.Fatalf("Verify(篡改消息): %v", err)
	}
	if ok {
		t.Fatalf("篡改消息的签名不应通过验签")
	}
	// SignTx 往返：签名进交易后用统一 Verify 仍通过。
}

// TestSecp256k1KnownVector：比特币公开向量校验 RIPEMD160 + Base58Check 实现。
// 私钥标量 1 → 压缩公钥 0279BE...F81798 → 地址 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH。
func TestSecp256k1KnownVector(t *testing.T) {
	scalar := make([]byte, 32)
	scalar[31] = 1
	w, err := walletFromSecpScalar(scalar)
	if err != nil {
		t.Fatalf("walletFromSecpScalar(1): %v", err)
	}
	wantPub := "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	gotPub := hex.EncodeToString(w.PublicKey)
	if gotPub != wantPub {
		t.Fatalf("压缩公钥 = %s， want %s", gotPub, wantPub)
	}
	addr := AddressSecp256k1(w.PublicKey)
	if addr != "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH" {
		t.Fatalf("地址 = %s， want 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", addr)
	}
}

// TestP256LegacyStillVerifies：P-256 旧地址仍验签通过，行为与旧版一致。
func TestP256LegacyStillVerifies(t *testing.T) {
	w, err := NewWallet()
	if err != nil {
		t.Fatalf("NewWallet: %v", err)
	}
	if len(w.PublicKey) != 65 || w.PublicKey[0] != 0x04 {
		t.Fatalf("P-256 公钥须为 65 字节未压缩格式")
	}
	if w.Curve != CurveP256 {
		t.Fatalf("Curve = %q， want %q", w.Curve, CurveP256)
	}
	if len(w.PubKeyHash()) != 20 {
		t.Fatalf("P-256 PubKeyHash 长度须为 20")
	}
	// 旧规则：SHA256 截断。
	sum := sha256.Sum256(w.PublicKey)
	h := w.PubKeyHash()
	if !bytes.Equal(h[:], sum[:20]) {
		t.Fatalf("P-256 PubKeyHash 不再是 SHA256 截断，兼容性破坏")
	}
	if PubKeyHashOf(w.PublicKey) != w.PubKeyHash() {
		t.Fatalf("PubKeyHashOf(P-256 公钥) 与钱包 PubKeyHash 不一致")
	}
	msg := sha256.Sum256([]byte("legacy"))
	sig, err := w.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("P-256 签名长度 = %d， want 64（固定 r||s）", len(sig))
	}
	ok, err := Verify(w.PublicKey, msg, sig)
	if err != nil || !ok {
		t.Fatalf("P-256 签名验签失败：ok=%v err=%v", ok, err)
	}
	// 旧变长签名兼容：循环签名直到出现带前导零的 r 或 s（约每百次出现一次），
	// 取去零后的变长拼接，Verify 仍应通过（旧版 Sign 的产物形态）。
	trim := func(b []byte) []byte { return bytes.TrimLeft(b, "\x00") }
	var legacySig []byte
	var legacyMsg [32]byte
	for i := 0; i < 2000 && legacySig == nil; i++ {
		m := sha256.Sum256([]byte(fmt.Sprintf("legacy-%d", i)))
		sigI, err := w.Sign(m)
		if err != nil {
			t.Fatalf("Sign(legacy 循环): %v", err)
		}
		trimmed := append(append([]byte{}, trim(sigI[:32])...), trim(sigI[32:])...)
		if len(trimmed) < 64 {
			legacySig, legacyMsg = trimmed, m
		}
	}
	if legacySig == nil {
		t.Fatalf("2000 次签名未出现带前导零的 r/s，无法构造旧变长签名（概率上几乎不可能）")
	}
	ok, err = Verify(w.PublicKey, legacyMsg, legacySig)
	if err != nil || !ok {
		t.Fatalf("旧变长 P-256 签名验签失败：ok=%v err=%v", ok, err)
	}
}

// TestVerifyRejectsUnknownPubKey：其他长度公钥 → 返回错误，不许猜。
func TestVerifyRejectsUnknownPubKey(t *testing.T) {
	msg := sha256.Sum256([]byte("x"))
	for _, bad := range [][]byte{
		{},
		make([]byte, 10),
		make([]byte, 32),
		make([]byte, 33), // 33 字节但首字节非 0x02/0x03（全零）
		make([]byte, 64),
		append([]byte{0x05}, make([]byte, 64)...),
	} {
		if _, err := Verify(bad, msg, make([]byte, 64)); err == nil {
			t.Fatalf("Verify(公钥长度 %d) 应返回错误", len(bad))
		}
	}
	// secp256k1 签名非 64 字节 → 错误。
	w, _ := NewSecp256k1Wallet()
	if _, err := Verify(w.PublicKey, msg, []byte{1, 2, 3}); err == nil {
		t.Fatalf("secp256k1 非 64 字节签名应返回错误")
	}
}

// TestBase58CheckRoundTripAndChecksum：编解码往返 + 校验和错误拒绝。
func TestBase58CheckRoundTripAndChecksum(t *testing.T) {
	var hash [20]byte
	for i := range hash {
		hash[i] = byte(i * 7)
	}
	addr := Base58CheckEncode(Base58CheckVersion, hash)
	version, decoded, err := DecodeBase58Check(addr)
	if err != nil {
		t.Fatalf("DecodeBase58Check: %v", err)
	}
	if version != Base58CheckVersion || decoded != hash {
		t.Fatalf("Base58Check 往返不一致")
	}
	// Base58 编解码往返（含前导零）。
	raw := []byte{0, 0, 1, 2, 3, 255}
	if got, err := Base58Decode(Base58Encode(raw)); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("Base58 往返失败：got=%x err=%v", got, err)
	}
	// 篡改末字符 → 校验和错误拒绝。
	bad := addr[:len(addr)-1] + "1"
	if addr[len(addr)-1] == '1' {
		bad = addr[:len(addr)-1] + "2"
	}
	if _, _, err := DecodeBase58Check(bad); err == nil {
		t.Fatalf("篡改后的地址应被校验和拒绝")
	}
	// 非法字符 → 拒绝。
	if _, err := Base58Decode("0OIl"); err == nil {
		t.Fatalf("含 0/O/I/l 的 Base58 应被拒绝")
	}
}

// TestMnemonicSeedRestoreSameWallet：助记词生成 → 种子 → 恢复同一钱包。
func TestMnemonicSeedRestoreSameWallet(t *testing.T) {
	// BIP-39 公开向量：熵全零 → abandon×11 + about。
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	if !ValidateMnemonic(mnemonic) {
		t.Fatalf("公开向量助记词应合法")
	}
	if ValidateMnemonic("abandon abandon abandon") {
		t.Fatalf("截断助记词应非法")
	}
	seed, err := MnemonicToSeed(mnemonic, "")
	if err != nil {
		t.Fatalf("MnemonicToSeed: %v", err)
	}
	if len(seed) != 64 {
		t.Fatalf("种子长度 = %d， want 64", len(seed))
	}
	// 同助记词、同曲线 → 同一钱包；不同 passphrase → 不同钱包。
	for _, curve := range []string{CurveP256, CurveSecp256k1} {
		a, err := WalletFromMnemonic(mnemonic, "", curve)
		if err != nil {
			t.Fatalf("WalletFromMnemonic(%s): %v", curve, err)
		}
		b, err := WalletFromMnemonic(mnemonic, "", curve)
		if err != nil {
			t.Fatalf("WalletFromMnemonic(%s) 2nd: %v", curve, err)
		}
		if !bytes.Equal(a.PublicKey, b.PublicKey) {
			t.Fatalf("%s：同助记词恢复出不同钱包", curve)
		}
		c, err := WalletFromSeed(seed, curve)
		if err != nil {
			t.Fatalf("WalletFromSeed(%s): %v", curve, err)
		}
		if !bytes.Equal(a.PublicKey, c.PublicKey) {
			t.Fatalf("%s：种子派生与助记词派生不一致", curve)
		}
		d, err := WalletFromMnemonic(mnemonic, "another-passphrase", curve)
		if err != nil {
			t.Fatalf("WalletFromMnemonic(passphrase): %v", err)
		}
		if bytes.Equal(a.PublicKey, d.PublicKey) {
			t.Fatalf("%s：不同 passphrase 应派生不同钱包", curve)
		}
		if a.Mnemonic != mnemonic {
			t.Fatalf("派生钱包应携带助记词")
		}
	}
	// 同种子、不同曲线 → 不同钱包（同路径不同曲线实现分开）。
	p, _ := WalletFromSeed(seed, CurveP256)
	s, _ := WalletFromSeed(seed, CurveSecp256k1)
	if bytes.Equal(p.PublicKey, s.PublicKey) {
		t.Fatalf("同种子不同曲线不应得到相同公钥")
	}
	// 非法曲线 → 错误。
	if _, err := WalletFromSeed(seed, "ed25519"); err == nil {
		t.Fatalf("未知曲线应返回错误")
	}
	if _, err := WalletFromMnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", "", CurveP256); err == nil {
		// 12 个 abandon 校验和非法（合法应为 abandon×11 + about）。
		t.Fatalf("非法助记词应返回错误")
	}
	// NewMnemonic 生成 12 词且合法。
	m, err := NewMnemonic()
	if err != nil {
		t.Fatalf("NewMnemonic: %v", err)
	}
	if len(strings.Fields(m)) != 12 || !ValidateMnemonic(m) {
		t.Fatalf("NewMnemonic 应生成合法 12 词助记词，实得 %q", m)
	}
}

// TestEncryptDecryptWrongPassword：口令加密 → 解密一致 → 错口令拒绝。
func TestEncryptDecryptWrongPassword(t *testing.T) {
	for _, curve := range []string{CurveP256, CurveSecp256k1} {
		mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
		w, err := WalletFromMnemonic(mnemonic, "", curve)
		if err != nil {
			t.Fatalf("WalletFromMnemonic(%s): %v", curve, err)
		}
		enc, err := EncryptWalletFile(w, "correct-horse-battery")
		if err != nil {
			t.Fatalf("EncryptWalletFile(%s): %v", curve, err)
		}
		if len(enc) < 16+12 {
			t.Fatalf("密文过短")
		}
		dec, err := DecryptWalletFile(enc, "correct-horse-battery")
		if err != nil {
			t.Fatalf("DecryptWalletFile(%s): %v", curve, err)
		}
		if !bytes.Equal(dec.PublicKey, w.PublicKey) {
			t.Fatalf("%s：解密后公钥不一致", curve)
		}
		if dec.Mnemonic != mnemonic {
			t.Fatalf("%s：解密后助记词丢失", curve)
		}
		// 解密出的钱包仍能签名验签。
		msg := sha256.Sum256([]byte("after-decrypt"))
		sig, err := dec.Sign(msg)
		if err != nil {
			t.Fatalf("解密后 Sign: %v", err)
		}
		ok, err := Verify(dec.PublicKey, msg, sig)
		if err != nil || !ok {
			t.Fatalf("解密后验签失败：ok=%v err=%v", ok, err)
		}
		// 错口令拒绝。
		if _, err := DecryptWalletFile(enc, "wrong-password"); err == nil {
			t.Fatalf("%s：错口令应拒绝解密", curve)
		}
		// 篡改密文拒绝。
		tampered := append([]byte{}, enc...)
		tampered[len(tampered)-1] ^= 0xFF
		if _, err := DecryptWalletFile(tampered, "correct-horse-battery"); err == nil {
			t.Fatalf("%s：篡改密文应拒绝解密", curve)
		}
		// 空口令拒绝加密。
		if _, err := EncryptWalletFile(w, ""); err == nil {
			t.Fatalf("%s：空口令应拒绝加密", curve)
		}
	}
}

// TestEncryptLegacyWallet：v1 明文钱包迁移 → 加密 → 解密一致。
func TestEncryptLegacyWallet(t *testing.T) {
	w, err := NewWallet() // v1 明文钱包：从未加密过
	if err != nil {
		t.Fatalf("NewWallet: %v", err)
	}
	enc, err := EncryptLegacyWallet(w, "migrate-me")
	if err != nil {
		t.Fatalf("EncryptLegacyWallet: %v", err)
	}
	dec, err := DecryptWalletFile(enc, "migrate-me")
	if err != nil {
		t.Fatalf("DecryptWalletFile(迁移后): %v", err)
	}
	if !bytes.Equal(dec.PublicKey, w.PublicKey) {
		t.Fatalf("迁移后解密公钥不一致")
	}
	if _, err := DecryptWalletFile(enc, "wrong"); err == nil {
		t.Fatalf("迁移后错口令应拒绝解密")
	}

	// secp256k1 旧钱包同样可迁移。
	ws, err := NewSecp256k1Wallet()
	if err != nil {
		t.Fatalf("NewSecp256k1Wallet: %v", err)
	}
	encS, err := EncryptLegacyWallet(ws, "migrate-secp")
	if err != nil {
		t.Fatalf("EncryptLegacyWallet(secp): %v", err)
	}
	decS, err := DecryptWalletFile(encS, "migrate-secp")
	if err != nil {
		t.Fatalf("DecryptWalletFile(迁移 secp): %v", err)
	}
	if !bytes.Equal(decS.PublicKey, ws.PublicKey) {
		t.Fatalf("迁移后 secp 解密公钥不一致")
	}
}

// TestDualCurvePubKeyHash20Bytes：双曲线 PubKeyHash 均为 20 字节。
func TestDualCurvePubKeyHash20Bytes(t *testing.T) {
	p, _ := NewWallet()
	s, _ := NewSecp256k1Wallet()
	if len(p.PubKeyHash()) != 20 || len(s.PubKeyHash()) != 20 {
		t.Fatalf("双曲线 PubKeyHash 均须为 20 字节")
	}
	if len(PubKeyHashSecp256k1(s.PublicKey)) != 20 {
		t.Fatalf("PubKeyHashSecp256k1 须为 20 字节")
	}
	// 两曲线同钱包哈希不应恒等（不同哈希算法，碰撞概率可忽略）。
	if p.PubKeyHash() == s.PubKeyHash() {
		t.Fatalf("两随机钱包哈希不应相等")
	}
}
