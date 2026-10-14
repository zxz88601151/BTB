package wallet

import (
	"os"
	"path/filepath"
	"testing"
)

// 明文保存→加载往返：私钥一致。
func TestWalletFilePlainRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")
	w, err := NewWallet()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveWalletFile(path, w, ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("钱包文件权限 = %o，want 0600", info.Mode().Perm())
	}
	back, err := LoadWalletFile(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(back.PublicKey) != string(w.PublicKey) {
		t.Errorf("加载后公钥不一致")
	}
}

// 加密保存→解密往返；错口令拒绝。
func TestWalletFileEncryptedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")
	w, err := NewSecp256k1Wallet()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveWalletFile(path, w, "correct-horse"); err != nil {
		t.Fatal(err)
	}
	back, err := LoadWalletFile(path, "correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	if string(back.PublicKey) != string(w.PublicKey) {
		t.Errorf("解密后公钥不一致")
	}
	if _, err := LoadWalletFile(path, "wrong-password"); err == nil {
		t.Errorf("错口令应拒绝解密")
	}
	// 密文文件配空口令应返回明确错误，不当明文解析。
	if _, err := LoadWalletFile(path, ""); err == nil {
		t.Errorf("密文文件配空口令应报错")
	}
}

// 明文→加密迁移：迁移后可用同一口令解密回同一钱包；重复迁移拒绝。
func TestMigrateWalletFileToEncrypted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "wallet.json")
	w, err := NewWallet()
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveWalletFile(path, w, ""); err != nil {
		t.Fatal(err)
	}
	if err := MigrateWalletFileToEncrypted(path, "migrate-pw"); err != nil {
		t.Fatal(err)
	}
	back, err := LoadWalletFile(path, "migrate-pw")
	if err != nil {
		t.Fatal(err)
	}
	if string(back.PublicKey) != string(w.PublicKey) {
		t.Errorf("迁移后解密公钥不一致")
	}
	if err := MigrateWalletFileToEncrypted(path, "migrate-pw"); err == nil {
		t.Errorf("已加密文件重复迁移应拒绝")
	}
}
