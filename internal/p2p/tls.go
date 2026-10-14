// Package p2p 的 mTLS / 节点认证支持（P4）。
//
// 本文件只提供可独立使用的构造块，不修改现有 node.go 的连接逻辑；
// 集成接线（Node.Start / ConnectToPeer 是否启用 TLS）由主代理另行完成。
//
// 设计要点：
//   - 证书体系：自签 CA + 节点证书，双向验证（mTLS），全部用标准库
//     crypto/x509 + crypto/tls 实现，零外部依赖。
//   - 轻量消息签名：常开设计，供集成方在 TLS 之上或无 TLS 场景下对
//     单条消息做来源认证；签名对象为 SHA256(msg)，格式为 r||s 拼接，
//     与 wallet.Wallet.Sign 的签名格式一致。
package p2p

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// TLSOptions 控制节点是否启用 mTLS。
//
// 默认 Enabled=false：本地开发兼容（明文 TCP，与现有行为一致）。
// 生产环境必须设 Enabled=true，并配齐三个文件路径。
type TLSOptions struct {
	Enabled  bool   // 是否启用 mTLS（默认 false，本地开发兼容；生产设 true）
	CertFile string // 节点证书 PEM 文件路径
	KeyFile  string // 节点私钥 PEM 文件路径
	CAFile   string // 信任的 CA 证书 PEM 文件路径
}

// 证书有效期。
const (
	// caValidity：CA 证书有效期 10 年。
	caValidity = 10 * 365 * 24 * time.Hour
	// nodeCertValidity：节点证书有效期 1 年。
	nodeCertValidity = 365 * 24 * time.Hour
)

// GenerateCA 生成一个自签 CA。
//
// 密钥类型：ECDSA P-256（与 wallet 密钥曲线一致，密钥短、签名快；
// RSA 2048 未采用——同等安全强度下 P-256 证书与握手开销更小）。
// 有效期 10 年。返回 CA 证书 PEM、私钥 PEM、解析后的证书与私钥。
func GenerateCA(commonName string) (certPEM, keyPEM []byte, cert *x509.Certificate, key crypto.Signer, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("生成 CA 私钥失败: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"HUNDUN"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(caValidity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("自签 CA 证书失败: %w", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("解析 CA 证书失败: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("编码 CA 私钥失败: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, cert, priv, nil
}

// IssueNodeCert 用 CA 签发节点证书。
//
// SAN 包含 nodeID（DNS SAN）、localhost（DNS SAN）与 127.0.0.1 / ::1（IP SAN），
// 使节点既能以 nodeID/主机名连接，也能以本地回环地址连接。
// 有效期 1 年。证书同时具备 ServerAuth 与 ClientAuth 用途，可用于 mTLS 双端。
func IssueNodeCert(caCert *x509.Certificate, caKey crypto.Signer, nodeID string) (certPEM, keyPEM []byte, err error) {
	if caCert == nil {
		return nil, nil, errors.New("CA 证书为空")
	}
	if caKey == nil {
		return nil, nil, errors.New("CA 私钥为空")
	}
	if nodeID == "" {
		return nil, nil, errors.New("nodeID 为空")
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("生成节点私钥失败: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   nodeID,
			Organization: []string{"HUNDUN"},
		},
		DNSNames:              []string{nodeID, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:             now,
		NotAfter:              now.Add(nodeCertValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("签发节点证书失败: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("编码节点私钥失败: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// TLSConfigFromFiles 从文件加载证书，构造双向验证的 *tls.Config。
//
// 服务端语义：要求客户端出示证书并验证（RequireAndVerifyClientCert）。
// 同一配置也可用于客户端：Certificates 用作出示的客户端证书，
// RootCAs 用于验证服务端证书；拨号方需自行设置 ServerName
// （如 "localhost"），否则 Go 会用拨号地址的主机名做校验。
func TLSConfigFromFiles(certFile, keyFile, caFile string) (*tls.Config, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("读取证书文件失败: %w", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("读取私钥文件失败: %w", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("读取 CA 文件失败: %w", err)
	}
	return TLSConfigFromPEM(certPEM, keyPEM, caPEM, true)
}

// TLSConfigFromPEM 是 TLSConfigFromFiles 的内存版，供单测与无文件场景使用。
//
// isServer=true：服务端配置，要求并验证客户端证书。
// isServer=false：客户端配置，验证服务端证书；调用方需设置 ServerName。
// 两种配置均强制最低 TLS 1.2。
func TLSConfigFromPEM(certPEM, keyPEM, caPEM []byte, isServer bool) (*tls.Config, error) {
	if len(certPEM) == 0 {
		return nil, errors.New("证书 PEM 为空")
	}
	if len(keyPEM) == 0 {
		return nil, errors.New("私钥 PEM 为空")
	}
	if len(caPEM) == 0 {
		return nil, errors.New("CA PEM 为空")
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("解析证书/私钥对失败: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("解析 CA 证书失败")
	}

	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if isServer {
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		// RootCAs 同样填上：同一配置被复用于出站拨号时可验证对端。
		cfg.RootCAs = pool
	} else {
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// SignMessage 对消息做 P-256 ECDSA 签名。
//
// 签名对象为 SHA256(msg)，签名格式为 r||s 拼接，与 wallet.Wallet.Sign 一致。
// 调用方须保证 msg 已最终确定；签名后再改动 msg 将使签名失效。
func SignMessage(privKey *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	if privKey == nil {
		return nil, errors.New("私钥为空")
	}
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("ECDSA 签名失败: %w", err)
	}
	return append(r.Bytes(), s.Bytes()...), nil
}

// VerifyMessageSignature 验证 SignMessage 产生的签名。
//
// pubKey 为签名方的 P-256 公钥；返回 (是否有效, 错误)。
// 签名格式为 r||s 拼接，按一半长度切分还原 r、s（与 wallet.Verify 一致）。
func VerifyMessageSignature(pubKey *ecdsa.PublicKey, msg, sig []byte) (bool, error) {
	if pubKey == nil {
		return false, errors.New("公钥为空")
	}
	if len(sig) < 2 {
		return false, errors.New("签名过短")
	}
	digest := sha256.Sum256(msg)
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s := new(big.Int).SetBytes(sig[half:])
	return ecdsa.Verify(pubKey, digest[:], r, s), nil
}

// MessageAuth 为一条消息附加的认证信息：声明的发送节点与消息签名。
// 集成方应在发送前用 SignEnvelope 填充，在接收后用 VerifyEnvelope 校验。
type MessageAuth struct {
	NodeID    string // 声明的发送节点 ID
	Signature []byte // 对 msg 的签名（见 SignMessage）
}

// SignEnvelope 对 msg 签名并打包成 MessageAuth。
func SignEnvelope(privKey *ecdsa.PrivateKey, nodeID string, msg []byte) (MessageAuth, error) {
	if nodeID == "" {
		return MessageAuth{}, errors.New("nodeID 为空")
	}
	sig, err := SignMessage(privKey, msg)
	if err != nil {
		return MessageAuth{}, err
	}
	return MessageAuth{NodeID: nodeID, Signature: sig}, nil
}

// Sign 是 SignEnvelope 的别名，供偏好短名的集成方使用。
func Sign(privKey *ecdsa.PrivateKey, nodeID string, msg []byte) (MessageAuth, error) {
	return SignEnvelope(privKey, nodeID, msg)
}

// VerifyEnvelope 验证 MessageAuth 中的签名是否对应 msg。
// 注意：本函数只验证“签名与消息匹配”，不验证 NodeID 与公钥的绑定关系；
// NodeID→公钥的映射由集成方维护（例如握手阶段交换并用 TLS 证书校验）。
func VerifyEnvelope(pubKey *ecdsa.PublicKey, msg []byte, auth MessageAuth) (bool, error) {
	return VerifyMessageSignature(pubKey, msg, auth.Signature)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("生成证书序列号失败: %w", err)
	}
	return serial, nil
}
