package p2p

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSGenerateAndIssue(t *testing.T) {
	caPEM, caKeyPEM, caCert, _, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA 失败: %v", err)
	}
	if len(caPEM) == 0 || len(caKeyPEM) == 0 {
		t.Fatal("CA PEM 为空")
	}
	if !caCert.IsCA {
		t.Fatal("CA 证书 IsCA 应为 true")
	}
	if got := caCert.NotAfter.Sub(caCert.NotBefore); got != caValidity {
		t.Fatalf("CA 有效期 = %v，期望 %v", got, caValidity)
	}

	nodeCertPEM, _, err := IssueNodeCert(caCert, mustSigner(t, caKeyPEM), "node-1")
	if err != nil {
		t.Fatalf("IssueNodeCert 失败: %v", err)
	}
	block, _ := pem.Decode(nodeCertPEM)
	if block == nil {
		t.Fatal("节点证书 PEM 解码失败")
	}
	nodeCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("解析节点证书失败: %v", err)
	}
	if got := nodeCert.NotAfter.Sub(nodeCert.NotBefore); got != nodeCertValidity {
		t.Fatalf("节点证书有效期 = %v，期望 %v", got, nodeCertValidity)
	}
	if nodeCert.Subject.CommonName != "node-1" {
		t.Fatalf("节点证书 CN = %q，期望 node-1", nodeCert.Subject.CommonName)
	}
	hasLocalhost, hasNodeID := false, false
	for _, d := range nodeCert.DNSNames {
		if d == "localhost" {
			hasLocalhost = true
		}
		if d == "node-1" {
			hasNodeID = true
		}
	}
	if !hasLocalhost || !hasNodeID {
		t.Fatalf("节点证书 DNS SAN = %v，期望包含 node-1 与 localhost", nodeCert.DNSNames)
	}
	hasLoopback := false
	for _, ip := range nodeCert.IPAddresses {
		if ip.String() == "127.0.0.1" {
			hasLoopback = true
		}
	}
	if !hasLoopback {
		t.Fatalf("节点证书 IP SAN = %v，期望包含 127.0.0.1", nodeCert.IPAddresses)
	}

	// 链验证：节点证书应能由 CA 验证通过（DNSName=localhost）。
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := nodeCert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost", CurrentTime: time.Now()}); err != nil {
		t.Fatalf("节点证书链验证失败: %v", err)
	}
}

// mustSigner 从 CA 私钥 PEM 解析出 *ecdsa.PrivateKey（即 crypto.Signer）。
func mustSigner(t *testing.T, keyPEM []byte) *ecdsa.PrivateKey {
	t.Helper()
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		t.Fatal("CA 私钥 PEM 解码失败")
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("解析 CA 私钥失败: %v", err)
	}
	return priv
}

// tlsPair 用同一 CA 签发服务端与客户端证书，返回双方配置。
func tlsPair(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (serverCfg, clientCfg *tls.Config) {
	t.Helper()
	serverCertPEM, serverKeyPEM, err := IssueNodeCert(caCert, caKey, "server-node")
	if err != nil {
		t.Fatalf("签发服务端证书失败: %v", err)
	}
	clientCertPEM, clientKeyPEM, err := IssueNodeCert(caCert, caKey, "client-node")
	if err != nil {
		t.Fatalf("签发客户端证书失败: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	serverCfg, err = TLSConfigFromPEM(serverCertPEM, serverKeyPEM, caPEM, true)
	if err != nil {
		t.Fatalf("服务端 TLS 配置失败: %v", err)
	}
	clientCfg, err = TLSConfigFromPEM(clientCertPEM, clientKeyPEM, caPEM, false)
	if err != nil {
		t.Fatalf("客户端 TLS 配置失败: %v", err)
	}
	clientCfg.ServerName = "localhost"
	return serverCfg, clientCfg
}

// runTLSEcho 启动一个 TLS 服务端（读 ping 回 pong），返回监听地址与服务端结果通道。
func runTLSEcho(t *testing.T, serverCfg *tls.Config) (addr string, serverErr chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	tlsLn := tls.NewListener(ln, serverCfg)
	serverErr = make(chan error, 1)
	go func() {
		defer close(serverErr)
		conn, err := tlsLn.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4)
		if _, err := conn.Read(buf); err != nil {
			serverErr <- err
			return
		}
		if string(buf) != "ping" {
			serverErr <- errMismatch("ping")
			return
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()
	t.Cleanup(func() { _ = tlsLn.Close() })
	return tlsLn.Addr().String(), serverErr
}

type errMismatch string

func (e errMismatch) Error() string { return "消息不匹配: " + string(e) }

func TestTLSHandshake(t *testing.T) {
	_, _, caCert, caKey, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA 失败: %v", err)
	}
	ecdsaCAKey, ok := caKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("CA 私钥不是 ECDSA")
	}
	serverCfg, clientCfg := tlsPair(t, caCert, ecdsaCAKey)

	if serverCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("服务端 MinVersion = %v，期望 TLS 1.2", serverCfg.MinVersion)
	}
	if serverCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("服务端 ClientAuth = %v，期望 RequireAndVerifyClientCert", serverCfg.ClientAuth)
	}
	if clientCfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("客户端 MinVersion = %v，期望 TLS 1.2", clientCfg.MinVersion)
	}

	addr, serverErr := runTLSEcho(t, serverCfg)
	conn, err := tls.Dial("tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("mTLS 握手失败: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("客户端写失败: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("客户端读失败: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("回显 = %q，期望 pong", buf)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("服务端出错: %v", err)
	}
}

func TestTLSConfigFromFiles(t *testing.T) {
	_, caKeyPEM, caCert, _, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA 失败: %v", err)
	}
	caKey := mustSigner(t, caKeyPEM)
	serverCertPEM, serverKeyPEM, err := IssueNodeCert(caCert, caKey, "server-node")
	if err != nil {
		t.Fatalf("签发服务端证书失败: %v", err)
	}
	clientCertPEM, clientKeyPEM, err := IssueNodeCert(caCert, caKey, "client-node")
	if err != nil {
		t.Fatalf("签发客户端证书失败: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	dir := t.TempDir()
	write := func(name string, data []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatalf("写 %s 失败: %v", name, err)
		}
		return p
	}
	serverCfg, err := TLSConfigFromFiles(
		write("server.crt", serverCertPEM),
		write("server.key", serverKeyPEM),
		write("ca.crt", caPEM),
	)
	if err != nil {
		t.Fatalf("TLSConfigFromFiles（服务端）失败: %v", err)
	}
	clientCfg, err := TLSConfigFromFiles(
		write("client.crt", clientCertPEM),
		write("client.key", clientKeyPEM),
		write("ca.crt", caPEM),
	)
	if err != nil {
		t.Fatalf("TLSConfigFromFiles（客户端）失败: %v", err)
	}
	clientCfg.ServerName = "localhost"

	addr, serverErr := runTLSEcho(t, serverCfg)
	conn, err := tls.Dial("tcp", addr, clientCfg)
	if err != nil {
		t.Fatalf("文件配置 mTLS 握手失败: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("客户端写失败: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("客户端读失败: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("回显 = %q，期望 pong", buf)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("服务端出错: %v", err)
	}
}

func TestTLSExpiredCertRejected(t *testing.T) {
	_, caKeyPEM, caCert, _, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA 失败: %v", err)
	}
	caKey := mustSigner(t, caKeyPEM)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	t.Run("过期服务端证书", func(t *testing.T) {
		expiredCertPEM, expiredKeyPEM := issueExpiredCert(t, caCert, caKey, "server-node")
		serverCfg, err := TLSConfigFromPEM(expiredCertPEM, expiredKeyPEM, caPEM, true)
		if err != nil {
			t.Fatalf("服务端 TLS 配置失败: %v", err)
		}
		clientCertPEM, clientKeyPEM, err := IssueNodeCert(caCert, caKey, "client-node")
		if err != nil {
			t.Fatalf("签发客户端证书失败: %v", err)
		}
		clientCfg, err := TLSConfigFromPEM(clientCertPEM, clientKeyPEM, caPEM, false)
		if err != nil {
			t.Fatalf("客户端 TLS 配置失败: %v", err)
		}
		clientCfg.ServerName = "localhost"

		addr, _ := runTLSEcho(t, serverCfg)
		conn, err := tls.Dial("tcp", addr, clientCfg)
		if err == nil {
			_ = conn.Close()
			t.Fatal("过期服务端证书应被拒绝，握手却成功")
		}
		t.Logf("过期服务端证书被拒绝（符合预期）: %v", err)
	})

	t.Run("过期客户端证书", func(t *testing.T) {
		serverCertPEM, serverKeyPEM, err := IssueNodeCert(caCert, caKey, "server-node")
		if err != nil {
			t.Fatalf("签发服务端证书失败: %v", err)
		}
		serverCfg, err := TLSConfigFromPEM(serverCertPEM, serverKeyPEM, caPEM, true)
		if err != nil {
			t.Fatalf("服务端 TLS 配置失败: %v", err)
		}
		expiredCertPEM, expiredKeyPEM := issueExpiredCert(t, caCert, caKey, "client-node")
		clientCfg, err := TLSConfigFromPEM(expiredCertPEM, expiredKeyPEM, caPEM, false)
		if err != nil {
			t.Fatalf("客户端 TLS 配置失败: %v", err)
		}
		clientCfg.ServerName = "localhost"

		addr, serverErr := runTLSEcho(t, serverCfg)
		conn, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			// TLS 1.2 下客户端握手阶段即失败，也算拒绝。
			t.Logf("过期客户端证书被拒绝（符合预期）: %v", err)
			return
		}
		// TLS 1.3 下客户端握手可能先成功，服务端在握手后验证客户端证书；
		// 以服务端的拒绝为准。
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("ping"))
		_, _ = conn.Read(make([]byte, 4))
		select {
		case serr := <-serverErr:
			if serr == nil {
				t.Fatal("过期客户端证书应被服务端拒绝，服务端却接受")
			}
			t.Logf("过期客户端证书被服务端拒绝（符合预期）: %v", serr)
		case <-time.After(5 * time.Second):
			t.Fatal("等待服务端拒绝结果超时")
		}
	})
}

// issueExpiredCert 签发一张已过期的节点证书（有效期为过去的一年）。
func issueExpiredCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, nodeID string) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成节点私钥失败: %v", err)
	}
	serial, err := randomSerial()
	if err != nil {
		t.Fatalf("生成序列号失败: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: nodeID},
		DNSNames:              []string{nodeID, "localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		NotBefore:             now.AddDate(-2, 0, 0),
		NotAfter:              now.AddDate(-1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("签发过期证书失败: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("编码私钥失败: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestTLSForgedCARejected(t *testing.T) {
	_, _, realCACert, realCAKey, err := GenerateCA("real-ca")
	if err != nil {
		t.Fatalf("GenerateCA（真实）失败: %v", err)
	}
	realKey, ok := realCAKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("真实 CA 私钥不是 ECDSA")
	}
	_, _, forgedCACert, forgedCAKey, err := GenerateCA("forged-ca")
	if err != nil {
		t.Fatalf("GenerateCA（伪造）失败: %v", err)
	}
	forgedKey, ok := forgedCAKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatal("伪造 CA 私钥不是 ECDSA")
	}
	realCAPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: realCACert.Raw})

	t.Run("伪造CA签发的客户端证书", func(t *testing.T) {
		// 先直接做链验证：伪造证书对真实 CA 验签必须失败（覆盖服务端
		// 收到伪造证书时的验签路径；Go 客户端在握手时还会因服务端
		// CertificateRequest 的 CA 列表不含伪造 CA 而不发送该证书）。
		forgedCertPEM, forgedClientKeyPEM, err := IssueNodeCert(forgedCACert, forgedKey, "client-node")
		if err != nil {
			t.Fatalf("签发伪造客户端证书失败: %v", err)
		}
		block, _ := pem.Decode(forgedCertPEM)
		if block == nil {
			t.Fatal("伪造证书 PEM 解码失败")
		}
		forgedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("解析伪造证书失败: %v", err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(realCACert)
		if _, err := forgedCert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost"}); err == nil {
			t.Fatal("伪造 CA 签发的证书对真实 CA 验签应失败")
		}

		serverCertPEM, serverKeyPEM, err := IssueNodeCert(realCACert, realKey, "server-node")
		if err != nil {
			t.Fatalf("签发服务端证书失败: %v", err)
		}
		serverCfg, err := TLSConfigFromPEM(serverCertPEM, serverKeyPEM, realCAPEM, true)
		if err != nil {
			t.Fatalf("服务端 TLS 配置失败: %v", err)
		}
		// 客户端证书由伪造 CA 签发（复用上面已签发的证书与私钥）。
		clientCfg, err := TLSConfigFromPEM(forgedCertPEM, forgedClientKeyPEM, realCAPEM, false)
		if err != nil {
			t.Fatalf("客户端 TLS 配置失败: %v", err)
		}
		clientCfg.ServerName = "localhost"

		addr, serverErr := runTLSEcho(t, serverCfg)
		conn, err := tls.Dial("tcp", addr, clientCfg)
		if err != nil {
			// TLS 1.2 下客户端握手阶段即失败，也算拒绝。
			t.Logf("伪造 CA 客户端证书被拒绝（符合预期）: %v", err)
			return
		}
		// TLS 1.3 下客户端握手可能先成功，服务端在握手后验证客户端证书；
		// 以服务端的拒绝为准。
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = conn.Write([]byte("ping"))
		_, _ = conn.Read(make([]byte, 4))
		select {
		case serr := <-serverErr:
			if serr == nil {
				t.Fatal("伪造 CA 签发的客户端证书应被服务端拒绝，服务端却接受")
			}
			t.Logf("伪造 CA 客户端证书被服务端拒绝（符合预期）: %v", serr)
		case <-time.After(5 * time.Second):
			t.Fatal("等待服务端拒绝结果超时")
		}
	})

	t.Run("伪造CA签发的服务端证书", func(t *testing.T) {
		forgedServerCertPEM, forgedServerKeyPEM, err := IssueNodeCert(forgedCACert, forgedKey, "server-node")
		if err != nil {
			t.Fatalf("签发伪造服务端证书失败: %v", err)
		}
		serverCfg, err := TLSConfigFromPEM(forgedServerCertPEM, forgedServerKeyPEM, realCAPEM, true)
		if err != nil {
			t.Fatalf("服务端 TLS 配置失败: %v", err)
		}
		clientCertPEM, clientKeyPEM, err := IssueNodeCert(realCACert, realKey, "client-node")
		if err != nil {
			t.Fatalf("签发客户端证书失败: %v", err)
		}
		clientCfg, err := TLSConfigFromPEM(clientCertPEM, clientKeyPEM, realCAPEM, false)
		if err != nil {
			t.Fatalf("客户端 TLS 配置失败: %v", err)
		}
		clientCfg.ServerName = "localhost"

		addr, _ := runTLSEcho(t, serverCfg)
		conn, err := tls.Dial("tcp", addr, clientCfg)
		if err == nil {
			_ = conn.Close()
			t.Fatal("伪造 CA 签发的服务端证书应被拒绝，握手却成功")
		}
		t.Logf("伪造 CA 服务端证书被拒绝（符合预期）: %v", err)
	})
}

func TestTLSMessageSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成签名私钥失败: %v", err)
	}
	msg := []byte(`{"type":"ping","height":123}`)
	sig, err := SignMessage(priv, msg)
	if err != nil {
		t.Fatalf("SignMessage 失败: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("签名为空")
	}
	// 往返：同一消息验签通过。
	ok, err := VerifyMessageSignature(&priv.PublicKey, msg, sig)
	if err != nil {
		t.Fatalf("VerifyMessageSignature 出错: %v", err)
	}
	if !ok {
		t.Fatal("正确签名验签应通过")
	}
	// 篡改消息：拒绝。
	ok, _ = VerifyMessageSignature(&priv.PublicKey, []byte(`{"type":"ping","height":124}`), sig)
	if ok {
		t.Fatal("篡改后的消息验签应失败")
	}
	// 篡改签名：拒绝。
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0x01
	ok, _ = VerifyMessageSignature(&priv.PublicKey, msg, tampered)
	if ok {
		t.Fatal("篡改后的签名验签应失败")
	}
	// 错误公钥：拒绝。
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成另一私钥失败: %v", err)
	}
	ok, _ = VerifyMessageSignature(&other.PublicKey, msg, sig)
	if ok {
		t.Fatal("错误公钥验签应失败")
	}
	// 空签名：报错而非 panic。
	if _, err := VerifyMessageSignature(&priv.PublicKey, msg, nil); err == nil {
		t.Fatal("空签名应返回错误")
	}
}

func TestTLSMessageEnvelope(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成签名私钥失败: %v", err)
	}
	msg := []byte("hello-hundun")
	auth, err := SignEnvelope(priv, "node-1", msg)
	if err != nil {
		t.Fatalf("SignEnvelope 失败: %v", err)
	}
	if auth.NodeID != "node-1" {
		t.Fatalf("MessageAuth.NodeID = %q，期望 node-1", auth.NodeID)
	}
	ok, err := VerifyEnvelope(&priv.PublicKey, msg, auth)
	if err != nil {
		t.Fatalf("VerifyEnvelope 出错: %v", err)
	}
	if !ok {
		t.Fatal("信封验签应通过")
	}
	// Sign 别名与 SignEnvelope 行为一致。
	auth2, err := Sign(priv, "node-1", msg)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}
	ok, err = VerifyEnvelope(&priv.PublicKey, msg, auth2)
	if err != nil || !ok {
		t.Fatalf("Sign 别名信封验签应通过，ok=%v err=%v", ok, err)
	}
	// 篡改消息：拒绝。
	ok, _ = VerifyEnvelope(&priv.PublicKey, []byte("hello-hundun!"), auth)
	if ok {
		t.Fatal("篡改消息后信封验签应失败")
	}
	// 空 nodeID：报错。
	if _, err := SignEnvelope(priv, "", msg); err == nil {
		t.Fatal("空 nodeID 应返回错误")
	}
}

func TestTLSConfigErrors(t *testing.T) {
	if _, err := TLSConfigFromPEM(nil, []byte("k"), []byte("ca"), true); err == nil {
		t.Fatal("空证书 PEM 应返回错误")
	}
	if _, err := TLSConfigFromPEM([]byte("c"), nil, []byte("ca"), true); err == nil {
		t.Fatal("空私钥 PEM 应返回错误")
	}
	if _, err := TLSConfigFromPEM([]byte("c"), []byte("k"), nil, true); err == nil {
		t.Fatal("空 CA PEM 应返回错误")
	}
	if _, err := TLSConfigFromFiles("/nonexistent/cert.pem", "/nonexistent/key.pem", "/nonexistent/ca.pem"); err == nil {
		t.Fatal("不存在的文件应返回错误")
	}
	// 空 CA 内容：AppendCertsFromPEM 失败。
	_, _, caCert, caKey, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA 失败: %v", err)
	}
	certPEM, keyPEM, err := IssueNodeCert(caCert, caKey.(*ecdsa.PrivateKey), "node-1")
	if err != nil {
		t.Fatalf("IssueNodeCert 失败: %v", err)
	}
	if _, err := TLSConfigFromPEM(certPEM, keyPEM, []byte("not-a-cert"), true); err == nil {
		t.Fatal("非法 CA PEM 应返回错误")
	}
	// 参数校验。
	if _, _, err := IssueNodeCert(nil, caKey, "node-1"); err == nil {
		t.Fatal("空 CA 证书应返回错误")
	}
	if _, _, err := IssueNodeCert(caCert, nil, "node-1"); err == nil {
		t.Fatal("空 CA 私钥应返回错误")
	}
	if _, _, err := IssueNodeCert(caCert, caKey, ""); err == nil {
		t.Fatal("空 nodeID 应返回错误")
	}
}
