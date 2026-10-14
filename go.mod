module hundun

go 1.22

// 依赖说明：骨架阶段为零依赖；决策项实施后引入：
//   - Pebble（P1 持久化，纯 Go 无 CGO，v1.1.5，Go 1.22 可装的最新 v1 线）
//   - btcec/v2 + x/crypto/ripemd160（P3 secp256k1 + Base58Check 地址）
//   - go-bip39 / go-bip32（P2 BIP-39 助记词 + HD 派生，内嵌完整 2048 词表）
//   - x/crypto/argon2（P2 口令加密密钥派生）
// 版本已 pin 到 Go 1.22 兼容版，禁止直接 go get @latest（会把 go 指令抬到 1.26+）。

require (
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/cockroachdb/pebble v1.1.5
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/tyler-smith/go-bip32 v1.0.0
	github.com/tyler-smith/go-bip39 v1.1.0
	golang.org/x/crypto v0.17.0
)

require (
	github.com/DataDog/zstd v1.4.5 // indirect
	github.com/FactomProject/basen v0.0.0-20150613233007-fe3947df716e // indirect
	github.com/FactomProject/btcutilecc v0.0.0-20130527213604-d3a63a5752ec // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/cockroachdb/errors v1.11.3 // indirect
	github.com/cockroachdb/fifo v0.0.0-20240606204812-0bbfbd93a7ce // indirect
	github.com/cockroachdb/logtags v0.0.0-20230118201751-21c54148d20b // indirect
	github.com/cockroachdb/redact v1.1.5 // indirect
	github.com/cockroachdb/tokenbucket v0.0.0-20230807174530-cc333fc44b06 // indirect
	github.com/getsentry/sentry-go v0.27.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/klauspost/compress v1.16.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.15.0 // indirect
	github.com/prometheus/client_model v0.3.0 // indirect
	github.com/prometheus/common v0.42.0 // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	golang.org/x/exp v0.0.0-20230626212559-97b1e661b5df // indirect
	golang.org/x/sys v0.18.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/protobuf v1.33.0 // indirect
)
