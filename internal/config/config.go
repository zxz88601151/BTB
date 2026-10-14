// Package config 定义节点运行所需的配置项。
// 骨架阶段先用硬编码默认值 + 简单的可选覆盖，后续可扩展为读取 YAML/TOML 配置文件或命令行参数（推荐用 spf13/cobra + viper）。
package config

// NodeConfig 单个节点的运行配置。
type NodeConfig struct {
	ListenAddr   string   // 本节点监听地址，例如 ":6688"
	SeedPeers    []string // 启动时主动连接的种子节点列表
	MinerEnabled bool     // 是否开启本地CPU挖矿
	MinerAddress string   // 挖矿奖励接收地址（矿工公钥哈希的十六进制字符串）
	DataDir      string   // 区块数据、钱包文件的存储目录

	// 钱包口令文件（P2）：只走 --wallet-password-file，文件须为 0600 权限；
	// 为空表示钱包文件不加密（开发调试用），生产必须配口令文件。
	WalletPasswordFile string

	// mTLS（P4）：默认关闭（本地开发兼容）；生产设 TLSEnabled=true 并配齐三个文件。
	TLSEnabled  bool
	TLSCertFile string
	TLSKeyFile  string
	TLSCAFile   string
}

// DefaultConfig 返回一份适合本地单机测试的默认配置。
func DefaultConfig() NodeConfig {
	return NodeConfig{
		ListenAddr:   ":6688",
		SeedPeers:    []string{},
		MinerEnabled: true,
		DataDir:      "./data",
	}
}
