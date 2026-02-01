package common

import (
	"github.com/mtsas/logger"
)

// 全局参数
// var (
// 	OutputDir         string                // .mtsas 目录路径，不检查是否存在
// 	ProjectName       string                // 配置文件路径，toml 格式，必须确保存在
// 	OutputFormat      string                // 输出文件格式:"json", "csv",否则默认为 "",不输出文件
// 	ScanDir           string                // 扫描目录路径
// 	ScanFiles         map[Language][]string // 带扫描文件语言和文件路径集合的映射
// 	ProjectConfigFile string                // 项目配置文件，toml 格式，简化命令行的繁琐
// 	MtsasConfig       string                // MTSAS 配置文件，toml 格式,记录各种工具的信息,硬编码在家目录
// 	IsQuiet           bool                  // 是否静默模式(控制台不输出除 Error 外的任何信息)
// )

var ConsoleLogger = logger.NewConsoleLogger()

// var FileManager = fileManager.NewFileManager(&OutputDir, &ProjectName)
