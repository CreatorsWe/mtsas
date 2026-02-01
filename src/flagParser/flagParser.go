package flagParser

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	. "github.com/mtsas/common"
)

type FlagParser struct{}

func NewFlagParser() *FlagParser {
	return &FlagParser{}
}

func (fp *FlagParser) ParseFlags() (*ScanFlag, error) {
	// 定义命令行参数
	var (
		projectName   = flag.String("name", "", "项目名称（必须）")
		outputDir     = flag.String("output-dir", ".", "输出目录路径，默认为 .mtsas")
		outputFormat  = flag.String("format", "", "输出文件格式: json, csv")
		projectConfig = flag.String("config", "", "项目配置文件路径（toml 格式）")
		isQuiet       = flag.Bool("quiet", false, "静默模式，控制台不输出除 Error 外的任何信息")
		excludeDirs   = flag.String("exclude", "", "要排除的目录，多个目录用逗号分隔")
	)

	// 自定义用法信息
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "用法: %s [选项] <scan_dir>\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "scan_dir: 要扫描的目录或文件路径（必须）\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "选项:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "\n示例:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  %s --name myproject --format json /path/to/project\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "  %s --name myproject --config config.toml --quiet /path/to/src\n", os.Args[0])
	}

	// 解析命令行参数
	flag.Parse()

	// 验证必须参数
	if *projectName == "" {
		return nil, fmt.Errorf("--name 参数必须提供")
	}

	// 获取位置参数（scan_dir）
	args := flag.Args()
	if len(args) == 0 {
		return nil, fmt.Errorf("必须提供扫描目录 scan_dir")
	}

	scanDir := args[0]

	// 验证扫描路径是否存在
	fileInfo, err := os.Stat(scanDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("错误: 扫描路径不存在: %s", scanDir)
		}
		return nil, fmt.Errorf("错误: 无法访问扫描路径: %v", err)
	}

	// 确报是目录
	if !fileInfo.IsDir() {
		return nil, fmt.Errorf("错误: 扫描路径必须是目录: %s", scanDir)
	}

	// 处理排除目录
	var excludedDirs []string
	if *excludeDirs != "" {
		excludedDirs = splitExcludeDirs(*excludeDirs)
	}

	// 获取扫描文件
	scanFiles, err := getScanFiles(scanDir, excludedDirs)
	if err != nil {
		return nil, fmt.Errorf("错误: 获取扫描文件失败: %v", err)
	}

	// 验证是否找到了可扫描的文件
	totalFiles := 0
	for _, files := range scanFiles {
		totalFiles += len(files)
	}
	if totalFiles == 0 {
		return nil, fmt.Errorf("错误: 在路径 %s 中未找到支持扫描的文件", scanDir)
	}

	// 构建输出目录的绝对路径
	absOutputDir, err := filepath.Abs(*outputDir)
	if err != nil {
		return nil, fmt.Errorf("错误: 无法解析输出目录路径: %v", err)
	}

	// 构建 Flag 对象
	flagObj := &ScanFlag{
		ProjectName:   *projectName,
		OutputDir:     absOutputDir,
		OutputFormat:  *outputFormat,
		ScanDir:       scanDir,
		ScanFiles:     scanFiles,
		Exclude:       excludedDirs,
		ProjectConfig: *projectConfig,
		IsQuiet:       *isQuiet,
	}

	return flagObj, nil
}

// splitExcludeDirs 将逗号分隔的排除目录字符串分割为切片
func splitExcludeDirs(excludeStr string) []string {
	var result []string
	// 简单的分割逻辑，可以根据需要增强
	// 这里使用简单的字符串分割，不考虑引号等复杂情况
	// 如果需要支持带空格的目录名，可以增强此函数
	dirs := splitByComma(excludeStr)
	for _, dir := range dirs {
		if dir != "" {
			result = append(result, dir)
		}
	}
	return result
}

// splitByComma 按逗号分割字符串，处理基本的空格
func splitByComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			// 提取字段并去除首尾空格
			field := trimSpace(s[start:i])
			if field != "" {
				result = append(result, field)
			}
			start = i + 1
		}
	}
	// 添加最后一个字段
	if start < len(s) {
		field := trimSpace(s[start:])
		if field != "" {
			result = append(result, field)
		}
	}
	return result
}

// trimSpace 去除字符串首尾空格
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
