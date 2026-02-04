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

func (fp *FlagParser) ParseFlags() (interface{}, error) {
	if len(os.Args) < 2 {
		return nil, fmt.Errorf("必须提供子命令: scan, visual 或 map")
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "scan":
		return fp.parseScanFlags()
	case "visual":
		return fp.parseVisualFlags()
	case "map":
		return fp.parseMapFlags()
	default:
		return nil, fmt.Errorf("未知子命令: %s，支持的命令: scan, visual, map", subcommand)
	}
}

// parseScanFlags 处理 mtsas scan 子命令
func (fp *FlagParser) parseScanFlags() (*ScanFlag, error) {
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)

	// 定义 scan 子命令的参数
	var (
		projectName   = scanCmd.String("name", "", "项目名称（必须）")
		outputDir     = scanCmd.String("output-dir", ".", "输出目录路径，默认为 .mtsas")
		outputFormat  = scanCmd.String("format", "", "输出文件格式: json, csv")
		projectConfig = scanCmd.String("config", "", "项目配置文件路径（toml 格式）")
		isQuiet       = scanCmd.Bool("quiet", false, "静默模式，控制台不输出除 Error 外的任何信息")
		excludeDirs   = scanCmd.String("exclude", "", "要排除的目录，多个目录用逗号分隔")
	)

	// 自定义用法信息
	scanCmd.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "用法: %s scan [选项] <scan_dir>\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "scan_dir: 要扫描的目录或文件路径（必须）\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "选项:\n")
		scanCmd.PrintDefaults()
	}

	// 解析 scan 子命令参数
	if err := scanCmd.Parse(os.Args[2:]); err != nil {
		return nil, err
	}

	// 验证必须参数
	if *projectName == "" {
		return nil, fmt.Errorf("--name 参数必须提供")
	}

	// 获取位置参数（scan_dir）
	args := scanCmd.Args()
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

	// 构建 ScanFlag 对象
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

// parseVisualFlags 处理 mtsas visual 子命令
func (fp *FlagParser) parseVisualFlags() (*VisualFlag, error) {
	visualCmd := flag.NewFlagSet("visual", flag.ExitOnError)

	// 定义 visual 子命令的参数
	var (
		outputDir = visualCmd.String("output-dir", ".", " .mtsas 目录，默认为 .")
		name      = visualCmd.String("name", "", "项目名称（必须）")
	)

	// 自定义用法信息
	visualCmd.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "用法: %s visual [选项]\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "选项:\n")
		visualCmd.PrintDefaults()
	}

	// 解析 visual 子命令参数
	if err := visualCmd.Parse(os.Args[2:]); err != nil {
		return nil, err
	}

	// 验证必须参数
	if *name == "" {
		return nil, fmt.Errorf("--name 参数必须提供")
	}

	// 构建输出目录的绝对路径
	absOutputDir, err := filepath.Abs(*outputDir)
	if err != nil {
		return nil, fmt.Errorf("错误: 无法解析输出目录路径: %v", err)
	}

	// 构建 VisualFlag 对象
	flagObj := &VisualFlag{
		ProjectName: *name,
		OutputDir:   absOutputDir,
	}

	return flagObj, nil
}

// parseMapFlags 处理 mtsas map 子命令
func (fp *FlagParser) parseMapFlags() (*MapFlag, error) {
	mapCmd := flag.NewFlagSet("map", flag.ExitOnError)

	// 自定义用法信息
	mapCmd.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "用法: %s map\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "可视化cwe预映射表\n\n")
	}

	// 解析 map 子命令参数
	if err := mapCmd.Parse(os.Args[2:]); err != nil {
		return nil, err
	}

	// 检查是否有额外的参数
	if len(mapCmd.Args()) > 0 {
		return nil, fmt.Errorf("map 子命令不需要额外参数")
	}

	// 构建 MapFlag 对象
	return &MapFlag{}, nil
}

// 原有的辅助函数保持不变
func splitExcludeDirs(excludeStr string) []string {
	var result []string
	dirs := splitByComma(excludeStr)
	for _, dir := range dirs {
		if dir != "" {
			result = append(result, dir)
		}
	}
	return result
}

func splitByComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			field := trimSpace(s[start:i])
			if field != "" {
				result = append(result, field)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		field := trimSpace(s[start:])
		if field != "" {
			result = append(result, field)
		}
	}
	return result
}

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
