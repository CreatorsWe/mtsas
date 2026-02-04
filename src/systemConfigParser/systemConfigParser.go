package systemConfigParser

import (
	"fmt"
	"os"
	"strings"

	. "github.com/mtsas/common"
	"github.com/pelletier/go-toml/v2"
)

// 将结构体改为非导出（首字母小写）
type tool struct {
	Name               string   `toml:"name"`
	Version            string   `toml:"version"`
	Path               string   `toml:"path"`
	SupportedLanguages []string `toml:"supportedLanguages"`
	Args               []string `toml:"args"`
}

func (t *tool) checkNotEmpty() error {
	if t.Name == "" || t.Version == "" || len(t.SupportedLanguages) == 0 || len(t.Args) == 0 {
		return fmt.Errorf("系统配置文件工具信息 name、version、supportedLanguages、args 不能为空")
	}
	return nil
}

// cweMapping 结构体定义
type _cweMapping struct {
	Path string `toml:"path"`
	Maps []struct {
		ToolName  string `toml:"toolName"`
		TableName string `toml:"tableName"`
	} `toml:"maps"`
}

type CWEMapping struct {
	Path string
	Maps map[string]string
}

// 添加构造函数
func NewCWEMapping() CWEMapping {
	return CWEMapping{
		Maps: make(map[string]string),
	}
}

// SystemConfigResult 结构体定义
type SystemConfigResult struct {
	Tools      map[string]ToolInfo `toml:"-"` // 不使用 toml 标签，手动解析
	CweMapping CWEMapping          `toml:"-"` // CWE 映射配置
}

// SystemConfigParser 结构体定义
type SystemConfigParser struct {
	systemConfigPath string
}

func NewSystemConfigParser() *SystemConfigParser {
	return &SystemConfigParser{
		systemConfigPath: `D:\Code\Project\Multi-tool_Static_Analysis_System_refactor\mtsas.conf.toml`,
	}
}

func (s *SystemConfigParser) Parse() (*SystemConfigResult, error) {
	// 检查配置文件是否存在
	if _, err := os.Stat(s.systemConfigPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", s.systemConfigPath)
	}

	// 读取配置文件内容
	content, err := os.ReadFile(s.systemConfigPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析 TOML 配置
	result, err := s.parseTOMLContent(content)
	if err != nil {
		return nil, fmt.Errorf("解析 TOML 配置失败: %v", err)
	}

	return result, nil
}

// parseTOMLContent 解析 TOML 内容
func (s *SystemConfigParser) parseTOMLContent(content []byte) (*SystemConfigResult, error) {
	result := &SystemConfigResult{
		Tools:      make(map[string]ToolInfo),
		CweMapping: NewCWEMapping(),
	}

	// 使用新的结构来解析 TOML
	var config struct {
		// 工具配置
		Pylint   *tool `toml:"pylint"`
		Bandit   *tool `toml:"bandit"`
		Horusec  *tool `toml:"horusec"`
		Semgrep  *tool `toml:"semgrep"`
		Insider  *tool `toml:"insider"`
		Cppcheck *tool `toml:"cppcheck"`

		// CWE 映射配置 - 新的扁平结构
		CweMapping *_cweMapping `toml:"cwe_mapping"`
	}

	if err := toml.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("解析 TOML 配置失败: %v", err)
	}

	// 解析工具配置
	if err := s.parseTools(&config, result); err != nil {
		return nil, err
	}

	// 解析 CWE 映射配置
	if err := s.parseCweMapping(config.CweMapping, result); err != nil {
		return nil, err
	}

	return result, nil
}

// parseTools 解析所有工具配置
func (s *SystemConfigParser) parseTools(config *struct {
	Pylint     *tool        `toml:"pylint"`
	Bandit     *tool        `toml:"bandit"`
	Horusec    *tool        `toml:"horusec"`
	Semgrep    *tool        `toml:"semgrep"`
	Insider    *tool        `toml:"insider"`
	Cppcheck   *tool        `toml:"cppcheck"`
	CweMapping *_cweMapping `toml:"cwe_mapping"`
}, result *SystemConfigResult) error {

	// 解析每个工具
	tools := map[string]*tool{
		"pylint":   config.Pylint,
		"bandit":   config.Bandit,
		"horusec":  config.Horusec,
		"semgrep":  config.Semgrep,
		"insider":  config.Insider,
		"cppcheck": config.Cppcheck,
	}

	for toolName, toolConfig := range tools {
		if toolConfig == nil {
			continue // 跳过未配置的工具
		}

		if err := s.parseSingleTool(toolName, toolConfig, result); err != nil {
			return err
		}
	}

	return nil
}

// parseCweMapping 解析 CWE 映射配置
func (s *SystemConfigParser) parseCweMapping(cweConfig *_cweMapping, result *SystemConfigResult) error {
	if cweConfig == nil {
		return nil // 没有 CWE 映射配置
	}

	// 检查路径是否存在
	if cweConfig.Path == "" {
		return fmt.Errorf("CWE 映射数据库路径为空")
	}

	result.CweMapping.Path = cweConfig.Path

	// 将映射信息存储到结果中
	for _, mapping := range cweConfig.Maps {
		if mapping.ToolName != "" && mapping.TableName != "" {
			// 存储格式: "toolName:tableName"
			result.CweMapping.Maps[mapping.ToolName] = mapping.TableName
		}
	}

	return nil
}

// parseSingleTool 解析单个工具配置
func (s *SystemConfigParser) parseSingleTool(toolName string, toolConfig *tool, result *SystemConfigResult) error {
	if toolConfig == nil {
		return fmt.Errorf("工具 %s 配置为空", toolName)
	}

	// 检查必需字段
	if err := toolConfig.checkNotEmpty(); err != nil {
		return fmt.Errorf("工具 %s 配置不完整: %v", toolName, err)
	}

	// 将 supportedLanguages 字符串转换为 Language 类型
	supportedLangs := make([]Language, len(toolConfig.SupportedLanguages))
	for i, langStr := range toolConfig.SupportedLanguages {
		lang := s.mapStringToLanguage(langStr)
		supportedLangs[i] = lang
	}

	// 构建命令
	var command string
	if toolConfig.Path == "" {
		command = strings.Join(append([]string{toolConfig.Name}, toolConfig.Args...), " ")
	} else {
		command = strings.Join(append([]string{toolConfig.Path}, toolConfig.Args...), " ")
	}

	// 创建 ToolInfo 对象
	toolInfo := ToolInfo{
		Name:               toolConfig.Name,
		Version:            toolConfig.Version,
		Path:               toolConfig.Path,
		Command:            command,
		SupportedLanguages: supportedLangs,
	}

	// 添加到结果中
	result.Tools[toolName] = toolInfo

	return nil
}

// mapStringToLanguage 将字符串映射到 Language 枚举
func (s *SystemConfigParser) mapStringToLanguage(langStr string) Language {
	switch strings.ToLower(langStr) {
	case "python":
		return LanguagePython
	case "java":
		return LanguageJava
	case "c":
		return LanguageC
	case "c++", "cpp":
		return LanguageCpp
	case "javascript", "js":
		return LanguageJs
	case "typescript", "ts":
		return LanguageTs
	case "go", "golang":
		return LanguageGo
	case "ruby", "rb":
		return LanguageRuby
	case "kotlin", "kt":
		return LanguageKotlin
	case "rust", "rs":
		return LanguageRust
	case "c#", "csharp":
		return LanguageCsharp
	default:
		return LanguageUnknown
	}
}

// GetCweMapping 获取指定工具的 CWE 映射信息
func (s *SystemConfigParser) GetCweMapping(toolName string) (string, string, error) {
	result, err := s.Parse()
	if err != nil {
		return "", "", err
	}

	mapping, exists := result.CweMapping.Maps[toolName]
	if !exists {
		return "", "", fmt.Errorf("未找到工具 %s 的 CWE 映射配置", toolName)
	}

	// 解析映射格式: "path:tableName"
	parts := strings.Split(mapping, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("CWE 映射格式错误: %s", mapping)
	}

	return parts[0], parts[1], nil
}

// GetToolNames 获取所有工具名称
func (s *SystemConfigParser) GetToolNames() ([]string, error) {
	result, err := s.Parse()
	if err != nil {
		return nil, err
	}

	names := make([]string, 0, len(result.Tools))
	for name := range result.Tools {
		names = append(names, name)
	}

	return names, nil
}

// GetSupportedLanguages 获取指定工具支持的语言
func (s *SystemConfigParser) GetSupportedLanguages(toolName string) ([]Language, error) {
	result, err := s.Parse()
	if err != nil {
		return nil, err
	}

	tool, exists := result.Tools[toolName]
	if !exists {
		return nil, fmt.Errorf("工具 %s 不存在", toolName)
	}

	return tool.SupportedLanguages, nil
}
