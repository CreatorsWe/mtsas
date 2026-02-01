package systemConfigParser

import (
	"fmt"
	"os"
	"strings"

	. "github.com/mtsas/common"
	"github.com/pelletier/go-toml/v2"
)

// tool 结构体定义，使用 toml 标签
type tool struct {
	Name               string   `toml:"name"`
	Version            string   `toml:"version"`
	Path               string   `toml:"path"`
	SupportedLanguages []string `toml:"supportedLanguages"`
	Args               []string `toml:"args"`
}

func (t *tool) checkNotEmpty() error {
	err := fmt.Errorf("系统配置文件工具信息 name、version、supportedLanguages、args 不能为空")
	if t.Name == "" || t.Version == "" || len(t.SupportedLanguages) == 0 || len(t.Args) == 0 {
		return err
	}
	return nil
}

// cweMapping 结构体定义
type cweMapping struct {
	Path string `toml:"path"`
}

// SystemConfigResult 结构体定义
type SystemConfigResult struct {
	Tools      map[string]ToolInfo `toml:"-"` // 不使用 toml 标签，手动解析
	CweMapping map[string]string   `toml:"-"` // CWE 映射配置
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
// parseTOMLContent 解析 TOML 内容
func (s *SystemConfigParser) parseTOMLContent(content []byte) (*SystemConfigResult, error) {
	result := &SystemConfigResult{
		Tools:      make(map[string]ToolInfo),
		CweMapping: make(map[string]string),
	}

	// 使用正确的嵌套结构来解析 TOML
	var config struct {
		// 工具配置
		Pylint   *tool `toml:"pylint"`
		Bandit   *tool `toml:"bandit"`
		Horusec  *tool `toml:"horusec"`
		Semgrep  *tool `toml:"semgrep"`
		Insider  *tool `toml:"insider"`
		Cppcheck *tool `toml:"cppcheck"`

		// CWE 映射配置 - 使用嵌套结构
		CweMapping struct {
			Pylint struct {
				Path string `toml:"path"`
			} `toml:"pylint"`
		} `toml:"cwe_mapping"`
	}

	if err := toml.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("解析 TOML 配置失败: %v", err)
	}

	// 解析工具配置
	if err := s.parseTools(&config, result); err != nil {
		return nil, err
	}

	// 解析 CWE 映射配置
	if config.CweMapping.Pylint.Path != "" {
		result.CweMapping["pylint"] = config.CweMapping.Pylint.Path
	}

	return result, nil
}

// parseTools 解析所有工具配置
func (s *SystemConfigParser) parseTools(config *struct {
	Pylint     *tool `toml:"pylint"`
	Bandit     *tool `toml:"bandit"`
	Horusec    *tool `toml:"horusec"`
	Semgrep    *tool `toml:"semgrep"`
	Insider    *tool `toml:"insider"`
	Cppcheck   *tool `toml:"cppcheck"`
	CweMapping struct {
		Pylint struct {
			Path string `toml:"path"`
		} `toml:"pylint"`
	} `toml:"cwe_mapping"`
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
	default:
		return LanguageUnknown
	}
}
