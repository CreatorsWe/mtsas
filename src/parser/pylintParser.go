package parser

import (
	"encoding/json"
	"fmt"
	"os"

	. "github.com/mtsas/common"

	"github.com/mtsas/cweMapper"
)

type PylintParser struct {
	parseFilePath string
	pylintMapper  *cweMapper.PylintMapper
}

func NewPylintParser(parseFilePath string, pylintCweMappingPath string) (*PylintParser, error) {
	// 检查 pylintCweMappingPath 是否为空和是否存在
	if pylintCweMappingPath == "" {
		return nil, fmt.Errorf("pylintCweMappingPath is empty")
	}
	if _, err := os.Stat(pylintCweMappingPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("pylintCweMappingPath does not exist")
	}
	ConsoleLogger.Debug(fmt.Sprintf("pylintCweMappingPath: %s", pylintCweMappingPath))
	pylintMapper := cweMapper.NewPylintMapper(pylintCweMappingPath)
	err := pylintMapper.LoadMapping()
	if err != nil {
		return nil, err
	}
	return &PylintParser{
		parseFilePath: parseFilePath,
		pylintMapper:  pylintMapper,
	}, nil
}

// PylintIssue 定义 Pylint JSON 报告的结构体
type PylintIssue struct {
	Type      string      `json:"type"`
	Module    string      `json:"module"`
	Obj       string      `json:"obj"` // 类/函数名，补充模块路径
	Line      NullableInt `json:"line"`
	Column    NullableInt `json:"column"`
	EndLine   NullableInt `json:"endLine"`
	EndColumn NullableInt `json:"endColumn"`
	Path      string      `json:"path"`
	Symbol    string      `json:"symbol"`
	Message   string      `json:"message"`
	MessageID string      `json:"message-id"`
}

// 将 pylint type 字段映射为 unified severity_level 字段
func pylint_getSeverityLevel(typeField string) SeverityLevel {
	switch typeField {
	case "error":
		return SeverityLevelHigh
	case "warning":
		return SeverityLevelMedium
	case "refactor":
		return SeverityLevelLow
	case "convention":
		return SeverityLevelLow
	case "fatal":
		return SeverityLevelUnknown
	default:
		return SeverityLevelUnknown
	}
}

// 将 pylint type 字段映射成 unified confidence_level 字段
func pylint_getConfidenceLevel(typeField string) ConfidenceLevel {
	switch typeField {
	case "error":
		return ConfidenceLevelHigh
	case "warning":
		return ConfidenceLevelMedium
	case "refactor":
		return ConfidenceLevelLow
	case "convention":
		return ConfidenceLevelLow
	case "fatal":
		return ConfidenceLevelLow
	default:
		return ConfidenceLevelLow
	}
}

// 获取 Module 字段
func pylint_getModule(module string, obj string) string {
	fullModule := module
	if obj != "" {
		fullModule = fmt.Sprintf("%s.%s", module, obj)
	}
	return fullModule
}

// 获取 CWE 字段
func (p *PylintParser) getCWEID(messageID string) (string, error) {
	result, err := p.pylintMapper.QueryRecord(messageID)
	if err != nil {
		return "", err
	}
	return result, nil
}

// ConvertPylintIssueToUnified 将PylintIssue转换为统一漏洞结构体
func (p *PylintParser) convertPylintIssueToUnified(issue PylintIssue) (UnifiedVulnerability, error) {
	cweID, err := p.getCWEID(issue.MessageID)
	if err != nil {
		return UnifiedVulnerability{}, err
	}

	return UnifiedVulnerability{
		Tool:         "pylint", // 固定为pylint
		WarningID:    issue.MessageID,
		WarningType:  issue.Symbol,
		Category:     issue.Type,
		ShortMessage: issue.Message,
		FilePath:     issue.Path,
		Range: Range{
			StartLine:   issue.Line,
			EndLine:     issue.EndLine,
			StartColumn: issue.Column,
			EndColumn:   issue.EndColumn,
		},
		CWEID:           cweID,
		SeverityLevel:   pylint_getSeverityLevel(issue.Type),
		ConfidenceLevel: pylint_getConfidenceLevel(issue.Type),
		Module:          pylint_getModule(issue.Module, issue.Obj),
	}, nil
}

func readJsonToPylintIssues(path string) ([]PylintIssue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		err_msg := fmt.Errorf("读取文件失败: %v\n", err)
		return nil, err_msg
	}

	// 2. 解析Pylint JSON为[]PylintIssue
	var pylintIssues []PylintIssue
	err = json.Unmarshal(data, &pylintIssues)
	if err != nil {
		err_msg := fmt.Errorf("解析JSON失败: %v\n", err)
		return nil, err_msg
	}

	return pylintIssues, nil
}

func (p *PylintParser) Parse() ([]UnifiedVulnerability, error) {
	pylintIssues, err := readJsonToPylintIssues(p.parseFilePath)
	if err != nil {
		return nil, err
	}

	// 加载数据库
	if err := p.pylintMapper.LoadMapping(); err != nil {
		return nil, err
	}

	// 3. 转换为统一格式
	var unifiedVuls []UnifiedVulnerability
	for _, issue := range pylintIssues {
		unifiedVul, err := p.convertPylintIssueToUnified(issue)
		if err != nil {
			return nil, err
		}
		unifiedVuls = append(unifiedVuls, unifiedVul)
	}
	return unifiedVuls, nil
}

func (p *PylintParser) GetName() string {
	return "pylintParser"
}
