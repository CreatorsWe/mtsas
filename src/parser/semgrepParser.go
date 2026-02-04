package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	. "github.com/mtsas/common"
)

type SemgrepParser struct {
	parseFilePath string
}

func NewSemgrepParser(parseFilePath string) *SemgrepParser {
	return &SemgrepParser{
		parseFilePath: parseFilePath,
	}
}

// SemgrepIssue 定义 Semgrep JSON 报告的结构体
type semgrepIssues struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"start"`
	End struct {
		Line   int `json:"line"`
		Col    int `json:"col"`
		Offset int `json:"offset"`
	} `json:"end"`
	Extra struct {
		Message  string `json:"message"`
		Fix      string `json:"fix,omitempty"`
		Metadata struct {
			FunctionalCategories []string `json:"functional-categories,omitempty"`
			Owasp                []string `json:"owasp,omitempty"`
			Cwe                  []string `json:"cwe,omitempty"`
			SourceRuleURL        string   `json:"source-rule-url,omitempty"`
			Category             string   `json:"category,omitempty"`
			Technology           []string `json:"technology,omitempty"`
			References           []string `json:"references,omitempty"`
			Subcategory          []string `json:"subcategory,omitempty"`
			Likelihood           string   `json:"likelihood,omitempty"`
			Impact               string   `json:"impact,omitempty"`
			Confidence           string   `json:"confidence,omitempty"`
			License              string   `json:"license,omitempty"`
			VulnerabilityClass   []string `json:"vulnerability_class,omitempty"`
			Source               string   `json:"source,omitempty"`
			Shortlink            string   `json:"shortlink,omitempty"`
			Cwe2022Top25         bool     `json:"cwe2022-top25,omitempty"`
			Cwe2021Top25         bool     `json:"cwe2021-top25,omitempty"`
		} `json:"metadata"`
		Severity        string `json:"severity"`
		Fingerprint     string `json:"fingerprint"`
		Lines           string `json:"lines"`
		ValidationState string `json:"validation_state"`
		EngineKind      string `json:"engine_kind"`
	} `json:"extra"`
}

// SemgrepReport 完整的 Semgrep 报告结构
type o_semgrepIssues struct {
	Semgrepissues []semgrepIssues `json:"results"`
}

// 将 Semgrep severity 字段映射为 unified severity_level 字段
func (s *SemgrepParser) getSeverityLevel(severity string) SeverityLevel {
	switch strings.ToUpper(severity) {
	case "ERROR":
		return SeverityLevelHigh
	case "WARNING":
		return SeverityLevelMedium
	case "INFO":
		return SeverityLevelLow
	default:
		return SeverityLevelUnknown
	}
}

// 将 Semgrep confidence 字段映射成 unified confidence_level 字段
func (s *SemgrepParser) getConfidenceLevel(confidence string) ConfidenceLevel {
	switch strings.ToUpper(confidence) {
	case "HIGH":
		return ConfidenceLevelHigh
	case "MEDIUM":
		return ConfidenceLevelMedium
	case "LOW":
		return ConfidenceLevelLow
	default:
		return ConfidenceLevelLow // 默认中等置信度
	}
}

// 获取 Module 字段 - 从文件路径和检查ID中提取模块信息
// func (s *SemgrepParser) getModule(filePath string, checkID string) string {
// }

// 从 cwe 数组获取 CWE 字段
func (s *SemgrepParser) getCWEID(cweList []string) string {
	if len(cweList) == 0 {
		return "" // 返回空字符串，序列化时会变成null
	}

	// 取第一个CWE ID
	cwe := cweList[0]

	// 提取CWE编号，格式可能是 "CWE-328: Use of Weak Hash"
	if strings.HasPrefix(cwe, "CWE-") {
		// 提取CWE-后面的数字部分
		parts := strings.Split(cwe, " ")
		if len(parts) > 0 {
			cweID := strings.TrimPrefix(parts[0], "CWE-")
			// 去掉可能的分隔符
			cweID = strings.TrimSuffix(cweID, ":")
			return cweID
		}
	}

	return cwe
}

// ConvertSemgrepIssueToUnified 将 SemgrepIssue 转换为统一漏洞结构体
func (s *SemgrepParser) convertIssuesToUnified(issue semgrepIssues) UnifiedVulnerability {
	// 构建Range结构
	vulnRange := Range{
		StartLine:   NullableInt(issue.Start.Line),
		EndLine:     NullableInt(issue.End.Line),
		StartColumn: NullableInt(issue.Start.Col),
		EndColumn:   NullableInt(issue.End.Col),
	}

	// 获取严重级别和置信度
	severityLevel := s.getSeverityLevel(issue.Extra.Severity)
	confidenceLevel := s.getConfidenceLevel(issue.Extra.Metadata.Confidence)

	// 获取CWE ID
	cweID := s.getCWEID(issue.Extra.Metadata.Cwe)

	// 获取模块信息
	// module := p.getModule(issue.Path, issue.CheckID)

	return UnifiedVulnerability{
		Tool:            "semgrep",
		WarningID:       issue.CheckID,
		Category:        issue.Extra.Metadata.Category,
		ShortMessage:    issue.Extra.Message,
		CWEID:           cweID,
		FilePath:        issue.Path,
		Module:          "",
		Range:           vulnRange,
		SeverityLevel:   severityLevel,
		ConfidenceLevel: confidenceLevel,
	}
}

// readJsonToSemgrepReport 读取JSON文件并解析为SemgrepReport
func (s *SemgrepParser) readReportToIssues(path string) ([]semgrepIssues, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	var report o_semgrepIssues
	err = json.Unmarshal(data, &report)
	if err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v", err)
	}

	return report.Semgrepissues, nil
}

func (s *SemgrepParser) Parse() ([]UnifiedVulnerability, error) {
	// 读取并解析Semgrep报告
	report, err := s.readReportToIssues(s.parseFilePath)
	if err != nil {
		return nil, fmt.Errorf("解析Semgrep报告失败: %v", err)
	}

	// 转换每个结果为统一格式
	var unifiedVulns []UnifiedVulnerability
	for _, issue := range report {
		unifiedVuln := s.convertIssuesToUnified(issue)
		unifiedVulns = append(unifiedVulns, unifiedVuln)
	}

	return unifiedVulns, nil
}

func (p *SemgrepParser) GetName() string {
	return "semgrepParser"
}

func (s *SemgrepParser) ParseToFile(output_file string) error {
	// 读取并解析Semgrep报告
	report, err := s.readReportToIssues(s.parseFilePath)
	if err != nil {
		return err
	}

	// 转换每个结果为统一格式
	var unifiedVulns []UnifiedVulnerability
	for _, issue := range report {
		unifiedVuln := s.convertIssuesToUnified(issue)
		unifiedVulns = append(unifiedVulns, unifiedVuln)
	}

	if err := StructsToJSONFile(unifiedVulns, output_file); err != nil {
		return err
	}
	return nil
}
