package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	. "github.com/mtsas/common"
)

type InsiderParser struct {
	parseFilePath string
}

func NewInsiderParser(parseFilePath string) *InsiderParser {
	return &InsiderParser{
		parseFilePath: parseFilePath,
	}
}

// InsiderReport 定义 Insider JSON 报告的结构体
type o_insiderIssues struct {
	Insiderissues []insiderIssues `json:"vulnerabilities"`
}

type insiderIssues struct {
	Cvss          float64 `json:"cvss"`
	Cwe           string  `json:"cwe"`
	Line          int     `json:"line"`
	Class         string  `json:"class"`
	VulID         string  `json:"vul_id"`
	Method        string  `json:"method"`
	Column        int     `json:"column"`
	Description   string  `json:"description"`
	ClassMessage  string  `json:"classMessage"`
	Recomendation string  `json:"recomendation,omitempty"`
}

// 将 CVSS 分数映射为 unified severity_level
func (i *InsiderParser) getSeverityLevel(cvss float64) SeverityLevel {
	switch {
	case cvss >= 9.0:
		return SeverityLevelCritical
	case cvss >= 7.0:
		return SeverityLevelHigh
	case cvss >= 4.0:
		return SeverityLevelMedium
	case cvss > 0:
		return SeverityLevelLow
	default:
		return SeverityLevelLow
	}
}

// 获取置信度级别（基于 CVSS 分数推断）
func (i *InsiderParser) getConfidenceLevel(cvss float64) ConfidenceLevel {
	switch {
	case cvss >= 7.0:
		return ConfidenceLevelHigh
	case cvss >= 4.0:
		return ConfidenceLevelMedium
	default:
		return ConfidenceLevelLow
	}
}

// 从 class 字段提取文件路径
func (i *InsiderParser) getFilePath(class string) string {
	// class 格式示例: "Demo1.java (16:20)"
	parts := strings.Split(class, " (")
	if len(parts) > 0 {
		return parts[0]
	}
	return class
}

// 从 CWE 字符串中提取 CWE ID
func (i *InsiderParser) getCWEID(cwe string) string {
	if strings.HasPrefix(cwe, "CWE-") {
		// 提取 CWE- 后面的数字部分
		parts := strings.Split(cwe, "-")
		if len(parts) >= 2 {
			// 去掉可能的后缀
			cweID := parts[1]
			if idx := strings.Index(cweID, " "); idx != -1 {
				cweID = cweID[:idx]
			}
			return cweID
		}
	}
	return cwe
}

// 获取模块名称
// func (p *InsiderParser) getModule(filePath string) string {
// 	if filePath == "" {
// 		return "unknown"
// 	}
// 	baseName := filepath.Base(filePath)
// 	return strings.TrimSuffix(baseName, filepath.Ext(baseName))
// }

func (i *InsiderParser) convertIssuesToUnified(issues insiderIssues) UnifiedVulnerability {
	// 构建 Range 结构
	vulnRange := Range{
		StartLine:   NullableInt(issues.Line),
		EndLine:     -1,
		StartColumn: NullableInt(issues.Column),
		EndColumn:   -1,
	}

	// 获取严重级别和置信度
	severityLevel := i.getSeverityLevel(issues.Cvss)
	confidenceLevel := i.getConfidenceLevel(issues.Cvss)

	// 提取文件路径和模块
	filePath := i.getFilePath(issues.Class)

	// 提取 CWE ID
	cweID := i.getCWEID(issues.Cwe)

	return UnifiedVulnerability{
		Tool:            "insider",
		WarningID:       issues.Cwe,
		Category:        "",
		ShortMessage:    issues.Description,
		CWEID:           cweID,
		FilePath:        filePath,
		Module:          "",
		Range:           vulnRange,
		SeverityLevel:   severityLevel,
		ConfidenceLevel: confidenceLevel,
	}
}

// readJSONToInsiderReport 读取 JSON 文件并解析为 InsiderReport
func (i *InsiderParser) readReportToIssues(path string) ([]insiderIssues, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	var report o_insiderIssues
	err = json.Unmarshal(data, &report)
	if err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v", err)
	}

	return report.Insiderissues, nil
}

// Parse 解析 Insider JSON 报告并返回 UnifiedVulnerability 列表
func (i *InsiderParser) Parse() ([]UnifiedVulnerability, error) {
	// 读取并解析 Insider 报告
	insiderissues, err := i.readReportToIssues(i.parseFilePath)
	if err != nil {
		return nil, fmt.Errorf("解析Insider报告失败: %v", err)
	}

	// 转换为统一格式
	var unifiedVulns []UnifiedVulnerability
	for _, vuln := range insiderissues {
		unifiedVuln := i.convertIssuesToUnified(vuln)
		unifiedVulns = append(unifiedVulns, unifiedVuln)
	}

	return unifiedVulns, nil
}

// GetName 获取解析器名称
func (p *InsiderParser) GetName() string {
	return "insiderParser"
}

func (i *InsiderParser) ParseToFile(output_file string) error {
	// 读取并解析 Insider 报告
	insiderissues, err := i.readReportToIssues(i.parseFilePath)
	if err != nil {
		return err
	}

	// 转换为统一格式
	var unifiedVulns []UnifiedVulnerability
	for _, vuln := range insiderissues {
		unifiedVuln := i.convertIssuesToUnified(vuln)
		unifiedVulns = append(unifiedVulns, unifiedVuln)
	}

	if err := StructsToJSONFile(unifiedVulns, output_file); err != nil {
		return err
	}

	return nil
}
