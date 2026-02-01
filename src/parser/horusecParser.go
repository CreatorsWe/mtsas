package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	. "github.com/mtsas/common"
)

type HorusecIssue struct {
	AnalysisVulnerabilities []AnalysisVulnerability `json:"analysisVulnerabilities"`
}

// 对应 analysisVulnerabilities 数组的元素
type AnalysisVulnerability struct {
	Vulnerabilities Vulnerability `json:"vulnerabilities"` // 映射单个漏洞对象
}

// 原 Vulnerabilities 结构体（对应 vulnerabilities 字段的内容）不变
type Vulnerability struct {
	VulnerabilityID string      `json:"vulnerabilityID"`
	Line            NullableInt `json:"line"`
	Column          NullableInt `json:"column"`
	Confidence      string      `json:"confidence"`
	File            string      `json:"file"`
	Details         string      `json:"details"`
	SecurityTool    string      `json:"securityTool"`
	Severity        string      `json:"severity"`
	Type            string      `json:"type"`
	RuleID          string      `json:"rule_id"`
}

// HorusecParser 实现Parser接口
type HorusecParser struct {
	parseFilePath string
}

func NewHorusecParser(parseFilePath string) *HorusecParser {
	return &HorusecParser{
		parseFilePath: parseFilePath,
	}
}

func horusec_getSeverityLevel(severity string) SeverityLevel {
	switch severity {
	case "CRITICAL":
		return SeverityLevelCritical
	case "HIGH":
		return SeverityLevelHigh
	case "MEDIUM":
		return SeverityLevelMedium
	case "LOW":
		return SeverityLevelLow
	default:
		return SeverityLevelUnknown
	}
}

func horusec_getConfidenceLevel(confidence string) ConfidenceLevel {
	switch confidence {
	case "HIGH":
		return ConfidenceLevelHigh
	case "MEDIUM":
		return ConfidenceLevelMedium
	case "LOW":
		return ConfidenceLevelLow
	default:
		return ConfidenceLevelLow
	}
}

func horusec_getCWEID(details string) string {
	cweRegex := regexp.MustCompile(`CWE-(\d+)`)
	if matches := cweRegex.FindStringSubmatch(details); len(matches) > 1 {
		return matches[1]
	}
	return ""
}
func convertVulnerabilityToUnified(vulnerability Vulnerability) UnifiedVulnerability {
	return UnifiedVulnerability{
		Tool:         "horusec",
		WarningID:    vulnerability.RuleID,
		WarningType:  vulnerability.RuleID,
		Category:     vulnerability.Type,
		ShortMessage: vulnerability.Details,
		FilePath:     vulnerability.File,
		Range: Range{
			StartLine:   vulnerability.Line,
			EndLine:     -1,
			StartColumn: vulnerability.Column,
			EndColumn:   -1,
		},
		CWEID:           horusec_getCWEID(vulnerability.Details),
		SeverityLevel:   horusec_getSeverityLevel(vulnerability.Severity),
		ConfidenceLevel: horusec_getConfidenceLevel(vulnerability.Confidence),
		Module:          "",
	}
}

func readJsonToVulnerabilities(path string) ([]Vulnerability, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	var horusecIssues HorusecIssue
	err = json.Unmarshal(data, &horusecIssues)
	if err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v", err)
	}

	// 遍历 analysisVulnerabilities，提取其中的 vulnerabilities 字段
	var vulList []Vulnerability
	for _, item := range horusecIssues.AnalysisVulnerabilities {
		vulList = append(vulList, item.Vulnerabilities)
	}

	return vulList, nil
}

// Parse 解析Horusec JSON文件，转换为统一漏洞结构体
func (p *HorusecParser) Parse() ([]UnifiedVulnerability, error) {
	vulnerabilities, err := readJsonToVulnerabilities(p.parseFilePath)
	if err != nil {
		return nil, err
	}
	var unifiedVulnerabilities []UnifiedVulnerability
	for _, vulnerability := range vulnerabilities {
		unifiedVulnerabilities = append(unifiedVulnerabilities, convertVulnerabilityToUnified(vulnerability))
	}
	return unifiedVulnerabilities, nil
}

func (p *HorusecParser) GetName() string {
	return "horusecParser"
}
