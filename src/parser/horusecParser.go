package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"

	. "github.com/mtsas/common"
)

type oo_horusecIssues struct {
	O_Horusecissues []o_horusecIssues `json:"analysisVulnerabilities"`
}

// 对应 analysisVulnerabilities 数组的元素
type o_horusecIssues struct {
	Horusecissues horusecIssues `json:"vulnerabilities"` // 映射单个漏洞对象
}

// 原 Vulnerabilities 结构体（对应 vulnerabilities 字段的内容）不变
type horusecIssues struct {
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

func (h *HorusecParser) getSeverityLevel(severity string) SeverityLevel {
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

func (h *HorusecParser) getConfidenceLevel(confidence string) ConfidenceLevel {
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

func (h *HorusecParser) getCWEID(details string) string {
	cweRegex := regexp.MustCompile(`CWE-(\d+)`)
	if matches := cweRegex.FindStringSubmatch(details); len(matches) > 1 {
		return matches[1]
	}
	return ""
}
func (h *HorusecParser) convertIssuesToUnified(issues horusecIssues) UnifiedVulnerability {
	return UnifiedVulnerability{
		Tool:         "horusec",
		WarningID:    issues.RuleID,
		Category:     issues.Type,
		ShortMessage: issues.Details,
		FilePath:     issues.File,
		Range: Range{
			StartLine:   issues.Line,
			EndLine:     -1,
			StartColumn: issues.Column,
			EndColumn:   -1,
		},
		CWEID:           h.getCWEID(issues.Details),
		SeverityLevel:   h.getSeverityLevel(issues.Severity),
		ConfidenceLevel: h.getConfidenceLevel(issues.Confidence),
		Module:          "",
	}
}

func (h *HorusecParser) readReportToIssues(path string) ([]horusecIssues, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	var oo_horusecissues oo_horusecIssues
	err = json.Unmarshal(data, &oo_horusecissues)
	if err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v", err)
	}

	// 遍历 analysisVulnerabilities，提取其中的 vulnerabilities 字段
	var horusecissues []horusecIssues
	for _, item := range oo_horusecissues.O_Horusecissues {
		horusecissues = append(horusecissues, item.Horusecissues)
	}

	return horusecissues, nil
}

// Parse 解析Horusec JSON文件，转换为统一漏洞结构体
func (h *HorusecParser) Parse() ([]UnifiedVulnerability, error) {
	vulnerabilities, err := h.readReportToIssues(h.parseFilePath)
	if err != nil {
		return nil, err
	}
	var unifiedVulnerabilities []UnifiedVulnerability
	for _, vulnerability := range vulnerabilities {
		unifiedVulnerabilities = append(unifiedVulnerabilities, h.convertIssuesToUnified(vulnerability))
	}
	return unifiedVulnerabilities, nil
}

func (p *HorusecParser) GetName() string {
	return "horusecParser"
}

func (h *HorusecParser) ParseToFile(output_file string) error {
	vulnerabilities, err := h.readReportToIssues(h.parseFilePath)
	if err != nil {
		return err
	}
	var unifiedVulnerabilities []UnifiedVulnerability
	for _, vulnerability := range vulnerabilities {
		unifiedVulnerabilities = append(unifiedVulnerabilities, h.convertIssuesToUnified(vulnerability))
	}

	if err := StructsToJSONFile(unifiedVulnerabilities, output_file); err != nil {
		return err
	}
	return nil
}
