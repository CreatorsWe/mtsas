package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

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
	VulnerabilityID string `json:"vulnerabilityID"`
	Line            string `json:"line"`
	Confidence      string `json:"confidence"`
	File            string `json:"file"`
	Details         string `json:"details"`
	SecurityTool    string `json:"securityTool"`
	Severity        string `json:"severity"`
	Type            string `json:"type"`
	RuleID          string `json:"rule_id"`
}

// HorusecParser 实现Parser接口
type HorusecParser struct {
	parseFilePath string
	scan_dir      string
}

func NewHorusecParser(parseFilePath string, scan_dir string) *HorusecParser {
	return &HorusecParser{
		parseFilePath: parseFilePath,
		scan_dir:      scan_dir,
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

func (h *HorusecParser) getCWEID(details string) (int, error) {
	cweRegex := regexp.MustCompile(`CWE-(\d+)`)
	if matches := cweRegex.FindStringSubmatch(details); len(matches) > 1 {
		cweID, err := strconv.Atoi(matches[1])
		if err != nil {
			return -1, err
		}
		return cweID, nil
	}
	return -1, nil
}
func (h *HorusecParser) convertIssuesToUnified(issues horusecIssues) (UnifiedVulnerability, error) {

	cweID, err := h.getCWEID(issues.Details)
	if err != nil {
		return UnifiedVulnerability{}, fmt.Errorf("解析CWEID失败: %v", err)
	}

	line, err := strconv.Atoi(issues.Line)
	if err != nil {
		return UnifiedVulnerability{}, err
	}

	return UnifiedVulnerability{
		Tool:            "horusec",
		WarningID:       issues.RuleID,
		Category:        issues.Type,
		ShortMessage:    issues.Details,
		FilePath:        filepath.Join(h.scan_dir, issues.File),
		Line:            line,
		CWEID:           cweID,
		SeverityLevel:   h.getSeverityLevel(issues.Severity),
		ConfidenceLevel: h.getConfidenceLevel(issues.Confidence),
	}, nil
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
		unifiedVuln, err := h.convertIssuesToUnified(vulnerability)
		if err != nil {
			return nil, err
		}
		unifiedVulnerabilities = append(unifiedVulnerabilities, unifiedVuln)
	}
	return unifiedVulnerabilities, nil
}

func (p *HorusecParser) GetName() string {
	return "horusecParser"
}
