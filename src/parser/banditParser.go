package parser

import (
	"encoding/json"
	"fmt"
	"os"

	. "github.com/mtsas/common"
)

// 表示是 banditIssues 的外层结构
type o_banditIssues struct {
	Banditissues []banditIssues `json:"results"`
}

type banditIssues struct {
	TestID          string    `json:"test_id"`
	TestName        string    `json:"test_name"`
	IssueText       string    `json:"issue_text"`
	Filename        string    `json:"filename"`
	IssueCwe        banditCwe `json:"issue_cwe"`
	IssueSeverity   string    `json:"issue_severity"`
	IssueConfidence string    `json:"issue_confidence"`
	Line            int       `json:"line_number"`
}

type banditCwe struct {
	ID int `json:"id"`
}

type BanditParser struct {
	parseFilePath string
}

func NewBanditParser(parseFilePath string) *BanditParser {
	return &BanditParser{
		parseFilePath: parseFilePath,
	}
}

// 返回 issuesMiddle
func (b *BanditParser) readReportToIssues(path string) ([]banditIssues, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	var o_banditIssues o_banditIssues
	err = json.Unmarshal(data, &o_banditIssues)
	if err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v", err)
	}

	return o_banditIssues.Banditissues, nil
}

func (b *BanditParser) getSeverityLevel(severity string) SeverityLevel {
	switch severity {
	case "LOW":
		return SeverityLevelLow
	case "MEDIUM":
		return SeverityLevelMedium
	case "HIGH":
		return SeverityLevelHigh
	default:
		return SeverityLevelUnknown
	}
}

func (b *BanditParser) getConfidenceLevel(confidence string) ConfidenceLevel {
	switch confidence {
	case "LOW":
		return ConfidenceLevelLow
	case "MEDIUM":
		return ConfidenceLevelMedium
	case "HIGH":
		return ConfidenceLevelHigh
	default:
		return ConfidenceLevelLow
	}
}

func (b *BanditParser) convertIssuesToUnified(result banditIssues) UnifiedVulnerability {

	return UnifiedVulnerability{
		Tool:            "bandit",
		WarningID:       result.TestID,
		Category:        "",
		ShortMessage:    result.IssueText,
		FilePath:        result.Filename,
		Line:            result.Line,
		CWEID:           result.IssueCwe.ID,
		SeverityLevel:   b.getSeverityLevel(result.IssueSeverity),
		ConfidenceLevel: b.getConfidenceLevel(result.IssueConfidence),
	}
}

func (b *BanditParser) Parse() ([]UnifiedVulnerability, error) {
	banditresults, err := b.readReportToIssues(b.parseFilePath)
	if err != nil {
		return nil, err
	}
	var unifiedVulnerabilities []UnifiedVulnerability
	for _, vulnerability := range banditresults {
		unifiedVulnerabilities = append(unifiedVulnerabilities, b.convertIssuesToUnified(vulnerability))
	}
	return unifiedVulnerabilities, nil
}

func (p *BanditParser) GetName() string {
	return "banditParser"
}
