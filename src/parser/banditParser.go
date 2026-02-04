package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	. "github.com/mtsas/common"
)

// 表示是 banditIssues 的外层结构
type o_banditIssues struct {
	Banditissues []banditIssues `json:"results"`
}

type banditIssues struct {
	TestID          string        `json:"test_id"`
	TestName        string        `json:"test_name"`
	IssueText       string        `json:"issue_text"`
	Filename        string        `json:"filename"`
	ColOffset       NullableInt   `json:"col_offset"`
	EndColOffset    NullableInt   `json:"end_col_offset"`
	IssueCwe        banditCwe     `json:"issue_cwe"`
	IssueSeverity   string        `json:"issue_severity"`
	IssueConfidence string        `json:"issue_confidence"`
	Linerange       []NullableInt `json:"line_range"`
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

func (b *BanditParser) getLineRange(line_range []NullableInt) (start_line, end_line NullableInt) {
	if len(line_range) == 1 {
		return line_range[0], -1
	} else if len(line_range) == 2 {
		return line_range[0], line_range[1]
	} else {
		return -1, -1
	}
}

func (b *BanditParser) convertIssuesToUnified(result banditIssues) UnifiedVulnerability {
	start_line, end_line := b.getLineRange(result.Linerange)

	return UnifiedVulnerability{
		Tool:         "bandit",
		WarningID:    result.TestID,
		Category:     "",
		ShortMessage: result.IssueText,
		FilePath:     result.Filename,
		Range: Range{
			StartLine:   start_line,
			EndLine:     end_line,
			StartColumn: result.ColOffset,
			EndColumn:   result.EndColOffset,
		},
		CWEID:           strconv.Itoa(result.IssueCwe.ID),
		SeverityLevel:   b.getSeverityLevel(result.IssueSeverity),
		ConfidenceLevel: b.getConfidenceLevel(result.IssueConfidence),
		Module:          "",
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

func (b *BanditParser) ParseToFile(output_file string) error {
	banditresults, err := b.readReportToIssues(b.parseFilePath)
	if err != nil {
		return err
	}
	var unifiedVulnerabilities []UnifiedVulnerability
	for _, vulnerability := range banditresults {
		unifiedVulnerabilities = append(unifiedVulnerabilities, b.convertIssuesToUnified(vulnerability))
	}

	if err := StructsToJSONFile(unifiedVulnerabilities, output_file); err != nil {
		return err
	}
	return nil
}
