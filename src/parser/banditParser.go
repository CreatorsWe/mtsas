package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	. "github.com/mtsas/common"
)

type BanditIssue struct {
	BanditResult []BanditResult `json:"results"`
}

type BanditResult struct {
	TestID          string        `json:"test_id"`
	TestName        string        `json:"test_name"`
	IssueText       string        `json:"issue_text"`
	Filename        string        `json:"filename"`
	ColOffset       NullableInt   `json:"col_offset"`
	EndColOffset    NullableInt   `json:"end_col_offset"`
	IssueCwe        BanditCwe     `json:"issue_cwe"`
	IssueSeverity   string        `json:"issue_severity"`
	IssueConfidence string        `json:"issue_confidence"`
	Linerange       []NullableInt `json:"line_range"`
}

type BanditCwe struct {
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

func readJsonToBanditResults(path string) ([]BanditResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	var banditIssues BanditIssue
	err = json.Unmarshal(data, &banditIssues)
	if err != nil {
		return nil, fmt.Errorf("解析JSON失败: %v", err)
	}

	return banditIssues.BanditResult, nil
}

func bandit_getSeverityLevel(severity string) SeverityLevel {
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

func bandit_getConfidenceLevel(confidence string) ConfidenceLevel {
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

func bandit_getLineRange(line_range []NullableInt) (start_line, end_line NullableInt) {
	if len(line_range) == 1 {
		return line_range[0], -1
	} else if len(line_range) == 2 {
		return line_range[0], line_range[1]
	} else {
		return -1, -1
	}
}

func convertBanditResultToUnified(result BanditResult) UnifiedVulnerability {
	start_line, end_line := bandit_getLineRange(result.Linerange)

	return UnifiedVulnerability{
		Tool:         "bandit",
		WarningID:    result.TestID,
		WarningType:  result.TestName,
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
		SeverityLevel:   bandit_getSeverityLevel(result.IssueSeverity),
		ConfidenceLevel: bandit_getConfidenceLevel(result.IssueConfidence),
		Module:          "",
	}
}

func (p *BanditParser) Parse() ([]UnifiedVulnerability, error) {
	banditresults, err := readJsonToBanditResults(p.parseFilePath)
	if err != nil {
		return nil, err
	}
	var unifiedVulnerabilities []UnifiedVulnerability
	for _, vulnerability := range banditresults {
		unifiedVulnerabilities = append(unifiedVulnerabilities, convertBanditResultToUnified(vulnerability))
	}
	return unifiedVulnerabilities, nil
}

func (p *BanditParser) GetName() string {
	return "banditParser"
}
