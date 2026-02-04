package parser

import (
	"encoding/xml"
	"fmt"
	"os"

	. "github.com/mtsas/common"
)

// SpotBugs XML 报告结构体定义
type o_spotbugsIssues struct {
	Spotbugsissues []spotbugsIssues `xml:"BugInstance"`
}

type spotbugsIssues struct {
	Type       string     `xml:"type,attr"`
	Priority   int        `xml:"priority,attr"`
	Rank       int        `xml:"rank,attr"`
	Abbrev     string     `xml:"abbrev,attr"`
	Category   string     `xml:"category,attr"`
	SourceLine sourceLine `xml:"SourceLine"`
}

type sourceLine struct {
	ClassName     string `xml:"classname,attr"`
	Start         int    `xml:"start,attr"`
	End           int    `xml:"end,attr"`
	SourceFile    string `xml:"sourcefile,attr"`
	SourcePath    string `xml:"sourcepath,attr"`
	StartBytecode int    `xml:"startBytecode,attr"`
	EndBytecode   int    `xml:"endBytecode,attr"`
}

type SpotBugsParser struct {
	parseFilePath string
}

func NewSpotBugsParser(parseFilePath string) *SpotBugsParser {
	return &SpotBugsParser{
		parseFilePath: parseFilePath,
	}
}

// 将 SpotBugs 优先级转换为严重性级别
func (s *SpotBugsParser) getSeverityLevel(priority int) SeverityLevel {
	switch priority {
	case 1:
		return SeverityLevelHigh
	case 2:
		return SeverityLevelMedium
	case 3:
		return SeverityLevelLow
	default:
		return SeverityLevelUnknown
	}
}

// 根据 rank 值获取置信度级别
func (s *SpotBugsParser) getConfidenceLevel(rank int) ConfidenceLevel {
	if rank <= 10 {
		return ConfidenceLevelHigh
	} else if rank <= 15 {
		return ConfidenceLevelMedium
	} else {
		return ConfidenceLevelLow
	}
}

// 读取并解析 XML 文件
func (s *SpotBugsParser) readReportToIssues(path string) ([]spotbugsIssues, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %v", err)
	}

	var report o_spotbugsIssues
	err = xml.Unmarshal(data, &report)
	if err != nil {
		return nil, fmt.Errorf("解析XML失败: %v", err)
	}

	return report.Spotbugsissues, nil
}

func (s *SpotBugsParser) convertIssuesToUnified(issues spotbugsIssues) (UnifiedVulnerability, error) {

	return UnifiedVulnerability{
		Tool:            "spotbugs",
		WarningID:       issues.Type,
		Category:        issues.Category,
		ShortMessage:    "",
		FilePath:        issues.SourceLine.SourcePath,
		CWEID:           "",
		SeverityLevel:   s.getSeverityLevel(issues.Priority),
		ConfidenceLevel: s.getConfidenceLevel(issues.Rank),
		Module:          "",
		Range: Range{
			StartLine:   NullableInt(issues.SourceLine.Start),
			EndLine:     NullableInt(issues.SourceLine.End),
			StartColumn: -1, // SpotBugs 不提供列信息
			EndColumn:   -1,
		},
	}, nil
}

// 主要解析方法
func (p *SpotBugsParser) Parse() ([]UnifiedVulnerability, error) {
	report, err := p.readReportToIssues(p.parseFilePath)
	if err != nil {
		return nil, err
	}

	var unifiedVulnerabilities []UnifiedVulnerability
	for _, bug := range report {
		unifiedVuln, err := p.convertIssuesToUnified(bug)
		if err != nil {
			return nil, err
		}
		unifiedVulnerabilities = append(unifiedVulnerabilities, unifiedVuln)
	}

	return unifiedVulnerabilities, nil
}

// 获取解析器名称
func (p *SpotBugsParser) GetName() string {
	return "spotbugsParser"
}

func (p *SpotBugsParser) ParseToFile(output_file string) error {
	report, err := p.readReportToIssues(p.parseFilePath)
	if err != nil {
		return err
	}

	var unifiedVulnerabilities []UnifiedVulnerability
	for _, bug := range report {
		unifiedVuln, err := p.convertIssuesToUnified(bug)
		if err != nil {
			return err
		}
		unifiedVulnerabilities = append(unifiedVulnerabilities, unifiedVuln)
	}

	if err := StructsToJSONFile(unifiedVulnerabilities, output_file); err != nil {
		return err
	}
	return nil
}
