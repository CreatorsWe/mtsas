package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	. "github.com/mtsas/common"
)

// SARIF 格式的结构定义
type sarifReport struct {
	Runs []run `json:"runs"`
}

type run struct {
	Tool    tool           `json:"tool"`
	Results []codeqlIssues `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Rules []rule `json:"rules"`
}

type rule struct {
	ID               string         `json:"id"`
	ShortDescription textContainer  `json:"shortDescription"`
	Properties       ruleProperties `json:"properties"`
}

type ruleProperties struct {
	ID              string   `json:"id"`
	Kind            string   `json:"kind"`
	Precision       string   `json:"precision"`
	Tags            []string `json:"tags"`
	ProblemSeverity string   `json:"problem.severity"`
}

// 仅记录漏洞信息，漏洞对应的 ruleId 需从 ruleProperties 中获取
type codeqlIssues struct {
	RuleID    string        `json:"ruleId"`
	Message   textContainer `json:"message"`
	Locations []locations   `json:"locations"`
}

type locations struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type artifactLocation struct {
	URI string `json:"uri"` // 文件路径
}

type region struct {
	StartLine   int `json:"startLine"`
	EndLine     int `json:"endLine"`
	StartColumn int `json:"startColumn"`
	EndColumn   int `json:"endColumn"`
}

type textContainer struct {
	Text string `json:"text"`
}

type CodeQLParser struct {
	parseFilePath  string
	queryInterface func(string, string) (string, error)
}

func NewCodeQLParser(parseFilePath string, query func(string, string) (string, error)) *CodeQLParser {
	return &CodeQLParser{
		parseFilePath:  parseFilePath,
		queryInterface: query,
	}
}

// 读取 SARIF 报告文件,获取 codeIssues 和 ruleProperties
func (c *CodeQLParser) readReportToIssues(path string) (*sarifReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取SARIF文件失败: %v", err)
	}

	var report sarifReport
	err = json.Unmarshal(data, &report)
	if err != nil {
		return nil, fmt.Errorf("解析SARIF JSON失败: %v", err)
	}

	return &report, nil
}

// 从规则属性中提取CWE ID
func (c *CodeQLParser) getCWEID(tags []string, ruleID string) (string, error) {
	for _, tag := range tags {
		if strings.HasPrefix(tag, "external/cwe/cwe-") {
			// 提取CWE编号，如 "external/cwe/cwe-79" -> "79"
			parts := strings.Split(tag, "/")
			if len(parts) > 0 {
				cwePart := parts[len(parts)-1]
				cweNum := strings.TrimPrefix(cwePart, "cwe-")
				return cweNum, nil
			}
		}
	}
	// 查询数据库
	cweID, err := c.queryInterface("codeql", ruleID)
	if err != nil {
		return "", err
	}
	return cweID, nil
}

// 转换严重级别
func (c *CodeQLParser) getSeverityLevel(severity string) SeverityLevel {
	switch strings.ToUpper(severity) {
	case "ERROR", "CRITICAL", "HIGH":
		return SeverityLevelHigh
	case "WARNING", "MEDIUM":
		return SeverityLevelMedium
	case "NOTE", "RECOMMENDATION", "LOW":
		return SeverityLevelLow
	default:
		return SeverityLevelUnknown
	}
}

// 转换置信度级别
func (c *CodeQLParser) getConfidenceLevel(precision string) ConfidenceLevel {
	switch strings.ToUpper(precision) {
	case "HIGH", "VERY-HIGH":
		return ConfidenceLevelHigh
	case "MEDIUM", "MODERATE":
		return ConfidenceLevelMedium
	case "LOW", "VERY-LOW":
		return ConfidenceLevelLow
	default:
		return ConfidenceLevelLow // 默认中等置信度
	}
}

// 获取规则元数据
func (c *CodeQLParser) getRuleMetadata(rules []rule, ruleID string) (ruleProperties, string) {
	for _, r := range rules {
		if r.ID == ruleID {
			return r.Properties, r.ShortDescription.Text
		}
	}
	return ruleProperties{}, ""
}

// 转换结果为统一格式
func (c *CodeQLParser) convertIssuesToUnified(resultObj codeqlIssues, rules []rule) (UnifiedVulnerability, error) {
	props, _ := c.getRuleMetadata(rules, resultObj.RuleID)

	// 处理文件路径 - 去除 file:// 前缀
	filePath := ""
	if len(resultObj.Locations) > 0 {
		filePath = strings.TrimPrefix(
			resultObj.Locations[0].PhysicalLocation.ArtifactLocation.URI,
			"file://",
		)
	}

	// 处理行号范围
	startLine := NullableInt(-1)
	endLine := NullableInt(-1)
	startColumn := NullableInt(-1)
	endColumn := NullableInt(-1)

	if len(resultObj.Locations) > 0 {
		region := resultObj.Locations[0].PhysicalLocation.Region
		startLine = NullableInt(region.StartLine)
		endLine = NullableInt(region.EndLine)
		startColumn = NullableInt(region.StartColumn)
		endColumn = NullableInt(region.EndColumn)
	}

	// 如果结束行号为0，使用开始行号
	if endLine == 0 {
		endLine = startLine
	}

	cweID, err := c.getCWEID(props.Tags, resultObj.RuleID)
	if err != nil {
		return UnifiedVulnerability{}, err
	}

	return UnifiedVulnerability{
		Tool:         "codeql",
		WarningID:    resultObj.RuleID,
		Category:     props.Kind,
		ShortMessage: resultObj.Message.Text,
		FilePath:     filePath,
		Range: Range{
			StartLine:   startLine,
			EndLine:     endLine,
			StartColumn: startColumn,
			EndColumn:   endColumn,
		},
		CWEID:           cweID,
		SeverityLevel:   c.getSeverityLevel(props.ProblemSeverity),
		ConfidenceLevel: c.getConfidenceLevel(props.Precision),
		Module:          "",
	}, nil
}

func (c *CodeQLParser) Parse() ([]UnifiedVulnerability, error) {
	report, err := c.readReportToIssues(c.parseFilePath)
	if err != nil {
		return nil, err
	}

	var unifiedVulnerabilities []UnifiedVulnerability

	// 处理每个run（通常只有一个run）
	for _, run := range report.Runs {

		// 转换每个result
		for _, result := range run.Results {
			unifiedVuln, err := c.convertIssuesToUnified(result, run.Tool.Driver.Rules)
			if err != nil {
				return nil, err
			}
			unifiedVulnerabilities = append(unifiedVulnerabilities, unifiedVuln)
		}
	}

	return unifiedVulnerabilities, nil
}

func (c *CodeQLParser) GetName() string {
	return "codeqlParser"
}

func (c *CodeQLParser) ParseToFile(output_file string) error {
	report, err := c.readReportToIssues(c.parseFilePath)
	if err != nil {
		return err
	}

	var unifiedVulnerabilities []UnifiedVulnerability

	// 处理每个run（通常只有一个run）
	for _, run := range report.Runs {

		// 转换每个result
		for _, result := range run.Results {
			unifiedVuln, err := c.convertIssuesToUnified(result, run.Tool.Driver.Rules)
			if err != nil {
				return err
			}
			unifiedVulnerabilities = append(unifiedVulnerabilities, unifiedVuln)
		}
	}

	if err := StructsToJSONFile(unifiedVulnerabilities, output_file); err != nil {
		return err
	}

	return nil
}
