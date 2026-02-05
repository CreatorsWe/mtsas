package parser

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	. "github.com/mtsas/common"
)

type csaIssues struct {
	indexIssues
	jumpIssues
}

// index.html HTML 报告字段
type indexIssues struct {
	BugGroup string
	BugType  string
	FilePath string
	Function string
	HrefPath string // <a> 标签中 href 属性对应的路径
}

type jumpIssues struct {
	Line    int
	Column  int
	Message string
}

type CSAParser struct {
	parseFilePath string
	baseDir       string
}

func NewCSAParser(parseFilePath string) *CSAParser {
	return &CSAParser{
		parseFilePath: parseFilePath,
		baseDir:       filepath.Dir(parseFilePath),
	}
}

// 根据 bugGroup 提取 SeverityLevel
func (c *CSAParser) getSeverityLevel(category string) SeverityLevel {
	// category 包含 error 则为 High，包含 unused 则为 Low，其余为 Medium
	switch {
	case strings.Contains(category, "error"):
		return SeverityLevelHigh
	case strings.Contains(category, "unused"):
		return SeverityLevelLow
	default:
		return SeverityLevelMedium
	}
}

func (c *CSAParser) convertIssuesToUnified(issues csaIssues) (UnifiedVulnerability, error) {
	return UnifiedVulnerability{
		Tool:         "clang-static-analysis",
		WarningID:    issues.BugType,
		Category:     issues.BugGroup,
		ShortMessage: issues.Message,
		CWEID:        "",
		FilePath:     issues.FilePath,
		Module:       "",
		Range: Range{
			StartLine:   NullableInt(issues.Line),
			EndLine:     -1,
			StartColumn: NullableInt(issues.Column),
			EndColumn:   -1,
		},
		SeverityLevel:   c.getSeverityLevel(issues.BugGroup),
		ConfidenceLevel: ConfidenceLevelHigh,
	}, nil
}

// 主要解析方法
func (c *CSAParser) Parse() ([]UnifiedVulnerability, error) {
	csaIssues, err := c.readReportToIssues(c.parseFilePath)
	if err != nil {
		return nil, err
	}

	var unifiedVulnerabilities []UnifiedVulnerability
	for _, issue := range csaIssues {
		issues, err := c.convertIssuesToUnified(issue)
		if err != nil {
			return nil, err
		}
		unifiedVulnerabilities = append(unifiedVulnerabilities, issues)
	}

	return unifiedVulnerabilities, nil
}

func (c *CSAParser) GetName() string {
	return "csaParser"
}

func (c *CSAParser) readReportToIssues(path string) ([]csaIssues, error) {
	indexIssuesList, err := c.parseIndexIssues(path)
	if err != nil {
		return nil, err
	}

	var issues []csaIssues
	for _, indexIssue := range indexIssuesList {
		jumpFilePath := filepath.Join(c.baseDir, indexIssue.HrefPath)
		jumpIssue, err := c.parseJumpIssues(jumpFilePath)
		if err != nil {
			fmt.Printf("Warning: Failed to parse jump file %s: %v\n", jumpFilePath, err)
			continue
		}

		issues = append(issues, csaIssues{
			indexIssues: indexIssue,
			jumpIssues:  *jumpIssue,
		})
	}

	return issues, nil
}

// 解析表格的 tbody 内容
func (c *CSAParser) parseIndexIssues(indexFilePath string) ([]indexIssues, error) {
	content, err := os.ReadFile(indexFilePath)
	if err != nil {
		return nil, err
	}

	// 正则表达式匹配 tr 行
	trRegex := regexp.MustCompile(`<tr class="[^"]*">\s*<td class="DESC">([^<]*)</td>\s*<td class="DESC">([^<]*)</td>\s*<td>([^<]*)</td>\s*<td class="DESC">([^<]*)</td>\s*<td class="Q">(\d+)</td>\s*<td class="Q">\d+</td>\s*<td>\s*<a href="([^#"]+)[^"]*">View Report</a>\s*</td>`)

	matches := trRegex.FindAllStringSubmatch(string(content), -1)

	var issues []indexIssues
	for _, match := range matches {
		if len(match) == 7 {
			issues = append(issues, indexIssues{
				BugGroup: strings.TrimSpace(match[1]),
				BugType:  strings.TrimSpace(match[2]),
				FilePath: strings.TrimSpace(match[3]),
				Function: strings.TrimSpace(match[4]),
				HrefPath: strings.TrimSpace(match[6]),
			})
		}
	}

	return issues, nil
}

// 解析详细报告文件
func (c *CSAParser) parseJumpIssues(jumpFilePath string) (*jumpIssues, error) {
	content, err := os.ReadFile(jumpFilePath)
	if err != nil {
		return nil, err
	}

	// 提取行号和列号
	lineColRegex := regexp.MustCompile(`<a href="#EndPath">line (\d+), column (\d+)</a>`)
	lineColMatch := lineColRegex.FindStringSubmatch(string(content))

	if len(lineColMatch) != 3 {
		return nil, fmt.Errorf("failed to parse line and column from %s", jumpFilePath)
	}

	line, _ := strconv.Atoi(lineColMatch[1])
	column, _ := strconv.Atoi(lineColMatch[2])

	// 提取消息
	messageRegex := regexp.MustCompile(`<a href="#EndPath">line \d+, column \d+</a><br />\s*([^<]+)`)
	messageMatch := messageRegex.FindStringSubmatch(string(content))

	var message string
	if len(messageMatch) >= 2 {
		message = strings.TrimSpace(messageMatch[1])
	} else {
		// 备用方法：提取警告表格中的完整文本
		warningRegex := regexp.MustCompile(`<td class="rowname">Warning:</td>\s*<td>\s*[^<]*<[^>]*>[^<]*</a><br />\s*([^<]+)`)
		warningMatch := warningRegex.FindStringSubmatch(string(content))
		if len(warningMatch) >= 2 {
			message = strings.TrimSpace(warningMatch[1])
		}
	}

	// message 合并多个空格、空白符为一个空格
	message = strings.Join(strings.Fields(message), " ")

	return &jumpIssues{
		Line:    line,
		Column:  column,
		Message: message,
	}, nil
}

func (c *CSAParser) ParseToFile(output_file string) error {
	csaIssues, err := c.readReportToIssues(c.parseFilePath)
	if err != nil {
		return err
	}

	var unifiedVulnerabilities []UnifiedVulnerability
	for _, issue := range csaIssues {
		issues, err := c.convertIssuesToUnified(issue)
		if err != nil {
			return err
		}
		unifiedVulnerabilities = append(unifiedVulnerabilities, issues)
	}

	if err := StructsToJSONFile(unifiedVulnerabilities, output_file); err != nil {
		return err
	}
	return nil
}
