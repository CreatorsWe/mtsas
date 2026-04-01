package featureExtractor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/mtsas/common" // 替换为实际的common包路径

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// -------------------------- 内部数据结构（保持原有逻辑） --------------------------
// ScopeInfo 仅保留作用域核心定位信息
type ScopeInfo struct {
	RawID     string // 原始作用域ID（带序号）
	Name      string // 作用域名称（无序号）
	StartLine int    // 作用域起始行
	EndLine   int    // 作用域结束行
	ParentID  string // 父作用域RawID
	ScopeType string // 作用域类型（MODULE/CLASS/FUNC/FILE）
}

// ScopeTable 作用域表（key=RawID，value=ScopeInfo）
type ScopeTable map[string]ScopeInfo

// -------------------------- 新增核心接口 --------------------------
// GetFeatureVuln 核心接口：从UnifiedVulnerability生成DbVulnerability
// 参数：
//
//	vuln: 统一漏洞结构体指针
//
// 返回：
//
//	*common.DbVulnerability: 数据库用漏洞结构体
//	error: 错误信息
func GetFeatureVuln(vuln *common.UnifiedVulnerability) (*common.DbVulnerability, error) {
	// 1. 入参校验
	if vuln == nil {
		return nil, fmt.Errorf("UnifiedVulnerability入参不能为空")
	}
	if vuln.FilePath == "" {
		return nil, fmt.Errorf("漏洞文件路径不能为空")
	}
	if vuln.Range.StartLine.Int() <= 0 {
		return nil, fmt.Errorf("漏洞起始行号必须大于0（当前值：%d）", vuln.Range.StartLine.Int())
	}

	// 2. 读取文件内容
	source, err := os.ReadFile(vuln.FilePath)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败：%w", err)
	}
	fileName := filepath.Base(vuln.FilePath)
	bugPos := vuln.Range.StartLine.Int()

	// 3. 解析语法树
	langEntry := grammars.DetectLanguage(vuln.FilePath)
	if langEntry == nil {
		return nil, fmt.Errorf("不支持的文件类型：%s", filepath.Ext(vuln.FilePath))
	}
	lang := langEntry.Language()
	parser := gotreesitter.NewParser(lang)
	tree, err := parser.Parse(source)
	if err != nil {
		return nil, fmt.Errorf("解析语法树失败：%w", err)
	}
	rootNode := tree.RootNode()

	// 4. 提取作用域表
	scopeTable, err := extractScopes(fileName, rootNode, langEntry.Name, lang, source)
	if err != nil {
		return nil, fmt.Errorf("提取作用域失败：%w", err)
	}

	// 5. 匹配最优作用域
	optimalScopeRawID, err := matchOptimalScope(bugPos, scopeTable)
	if err != nil {
		return nil, fmt.Errorf("匹配最优作用域失败：%w", err)
	}
	optimalScope := scopeTable[optimalScopeRawID]

	// 6. 构建ScopeOffsetID（作用域链 > 偏移，不含CWE）
	scopeID := buildHierarchicalScopeID(fileName, optimalScopeRawID)
	offset := bugPos - optimalScope.StartLine
	scopeOffsetID := fmt.Sprintf("%s > %d", scopeID, offset)

	// 7. 计算Hash（需要CWE，无则为空）
	var hash string
	if vuln.CWEID != "" && vuln.CWEID != "null" {
		// 解析CWEID（处理字符串格式，如"CWE-123"或"123"）
		cwe, err := parseCWEID(vuln.CWEID)
		if err != nil {
			return nil, fmt.Errorf("解析CWEID失败：%w", err)
		}
		if cwe > 0 {
			hash = calculateHash(fileName, scopeID, offset, cwe)
		}
	}

	// 8. 构建返回结果
	dbVuln := &common.DbVulnerability{
		Vulnerabilities: *vuln,
		Hash:            hash,
		ScopeOffsetID:   scopeOffsetID,
		OptimalScope: common.ScopeRange{
			Start: optimalScope.StartLine,
			End:   optimalScope.EndLine,
		},
		WarningCount: 1,
	}

	return dbVuln, nil
}

// -------------------------- 内部核心函数（优化补充） --------------------------

// parseCWEID 解析CWEID字符串（支持CWE-XXX、XXX格式）
func parseCWEID(cweID string) (int, error) {
	// 移除CWE前缀（如CWE-123 → 123）
	cweStr := strings.TrimPrefix(strings.TrimSpace(cweID), "CWE-")
	if cweStr == "" {
		return 0, fmt.Errorf("CWEID为空")
	}
	cwe, err := strconv.Atoi(cweStr)
	if err != nil {
		return 0, fmt.Errorf("CWEID格式错误（%s）：%w", cweID, err)
	}
	if cwe <= 0 {
		return 0, fmt.Errorf("CWEID必须大于0（%s）", cweID)
	}
	return cwe, nil
}

// extractScopes 提取作用域表
func extractScopes(fileName string, root *gotreesitter.Node, lang string, treeSitterLang *gotreesitter.Language, source []byte) (ScopeTable, error) {
	scopeTable := make(ScopeTable)
	scopeStack := []string{}
	counter := make(map[string]int)

	// 初始化文件根作用域
	rootRawID := fmt.Sprintf("%s[0]", fileName)
	rootScope := ScopeInfo{
		RawID:     rootRawID,
		Name:      fileName,
		StartLine: 1,
		EndLine:   len(strings.Split(string(source), "\n")),
		ParentID:  "",
		ScopeType: "FILE",
	}
	scopeTable[rootRawID] = rootScope
	scopeStack = append(scopeStack, rootRawID)

	// 深度优先遍历
	var traverse func(node *gotreesitter.Node)
	traverse = func(node *gotreesitter.Node) {
		if node == nil {
			return
		}

		nodeType := node.Type(treeSitterLang)
		normalizedType := normalizeNodeType(nodeType, lang)
		currentRawID := ""

		if normalizedType != "OTHER" {
			// 提取作用域名称
			nodeText := strings.TrimSpace(node.Text(source))
			scopeName := simplifyScopeName(nodeText, normalizedType, lang)
			if scopeName == "" {
				scopeName = "unknown"
			}

			// 提取行号
			startLine := int(node.StartPoint().Row) + 1
			endLine := int(node.EndPoint().Row) + 1

			// 生成RawID
			parentRawID := scopeStack[len(scopeStack)-1]
			counterKey := fmt.Sprintf("%s_%s_%s", parentRawID, normalizedType, scopeName)
			seq := counter[counterKey]
			counter[counterKey]++
			currentRawID = fmt.Sprintf("%s > %s[%d]", parentRawID, scopeName, seq)

			// 存储作用域信息
			scopeTable[currentRawID] = ScopeInfo{
				RawID:     currentRawID,
				Name:      scopeName,
				StartLine: startLine,
				EndLine:   endLine,
				ParentID:  parentRawID,
				ScopeType: normalizedType,
			}

			scopeStack = append(scopeStack, currentRawID)
		}

		// 遍历子节点
		childCount := int(node.ChildCount())
		for i := range childCount {
			traverse(node.Child(i))
		}

		// 弹栈
		if currentRawID != "" {
			scopeStack = scopeStack[:len(scopeStack)-1]
		}
	}

	traverse(root)
	return scopeTable, nil
}

// matchOptimalScope 匹配最优作用域（最细粒度）
func matchOptimalScope(vulnLine int, scopeTable ScopeTable) (string, error) {
	var candidates []string

	// 筛选包含漏洞行的作用域
	for rawID, info := range scopeTable {
		if vulnLine >= info.StartLine && vulnLine <= info.EndLine {
			candidates = append(candidates, rawID)
		}
	}

	if len(candidates) == 0 {
		return "", fmt.Errorf("未找到包含漏洞行 %d 的作用域", vulnLine)
	}

	// 按粒度排序（FUNC > CLASS > MODULE > FILE）
	granularity := map[string]int{
		"FUNC":   3,
		"CLASS":  2,
		"MODULE": 1,
		"FILE":   0,
	}
	optimalRawID := candidates[0]
	maxGranularity := granularity[scopeTable[optimalRawID].ScopeType]

	// 选择最细粒度的作用域
	for _, rawID := range candidates[1:] {
		level := granularity[scopeTable[rawID].ScopeType]
		if level > maxGranularity {
			maxGranularity = level
			optimalRawID = rawID
		}
	}

	return optimalRawID, nil
}

// buildHierarchicalScopeID 构建层级化作用域ID
func buildHierarchicalScopeID(fileName string, rawID string) string {
	parts := strings.Split(rawID, " > ")
	if len(parts) > 0 {
		parts[0] = fileName
	}
	return strings.Join(parts, " > ")
}

// calculateHash 计算哈希值（包含CWE）
func calculateHash(fileName, scopeID string, offset int, cwe int) string {
	// 拼接并归一化输入
	rawInput := fmt.Sprintf("%s > %s > %d > %d", fileName, scopeID, offset, cwe)
	normalizedInput := strings.ToLower(strings.ReplaceAll(rawInput, " ", ""))

	// SHA256哈希
	hashBytes := sha256.Sum256([]byte(normalizedInput))
	return hex.EncodeToString(hashBytes[:])
}

// simplifyScopeName 提取简化的作用域名称
func simplifyScopeName(rawText, scopeType, lang string) string {
	cleanText := strings.ReplaceAll(rawText, "\n", " ")
	cleanText = regexp.MustCompile(`\s+`).ReplaceAllString(cleanText, " ")

	switch lang {
	case "go":
		if scopeType == "MODULE" {
			reg := regexp.MustCompile(`package\s+(\w+)`)
			match := reg.FindStringSubmatch(cleanText)
			if len(match) > 1 {
				return match[1]
			}
		}
		if scopeType == "FUNC" {
			reg := regexp.MustCompile(`func\s+(\w+)\s*\([^)]*\)`)
			match := reg.FindStringSubmatch(cleanText)
			if len(match) > 1 {
				return match[1]
			}
		}
	case "java":
		if scopeType == "CLASS" {
			reg := regexp.MustCompile(`class\s+(\w+)\s*\{`)
			match := reg.FindStringSubmatch(cleanText)
			if len(match) > 1 {
				return match[1]
			}
		}
		if scopeType == "FUNC" {
			reg := regexp.MustCompile(`\s+(\w+)\s*\([^)]*\)\s*\{`)
			match := reg.FindStringSubmatch(cleanText)
			if len(match) > 1 {
				return match[1]
			}
		}
	case "cpp":
		if scopeType == "MODULE" {
			reg := regexp.MustCompile(`namespace\s+(\w+)\s*\{`)
			match := reg.FindStringSubmatch(cleanText)
			if len(match) > 1 {
				return match[1]
			}
		}
		if scopeType == "CLASS" {
			reg := regexp.MustCompile(`class\s+(\w+)\s*\{`)
			match := reg.FindStringSubmatch(cleanText)
			if len(match) > 1 {
				return match[1]
			}
		}
		if scopeType == "FUNC" {
			reg := regexp.MustCompile(`\s*[\w:]+?\s+(\w+)\s*\([^)]*\)\s*\{`)
			match := reg.FindStringSubmatch(cleanText)
			if len(match) > 1 {
				return match[1]
			}
		}
	}

	// 兜底处理
	if len(cleanText) > 20 {
		return cleanText[:20]
	}
	return cleanText
}

// normalizeNodeType 归一化节点类型
func normalizeNodeType(nodeType, lang string) string {
	mapping := map[string]map[string]string{
		"go": {
			"package_declaration":   "MODULE",
			"function_declaration":  "FUNC",
			"method_declaration":    "FUNC",
			"type_declaration":      "CLASS",
			"interface_declaration": "CLASS",
		},
		"java": {
			"package_declaration": "MODULE",
			"class_declaration":   "CLASS",
			"method_declaration":  "FUNC",
		},
		"python": {
			"function_definition": "FUNC",
			"class_definition":    "CLASS",
		},
		"c": {
			"function_definition": "FUNC",
			"struct_specifier":    "CLASS",
		},
		"cpp": {
			"function_definition":  "FUNC",
			"class_specifier":      "CLASS",
			"namespace_definition": "MODULE",
			"method_definition":    "FUNC",
		},
	}

	// 查找并返回归一化后的类型
	if langMap, ok := mapping[lang]; ok {
		if t, ok := langMap[nodeType]; ok {
			return t
		}
	}
	return "OTHER"
}
