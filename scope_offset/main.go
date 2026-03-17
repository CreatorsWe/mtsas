package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// -------------------------- 精简后的数据结构 --------------------------
// ScopeInfo 仅保留作用域核心定位信息
type ScopeInfo struct {
	RawID     string // 原始作用域ID（带序号）
	Name      string // 作用域名称（无序号）
	StartLine int    // 作用域起始行
	EndLine   int    // 作用域结束行
	ParentID  string // 父作用域RawID
	ScopeType string // 作用域类型（MODULE/CLASS/FUNC/FILE）
}

// VulnInfo 漏洞核心信息（仅保留输出所需字段）
type VulnInfo struct {
	ScopeOffsetID string // Scope+Offset 标识（文件名 > 作用域链 > 偏移 > cwe）
	Hash          string // 哈希值（基于文件名+ScopeID+Offset+CWE）
	ScopeStart    int    // 最优作用域起始行
	ScopeEnd      int    // 最优作用域结束行
	CWE           int    // CWE类型
}

// ScopeTable 作用域表（key=RawID，value=ScopeInfo）
type ScopeTable map[string]ScopeInfo

// -------------------------- 主函数 --------------------------
func main() {
	// 解析命令行参数
	filePath := flag.String("file", "", "目标文件路径（必填）")
	bugPos := flag.Int("bug-pos", 0, "漏洞行号（必填，1-based）")
	cwe := flag.Int("cwe", 0, "漏洞CWE类型（必填，如 22）")
	flag.Parse()

	// 强制校验必填参数
	if *filePath == "" {
		fmt.Println("错误：必须指定 --file 参数（目标文件路径）")
		flag.Usage()
		os.Exit(1)
	}
	if *bugPos <= 0 {
		fmt.Println("错误：必须指定 --bug-pos 参数（漏洞行号，1-based）")
		flag.Usage()
		os.Exit(1)
	}
	if *cwe == 0 {
		fmt.Println("错误：必须指定 --cwe 参数（漏洞CWE类型，如 22）")
		flag.Usage()
		os.Exit(1)
	}

	// 读取文件内容
	source, err := os.ReadFile(*filePath)
	if err != nil {
		fmt.Printf("读取文件失败：%v\n", err)
		os.Exit(1)
	}
	fileName := filepath.Base(*filePath)

	// 1. 解析语法树
	langEntry := grammars.DetectLanguage(*filePath)
	if langEntry == nil {
		fmt.Printf("不支持的文件类型：%s\n", filepath.Ext(*filePath))
		os.Exit(1)
	}
	lang := langEntry.Language()
	parser := gotreesitter.NewParser(lang)
	tree, err := parser.Parse(source)
	if err != nil {
		fmt.Printf("解析语法树失败：%v\n", err)
		os.Exit(1)
	}
	rootNode := tree.RootNode()

	// 2. 提取作用域表
	scopeTable, err := ExtractScopes(fileName, rootNode, langEntry.Name, lang, source)
	if err != nil {
		fmt.Printf("提取作用域失败：%v\n", err)
		os.Exit(1)
	}

	// 3. 匹配最优作用域
	optimalScopeRawID, err := MatchOptimalScope(*bugPos, scopeTable)
	if err != nil {
		fmt.Printf("匹配最优作用域失败：%v\n", err)
		os.Exit(1)
	}
	optimalScope := scopeTable[optimalScopeRawID]

	// 4. 构建Scope+Offset标识
	scopeID := BuildHierarchicalScopeID(fileName, optimalScopeRawID, scopeTable)
	offset := *bugPos - optimalScope.StartLine
	scopeOffsetID := fmt.Sprintf("%s > %d > %s", scopeID, offset, fmt.Sprintf("CWE-%d", *cwe))

	// 5. 计算哈希值
	hash := CalculateHash(fileName, scopeID, offset, *cwe)

	// 6. 构建漏洞信息并输出
	vulnInfo := VulnInfo{
		ScopeOffsetID: scopeOffsetID,
		Hash:          hash,
		ScopeStart:    optimalScope.StartLine,
		ScopeEnd:      optimalScope.EndLine,
		CWE:           *cwe,
	}
	PrintResult(vulnInfo)
}

// -------------------------- 核心函数 --------------------------

// ExtractScopes 提取作用域表
func ExtractScopes(fileName string, root *gotreesitter.Node, lang string, treeSitterLang *gotreesitter.Language, source []byte) (ScopeTable, error) {
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

// MatchOptimalScope 匹配最优作用域（最细粒度）
func MatchOptimalScope(vulnLine int, scopeTable ScopeTable) (string, error) {
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

	// 按粒度排序（FUNC  >  CLASS  >  MODULE  >  FILE）
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

// BuildHierarchicalScopeID 构建层级化作用域ID
func BuildHierarchicalScopeID(fileName string, rawID string, scopeTable ScopeTable) string {
	parts := strings.Split(rawID, " > ")
	if len(parts) > 0 {
		parts[0] = fileName
	}
	return strings.Join(parts, " > ")
}

// CalculateHash 计算哈希值（包含CWE）
func CalculateHash(fileName, scopeID string, offset int, cwe int) string {
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

// PrintResult 格式化输出核心结果
func PrintResult(vulnInfo VulnInfo) {
	fmt.Println("=== 优化后的 Scope+Offset 漏洞定位结果 ===")
	fmt.Printf("Scope+Offset 标识：%s\n", vulnInfo.ScopeOffsetID)
	fmt.Printf("漏洞哈希值：%s\n", vulnInfo.Hash)
	fmt.Printf("最优作用域行号区间：[%d, %d]\n", vulnInfo.ScopeStart, vulnInfo.ScopeEnd)
}
