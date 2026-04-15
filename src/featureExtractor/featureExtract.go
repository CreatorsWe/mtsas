package featureExtractor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mtsas/common"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
)

type ScopeInfo struct {
	RawID     string
	Name      string
	StartLine int
	EndLine   int
	ParentID  string
	ScopeType string
}

type ScopeTable map[string]ScopeInfo

type captureInfo struct {
	node *sitter.Node
	typ  string
}

var langMap = map[string]*sitter.Language{
	".go":   golang.GetLanguage(),
	".java": java.GetLanguage(),
	".py":   python.GetLanguage(),
	".js":   javascript.GetLanguage(),
	".cpp":  cpp.GetLanguage(),
	".c":    c.GetLanguage(),
	".h":    c.GetLanguage(),
	".hpp":  cpp.GetLanguage(),
}

var queryMap = map[string]string{
	"go": `
		(package_declaration) @module
		(function_declaration) @func
		(method_declaration) @func
		(type_declaration) @class
	`,
	"java": `
		(package_declaration) @module
		(class_declaration) @class
		(method_declaration) @func
	`,
	"python": `
		(function_definition) @func
		(class_definition) @class
	`,
	"cpp": `
		(namespace_definition) @module
		(class_specifier) @class
		(function_definition) @func
	`,
	"c": `
		(function_definition) @func
		(struct_specifier) @class
	`,
	"javascript": `
		(function_declaration) @func
		(class_declaration) @class
	`,
}

// 计算漏洞特征： 1. 文件路径 2. 漏洞行 3.
func GetFeatureVuln(file_path string, line int, cwe int) (string, error) {
	if file_path == "" || line <= 0 || cwe <= 0 {
		return "", fmt.Errorf("invalid vuln data")
	}

	src, err := os.ReadFile(file_path)
	if err != nil {
		return "", err
	}
	file := filepath.Base(file_path)

	lang, langName, err := getLang(file_path)
	if err != nil {
		return "", err
	}

	parser := sitter.NewParser()
	parser.SetLanguage(lang)
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return "", err
	}
	defer tree.Close()

	scopes, err := extractScopes(file, tree.RootNode(), src, langName)
	if err != nil {
		return "", err
	}

	bestID, err := findBestScope(line, scopes)
	if err != nil {
		return "", err
	}
	best := scopes[bestID]

	scopeID := buildScopeID(file, bestID)
	offset := line - best.StartLine
	scopeOffsetID := fmt.Sprintf("%s@%d", scopeID, offset)

	common.ConsoleLogger.Debug(scopeOffsetID)

	hash := sha256Sum(fmt.Sprintf("%s|%d", scopeOffsetID, cwe))

	return hash, nil
}

func extractScopes(fileName string, root *sitter.Node, src []byte, lang string) (ScopeTable, error) {
	st := make(ScopeTable)
	stack := []string{}
	counter := make(map[string]int)

	totalLines := len(strings.Split(string(src), "\n"))
	rootID := fmt.Sprintf("%s[0]", fileName)
	st[rootID] = ScopeInfo{
		RawID:     rootID,
		Name:      fileName,
		StartLine: 1,
		EndLine:   totalLines,
		ParentID:  "",
		ScopeType: "FILE",
	}
	stack = append(stack, rootID)

	var list []captureInfo
	queryStr := queryMap[lang]
	lines := strings.Split(queryStr, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "@") {
			continue
		}
		parts := strings.Split(line, "@")
		if len(parts) < 2 {
			continue
		}
		typStr := parts[1]
		typ := ""
		switch typStr {
		case "module":
			typ = "MODULE"
		case "class":
			typ = "CLASS"
		case "func":
			typ = "FUNC"
		default:
			continue
		}

		pattern := strings.TrimSpace(parts[0])
		pattern = strings.Trim(pattern, "()")
		walk(root, func(n *sitter.Node) {
			if n.Type() == pattern {
				list = append(list, captureInfo{node: n, typ: typ})
			}
		})
	}

	sortList(list)
	for _, item := range list {
		n := item.node
		startLine := int(n.StartPoint().Row) + 1
		endLine := int(n.EndPoint().Row) + 1

		// ✅ 修复：string 转 []byte
		name := simplify([]byte(n.Content(src)), item.typ, lang)

		parentID := rootID
		for i := len(stack) - 1; i >= 0; i-- {
			s := st[stack[i]]
			if startLine >= s.StartLine && endLine <= s.EndLine {
				parentID = s.RawID
				break
			}
		}

		key := fmt.Sprintf("%s_%s_%s", parentID, item.typ, name)
		seq := counter[key]
		counter[key]++
		id := fmt.Sprintf("%s>%s[%d]", parentID, name, seq)

		st[id] = ScopeInfo{
			RawID:     id,
			Name:      name,
			StartLine: startLine,
			EndLine:   endLine,
			ParentID:  parentID,
			ScopeType: item.typ,
		}
		stack = append(stack, id)
	}

	return st, nil
}

func sortList(list []captureInfo) {
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			a := list[i].node.StartPoint()
			b := list[j].node.StartPoint()
			if a.Row > b.Row || (a.Row == b.Row && a.Column > b.Column) {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
}

func walk(n *sitter.Node, f func(*sitter.Node)) {
	f(n)
	for i := 0; i < int(n.ChildCount()); i++ {
		walk(n.Child(i), f)
	}
}

func getLang(path string) (*sitter.Language, string, error) {
	ext := filepath.Ext(path)
	l, ok := langMap[ext]
	if !ok {
		return nil, "", fmt.Errorf("unsupported file: %s", path)
	}
	var name string
	switch ext {
	case ".go":
		name = "go"
	case ".java":
		name = "java"
	case ".py":
		name = "python"
	case ".js":
		name = "javascript"
	case ".cpp", ".hpp":
		name = "cpp"
	case ".c", ".h":
		name = "c"
	}
	return l, name, nil
}

func findBestScope(line int, st ScopeTable) (string, error) {
	var ids []string
	for id, s := range st {
		if line >= s.StartLine && line <= s.EndLine {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("no scope contains line %d", line)
	}

	prio := map[string]int{"FUNC": 3, "CLASS": 2, "MODULE": 1, "FILE": 0}
	best := ids[0]
	max := prio[st[best].ScopeType]
	for _, id := range ids[1:] {
		if p := prio[st[id].ScopeType]; p > max {
			max = p
			best = id
		}
	}
	return best, nil
}

func buildScopeID(file, raw string) string {
	parts := strings.Split(raw, ">")

	if len(parts) > 0 {
		parts[0] = file
	}
	return strings.Join(parts, ">")
}

func sha256Sum(s string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(s)))
	return hex.EncodeToString(sum[:])
}

func simplify(content []byte, typ, lang string) string {
	s := strings.TrimSpace(string(content))
	s = regexp.MustCompile(`\s+`).ReplaceAllString(s, " ")
	if len(s) > 32 {
		return s[:32]
	}
	return s
}
