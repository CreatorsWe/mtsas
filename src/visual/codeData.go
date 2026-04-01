package visual

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
)

// 结构体定义（完全保持你原始定义不变）
type ScopeRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

type BugPos struct {
	StartLine   int  `json:"start_line"`
	EndLine     *int `json:"end_line"` // 为nil时使用StartLine
	StartColumn int  `json:"start_column"`
	EndColumn   *int `json:"end_column"` // 为nil时使用StartColumn
}

// 返回数据结构
type CodeInfo struct {
	Number  int    `json:"number"`
	Content string `json:"content"`
	Isbug   bool   `json:"isbug"`
}

// 请求体结构体：接收前端POST的JSON数据
type CodeRequest struct {
	FilePath    string     `json:"file_path"`  // 文件路径
	ReadScope   ScopeRange `json:"read_scope"` // 读取行范围
	BugPosition int        `json:"bug_pos"`    // Bug位置信息
}

// CodeHandler 核心函数：仅处理 POST JSON
func codeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// 1. 跨域配置（解决前端跨域请求问题）
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		// 1. 仅允许 POST 请求
		if r.Method != http.MethodPost {
			json.NewEncoder(w).Encode(map[string]string{"error": "仅支持POST请求"})
			return
		}

		// 2. 解析前端传入的JSON请求体
		var req CodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "JSON参数解析失败"})
			return
		}
		defer r.Body.Close()

		// 3. 处理Bug位置默认值（空指针时取起始值）

		// 4. 读取代码文件
		file, err := os.Open(req.FilePath)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"error": "文件打开失败"})
			return
		}
		defer file.Close()

		// 5. 逐行读取并标记Bug
		scanner := bufio.NewScanner(file)
		var codeList []CodeInfo
		lineNum := 0

		for scanner.Scan() {
			lineNum++
			// 只读取指定行范围
			if lineNum < req.ReadScope.Start {
				continue
			}

			if lineNum > req.ReadScope.End {
				json.NewEncoder(w).Encode(codeList)
				return
			}

			info := CodeInfo{
				Number:  lineNum,
				Content: scanner.Text(),
				Isbug:   false,
			}

			// 判断当前行是否是Bug行
			if lineNum == req.BugPosition {
				info.Isbug = true
			}

			codeList = append(codeList, info)
		}

	}
}
