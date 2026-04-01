package visual

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// readTimestamps 读取指定项目下的时间戳目录，填充全局映射表
//
//	mtsas_path: .mtsas 根目录路径
//	project_name: 项目名称（如 demo、demo1）
//	返回值: 错误信息（路径不存在/无项目/无时间戳目录等）
func readTimestamps(mtsas_path, project_name string) (NumToTimestamps, NumToDbPaths map[int]string, e error) {
	NumToTimestamps, NumToDbPaths = nil, nil
	// ========== 步骤1：校验根目录是否存在 ==========
	if _, err := os.Stat(mtsas_path); os.IsNotExist(err) {
		e = fmt.Errorf("mtsas 根目录不存在: %s", mtsas_path)
		return
	} else if err != nil {
		e = fmt.Errorf("检查mtsas根目录失败: %w", err)
		return
	}

	// ========== 步骤2：校验项目目录是否存在 ==========
	projectDir := filepath.Join(mtsas_path, project_name)
	if _, err := os.Stat(projectDir); os.IsNotExist(err) {
		e = fmt.Errorf("没有 %s 项目", project_name)
		return
	} else if err != nil {
		e = fmt.Errorf("检查%s项目目录失败: %w", project_name, err)
		return
	}

	// ========== 步骤3：遍历项目目录下的子目录（不递归） ==========
	// 编译时间戳目录格式正则：匹配 年-月-日_时.分.秒（如 2026-1-24_11.42.23）
	// 正则说明：
	// ^\d{4}-\d{1,2}-\d{1,2}_\d{1,2}\.\d{1,2}\.\d{1,2}$
	// \d{4}：4位年份 | \d{1,2}：1-2位月/日/时/分/秒 | _/.：分隔符
	tsRegex := regexp.MustCompile(`^\d{4}-\d{1,2}-\d{1,2}_\d{1,2}\.\d{1,2}\.\d{1,2}$`)

	// 读取项目目录下所有条目
	entries, err := os.ReadDir(projectDir)
	if err != nil {
		e = fmt.Errorf("读取%s项目目录失败: %w", project_name, err)
		return
	}

	// 筛选符合格式的时间戳目录，暂存到临时切片
	var tsDirs []string
	for _, entry := range entries {
		// 只处理目录，且名称匹配时间戳格式
		if entry.IsDir() && tsRegex.MatchString(entry.Name()) {
			tsDirs = append(tsDirs, entry.Name())
		}
	}

	// 无符合格式的时间戳目录
	if len(tsDirs) == 0 {
		e = fmt.Errorf(project_name, " 项目没有扫描记录")
		return
	}

	// ========== 步骤4：排序并填充全局映射表 ==========
	// 初始化全局映射（避免nil panic）
	NumToTimestamps = make(map[int]string, len(tsDirs))
	NumToDbPaths = make(map[int]string, len(tsDirs))

	// 对时间戳目录按名称排序（保证序号顺序稳定）
	sort.Strings(tsDirs)

	// 序号从1开始赋值
	for idx, tsName := range tsDirs {
		serialNum := idx + 1 // 序号从1开始
		// 填充时间戳字符串映射
		NumToTimestamps[serialNum] = tsName
		// 填充时间戳目录完整路径映射
		NumToDbPaths[serialNum] = filepath.Join(projectDir, tsName, "vulner.sqlite3")
	}

	return
}

func indexDataHandler(projectName string, numToTimestamps map[int]string) http.HandlerFunc {
	// TimestampItem 前端所需的时间戳条目结构
	type TimestampItem struct {
		Number    int    `json:"number"`
		Timestamp string `json:"timestamp"`
	}

	// IndexResponse 总览接口返回数据结构
	type IndexResponse struct {
		ProjectName   string          `json:"projectName"`
		TimestampMaps []TimestampItem `json:"timestampMaps"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. 跨域配置（解决前端跨域请求问题）
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// 2. 构造前端所需的响应数据
		var timestampMaps []TimestampItem
		for num := 1; num <= len(numToTimestamps); num++ {
			timestampMaps = append(timestampMaps, TimestampItem{
				Number:    num,
				Timestamp: numToTimestamps[num],
			})
		}

		response := IndexResponse{
			ProjectName:   projectName,
			TimestampMaps: timestampMaps,
		}

		// 5. 返回 JSON 数据
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, fmt.Sprintf("数据序列化失败: %v", err), http.StatusInternalServerError)
			return
		}
	}
}
