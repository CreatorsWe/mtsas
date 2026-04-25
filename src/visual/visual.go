package visual

import (
	"errors"
	"fmt"
	"net/http"
	"filepath"

	"github.com/mtsas/common"
)

// visual 启动 HTTP 服务：提供静态页面 + 数据接口
//
//	mtsasPath: .mtsas 根目录路径
//	projectName: 项目名称（如 demo）
//	返回值: 服务启动错误
func Visual(mtsasDir, projectName string) error {
	// 1. 参数校验
	if mtsasDir == "" || projectName == "" {
		return errors.New("mtsasPath 和 projectName 不能为空")
	}

	mtsasPath := filepath.join(mtsasDir, ".mtsas");

	numToTimestamps, numToDbPaths, err := readTimestamps(mtsasPath, projectName)

	if err != nil {
		return fmt.Errorf("visual error: %s", err)
	}

	const STATIC_PATH = `/home/PatrickStar/Downloads/github.project/mtsas/static/dist`

	// 2. 注册路由
	http.HandleFunc(fmt.Sprintf("/%s/index", projectName), indexPageHandler(STATIC_PATH))
	http.HandleFunc(fmt.Sprintf("/%s", projectName), indexPageHandler(STATIC_PATH))
	http.HandleFunc("/mtsas/index-data/timestamps", indexDataHandler(projectName, numToTimestamps))
	http.HandleFunc("/mtsas/vulner-data", vulnerDataHandler(numToDbPaths))
	// 2. 静态资源（js/css）从 dist/assets 加载
	http.Handle("/assets/", http.FileServer(http.Dir(STATIC_PATH)))

	// 3. 启动 HTTP 服务
	common.ConsoleLogger.Info("=== MTSAS 可视化服务启动成功 ===\n")
	common.ConsoleLogger.Info(fmt.Sprintf("前端页面地址: http://localhost:8080/%s\n", projectName))

	return http.ListenAndServe(":8080", nil)
}
