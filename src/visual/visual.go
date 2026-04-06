package visual

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/mtsas/common"
)

// visual 启动 HTTP 服务：提供静态页面 + 数据接口
//
//	mtsasPath: .mtsas 根目录路径
//	projectName: 项目名称（如 demo）
//	返回值: 服务启动错误
func Visual(mtsasPath, projectName string) error {
	// 1. 参数校验
	if mtsasPath == "" || projectName == "" {
		return errors.New("mtsasPath 和 projectName 不能为空")
	}

	numToTimestamps, numToDbPaths, err := readTimestamps(mtsasPath, projectName)

	if err != nil {
		return fmt.Errorf("visual error: %s", err)
	}

	// 2. 注册路由
	http.HandleFunc(fmt.Sprintf("/%s/index", projectName), indexPageHandler)
	http.HandleFunc(fmt.Sprintf("/%s", projectName), indexPageHandler)
	http.HandleFunc("/mtsas/index-data/timestamps", indexDataHandler(projectName, numToTimestamps))
	http.HandleFunc(fmt.Sprintf("/%s/vulner-data", projectName), vulnerDataHandler(numToDbPaths))

	// 3. 启动 HTTP 服务
	common.ConsoleLogger.Info("=== MTSAS 可视化服务启动成功 ===\n")
	common.ConsoleLogger.Info(fmt.Sprintf("前端页面地址: http://localhost:8080/%s\n", projectName))

	return http.ListenAndServe(":8080", nil)
}
