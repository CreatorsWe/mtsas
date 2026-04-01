// 返回 index 页面的处理函数: 返回 index.html index.css index.js 页面
package visual

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	common "github.com/mtsas/common"
)

const INDEXPAGE_PATH = `D:\Code\Project\Multi-tool_Static_Analysis_System_refactor\src\static\visual\index`

// 路由前缀 /demo/index 或者 /demo
func indexPageHandler(w http.ResponseWriter, r *http.Request) {
	var reqPath = r.URL.Path

	var ext = filepath.Ext(reqPath)

	// 1. 获取请求的文件路径
	var indexPath string

	switch ext {
	case ".html", "":
		indexPath = filepath.Join(INDEXPAGE_PATH, "index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case ".css":
		indexPath = filepath.Join(INDEXPAGE_PATH, "index.css")
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		indexPath = filepath.Join(INDEXPAGE_PATH, "index.js")
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	}

	// 2. 检查文件是否存在
	if _, err := os.Stat(indexPath); os.IsNotExist(err) {
		http.NotFound(w, r)

		common.ConsoleLogger.Info(fmt.Sprintf("%s not found in: %s", indexPath, INDEXPAGE_PATH))
		return
	} else if err != nil {
		http.Error(w, fmt.Sprintf("读取文件失败: %v", err), http.StatusInternalServerError)
		common.ConsoleLogger.Info(fmt.Sprintf("read index file error: %v", err))
		return
	}

	http.ServeFile(w, r, indexPath)
}
