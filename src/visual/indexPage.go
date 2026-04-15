// 返回 index 页面的处理函数: 返回 index.html index.css index.js 页面
package visual

import (
	"net/http"
	"path/filepath"
)

// 路由前缀 /demo/index 或者 /demo
//

func indexPageHandler(static_path string) http.HandlerFunc {
	// 关键：读取真实的 index.html 文件
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join(static_path, "index.html"))
	}
}
