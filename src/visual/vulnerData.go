package visual

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	common "github.com/mtsas/common"
	"github.com/mtsas/dbManager"
)

// 返回数据
type VulnerData struct {
	HasCWEVulns   []common.DbVulnerability `json:"hasCWEVulns"`
	EmptyCWEVulns []common.DbVulnerability `json:"emptyCWEVulns"`
}

// 查询 number 的数据库结果并返回
func vulnerDataHandler(numToDbPaths map[int]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. 跨域配置（解决前端跨域请求问题）
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// 2. 获取 number 参数
		n := r.URL.Query().Get("number")
		number, err := strconv.Atoi(n)
		if err != nil {
			http.Error(w, fmt.Sprintf("无效 number: %v", err), http.StatusInternalServerError)
			return
		}

		// 3. 数据库路径
		var dbPath = numToDbPaths[number]
		// 4. 查询有无 hash 的漏洞数据并返回
		db, err := dbManager.NewDbManager(dbPath)
		if err != nil {
			http.Error(w, fmt.Sprintf("open %s database error", dbPath), http.StatusInternalServerError)
			common.ConsoleLogger.Error(fmt.Sprintf("open %s database error", dbPath))
			return
		}
		defer db.Close()

		emptycwevulns, err := db.QueryEmptyCWEVulns()
		if err != nil {
			http.Error(w, fmt.Sprintf("query data error in %s database: %s", dbPath, err), http.StatusInternalServerError)
			common.ConsoleLogger.Error(fmt.Sprintf("query data error in %s database: %s", dbPath, err))
			return
		}
		hascwevulns, err := db.QueryHasCWEVulns()
		if err != nil {
			http.Error(w, fmt.Sprintf("query data error in %s database: %s", dbPath, err), http.StatusInternalServerError)
			common.ConsoleLogger.Error(fmt.Sprintf("query data error in %s database: %s", dbPath, err))
			return
		}
		// 5. 构建 json 数据。并发送
		var vulnerDatas VulnerData
		vulnerDatas.HasCWEVulns = hascwevulns
		vulnerDatas.EmptyCWEVulns = emptycwevulns
		_ = json.NewEncoder(w).Encode(vulnerDatas)
	}
}
