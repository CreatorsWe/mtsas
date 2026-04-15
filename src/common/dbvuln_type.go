// 定义漏洞数据库类型
package common

type DbVulnerability struct {
	Vulnerabilities UnifiedVulnerability `json:"vulnerabilities"`
	Hash            string               `json:"hash"`
	WarningCount    int                  `json:"warningCount"` // 警告数量,相同 hash 警告要去重，但是要记录相同警告数量
	Score           float64              `json:"score"`
}
