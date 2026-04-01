// 定义漏洞数据库类型
package common

type DbVulnerability struct {
	Vulnerabilities UnifiedVulnerability `json:"vulnerabilities"`
	Hash            string               `json:"hash"`
	ScopeOffsetID   string               `json:"scopeoffsetID"`
	OptimalScope    ScopeRange           `json:"optimalscope"`
	WarningCount    int                  `json:"warningCount"` // 警告数量,相同 hash 警告要去重，但是要记录相同警告数量
}

type ScopeRange struct {
	Start int `json:"start"`
	End   int `json:"end"`
}
