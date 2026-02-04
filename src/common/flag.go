package common

type ScanFlag struct {
	ProjectName   string                // 项目名称
	OutputDir     string                // .mtsas 目录路径，不检查是否存在
	OutputFormat  string                // 输出文件格式:"json", "csv",否则默认为 "",不输出文件
	ScanDir       string                // 扫描目录路径
	ScanFiles     map[Language][]string // 带扫描文件语言和文件路径集合的映射
	Exclude       []string              // 排除的文件或目录,如 "/path/tests/**, /path/docs/**, /path/test.py"
	ProjectConfig string                // 项目配置文件，toml 格式，简化命令行的繁琐
	IsQuiet       bool                  // 是否静默模式(控制台不输出除 Error 外的任何信息)
}

type VisualFlag struct {
	ProjectName string
	OutputDir   string
}

type MapFlag struct{}
