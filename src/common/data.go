package common

import (
	"github.com/mtsas/logger"
)

var ConsoleLogger = logger.NewConsoleLogger()

type Language string

// 编程语言的枚举类型
const (
	LanguageGo      Language = "go"
	LanguageJava    Language = "java"
	LanguagePython  Language = "python"
	LanguageC       Language = "c"
	LanguageCsharp  Language = "c#"
	LanguageCpp     Language = "cpp"
	LanguageKotlin  Language = "kotlin"
	LanguageJs      Language = "javascript"
	LanguageTs      Language = "typescript"
	LanguageRuby    Language = "ruby"
	LanguageRust    Language = "rust"
	LanguageUnknown Language = "unknown"
)
