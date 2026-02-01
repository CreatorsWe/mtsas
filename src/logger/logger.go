package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// 颜色代码常量
const (
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorReset  = "\033[0m"
	ColorGreen  = "\033[32m"
)

// ConsoleLogger 控制台日志记录器
type ConsoleLogger struct {
	logger  *log.Logger
	mu      sync.Mutex
	isquiet bool
}

// NewConsoleLogger 创建新的控制台日志记录器
func NewConsoleLogger() *ConsoleLogger {
	return &ConsoleLogger{
		logger:  log.New(os.Stdout, "", 0),
		isquiet: false,
	}
}

func (cl *ConsoleLogger) SetQuiet(isQuiet bool) {
	cl.isquiet = isQuiet
}

// 控制台日志方法（带颜色）
func (cl *ConsoleLogger) logError(message string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	coloredMessage := fmt.Sprintf("%s[ERROR]%s %s", ColorRed, ColorReset, message)
	cl.logger.Println(coloredMessage)
}

func (cl *ConsoleLogger) logWarning(message string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	coloredMessage := fmt.Sprintf("%s[WARN]%s %s", ColorYellow, ColorReset, message)
	cl.logger.Println(coloredMessage)
}

func (cl *ConsoleLogger) logInfo(message string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	coloredMessage := fmt.Sprintf("%s[INFO]%s %s", ColorBlue, ColorReset, message)
	cl.logger.Println(coloredMessage)
}

func (cl *ConsoleLogger) logDebug(message string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	coloredMessage := fmt.Sprintf("%s[DEBUG]%s %s", ColorGreen, ColorReset, message)
	cl.logger.Println(coloredMessage)
}

// 单独使用控制台日志记录器的方法（保持向后兼容）
func (cl *ConsoleLogger) Error(message string) {
	cl.logError(message)
}

func (cl *ConsoleLogger) Warning(message string) {
	if !cl.isquiet {
		cl.logWarning(message)
	}

}

func (cl *ConsoleLogger) Info(message string) {
	if !cl.isquiet {
		cl.logInfo(message)
	}
}

func (cl *ConsoleLogger) Debug(message string) {
	if !cl.isquiet {
		cl.logDebug(message)
	}
}

// SetOutput 设置控制台日志的输出目标
func (cl *ConsoleLogger) SetOutput(w io.Writer) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.logger.SetOutput(w)
}
