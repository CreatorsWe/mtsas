package main

import (
	"fmt"
	"os"

	. "github.com/mtsas/common"
	"github.com/mtsas/flagParser"
	"github.com/mtsas/scheduler"

	"github.com/mtsas/systemConfigParser"
)

func main() {

	// 1. flagParser 解析命令行参数
	flagparser := flagParser.NewFlagParser()
	result, err := flagparser.ParseFlags()
	if err != nil {
		ConsoleLogger.Error(err.Error())
		os.Exit(0)
	}
	switch resultObj := result.(type) {
	case *ScanFlag:
		// 2. 初始化 systemConfigParser
		systemConfigParser := systemConfigParser.NewSystemConfigParser()
		systemConfigResult, err := systemConfigParser.Parse()
		if err != nil {
			ConsoleLogger.Error(err.Error())
		}

		// 3. 初始化 scheduler
		scheduler := scheduler.NewScheduler(resultObj, systemConfigResult)

		err = scheduler.Init()
		if err != nil {
			ConsoleLogger.Error(err.Error())
		}

		scheduler.Scheduler()
	case *VisualFlag:
		fmt.Println("可视化去重、严重性等级排序")
	case *MapFlag:
		fmt.Println("可视化 cwe 预映射表命令")
	}
}
