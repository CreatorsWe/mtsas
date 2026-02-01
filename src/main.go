package main

import (
	. "github.com/mtsas/common"
	"github.com/mtsas/flagParser"
	"github.com/mtsas/scheduler"

	"github.com/mtsas/systemConfigParser"
)

func main() {

	// 1. flagParser 解析命令行参数
	flagParser := flagParser.NewFlagParser()
	flagResult, err := flagParser.ParseFlags()
	if err != nil {
		ConsoleLogger.Error(err.Error())
	}

	// 2. 初始化 systemConfigParser
	systemConfigParser := systemConfigParser.NewSystemConfigParser()
	systemConfigResult, err := systemConfigParser.Parse()
	if err != nil {
		ConsoleLogger.Error(err.Error())
	}

	// 3. 初始化 scheduler
	scheduler := scheduler.NewScheduler(flagResult, systemConfigResult)

	err = scheduler.Init()
	if err != nil {
		ConsoleLogger.Error(err.Error())
	}

	scheduler.Scheduler()
}
