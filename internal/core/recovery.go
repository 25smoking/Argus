package core

import (
	"context"
	"fmt"
	"runtime/debug"

	"go.uber.org/zap"
)

// SafeRun 安全执行插件，捕获 panic 并转换为错误
func SafeRun(plugin Plugin, ctx context.Context, cfg *ScanConfig) (results []Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			stack := string(debug.Stack())
			err = fmt.Errorf("插件 %s 发生 panic: %v\n堆栈:\n%s", plugin.Name(), r, stack)

			// 记录到日志
			if logger, ok := ctx.Value("logger").(*zap.Logger); ok {
				logger.Error("插件执行 panic",
					zap.String("plugin", plugin.Name()),
					zap.Any("panic", r),
					zap.String("stack", stack),
				)
			}

			// 返回一个包含错误信息的结果
			results = []Result{
				{
					Plugin:      plugin.Name(),
					Level:       "error",
					Description: fmt.Sprintf("插件执行异常: %v", r),
					Reference:   "请检查日志获取详细堆栈信息",
				},
			}
		}
	}()

	return plugin.Run(ctx, cfg)
}
