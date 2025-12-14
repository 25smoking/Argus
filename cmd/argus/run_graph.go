package main

import (
	"os"

	"github.com/25smoking/Argus/internal/core"
	"github.com/25smoking/Argus/internal/graph"
	"go.uber.org/zap"
)

func runGraph() {
	// Initialize local logger since main doesn't export one
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	log := logger.Sugar()

	log.Info("正在生成系统攻击图谱快照...")

	g, err := graph.BuildSnapshot()
	if err != nil {
		log.Fatalf("构建图谱失败: %v", err)
	}

	outputPath := "attack_graph.dot"
	if core.GlobalConfig != nil && core.GlobalConfig.Output != "" {
		outputPath = core.GlobalConfig.Output
	}

	f, err := os.Create(outputPath)
	if err != nil {
		log.Fatalf("无法创建输出文件: %v", err)
	}
	defer f.Close()

	if err := g.ExportDOT(f); err != nil {
		log.Fatalf("写出 DOT 文件失败: %v", err)
	}

	log.Infof("图谱已生成: %s", outputPath)
	log.Info("请使用 Graphviz 打开该文件，或访问 http://www.webgraphviz.com/ 进行查看。")
}
