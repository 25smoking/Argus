//go:build !windows && !linux

package main

import (
	"fmt"
	"runtime"

	"github.com/25smoking/Argus/internal/core"
)

func checkPrivileges() {
}

func getOSInfo() string {
	return fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH)
}

func getOSPlugins() []core.Plugin {
	return nil
}

func initOS() {
}
