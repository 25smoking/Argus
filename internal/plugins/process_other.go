//go:build !windows && !linux && !darwin

package plugins

import "github.com/25smoking/Argus/internal/core"

func (p *ProcessPlugin) checkProcessSignature(exePath string, pid int32) *core.Result {
	return nil
}

func (p *ProcessPlugin) checkHiddenProcesses(visiblePids []int32) []core.Result {
	return nil
}
