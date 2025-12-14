//go:build linux || darwin

package plugins

import "github.com/25smoking/Argus/internal/core"

// checkProcessSignature Linux 下暂不验签 (或者未来实现 ELF 签名验证)
func (p *ProcessPlugin) checkProcessSignature(exePath string, pid int32) *core.Result {
	return nil
}

// checkHiddenProcesses Linux 下暂未实现 (需要 /proc 与 getdents 对比)
func (p *ProcessPlugin) checkHiddenProcesses(visiblePids []int32) []core.Result {
	return nil
}
