//go:build !windows

package graph

import (
	"fmt"

	netutil "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

func BuildSnapshot() (*AttackGraph, error) {
	g := NewAttackGraph()
	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("failed to get process list: %v", err)
	}

	pidMap := make(map[int32]string)
	for _, proc := range procs {
		name, _ := proc.Name()
		if name == "" {
			name = "unknown"
		}
		nodeID := fmt.Sprintf("PROC_%d", proc.Pid)
		g.AddNode(nodeID, fmt.Sprintf("%s\n(PID: %d)", name, proc.Pid), NodeProcess)
		pidMap[proc.Pid] = nodeID
	}

	for _, proc := range procs {
		ppid, err := proc.Ppid()
		if err != nil || ppid <= 0 {
			continue
		}
		srcID, ok := pidMap[ppid]
		if !ok {
			continue
		}
		dstID := pidMap[proc.Pid]
		g.AddEdge(srcID, dstID, "SPAWNS")
	}

	conns, err := netutil.Connections("all")
	if err != nil {
		return g, nil
	}
	for _, conn := range conns {
		if conn.Raddr.IP == "" || conn.Raddr.Port == 0 {
			continue
		}
		netID := fmt.Sprintf("NET_%s_%d", conn.Raddr.IP, conn.Raddr.Port)
		g.AddNode(netID, fmt.Sprintf("%s:%d", conn.Raddr.IP, conn.Raddr.Port), NodeNetwork)
		procID, ok := pidMap[conn.Pid]
		if ok {
			g.AddEdge(procID, netID, "CONNECTS_TO")
		}
	}

	return g, nil
}
