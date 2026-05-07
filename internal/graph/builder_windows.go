package graph

import (
	"fmt"

	winsys "github.com/25smoking/Argus/internal/sys/windows"
)

// BuildSnapshot captures the current system state (Process Tree + Network)
// and constructs an AttackGraph.
func BuildSnapshot() (*AttackGraph, error) {
	g := NewAttackGraph()

	// 1. Get Processes
	procs, err := winsys.GetProcessList()
	if err != nil {
		return nil, fmt.Errorf("failed to get process list: %v", err)
	}

	// Helper to track known PIDs for faster lookup
	pidMap := make(map[uint32]string)

	// Add Process Nodes
	for _, p := range procs {
		nodeID := fmt.Sprintf("PROC_%d", p.PID)
		label := fmt.Sprintf("%s\n(PID: %d)", p.Name, p.PID)
		if p.Name == "" {
			label = fmt.Sprintf("Unknown\n(PID: %d)", p.PID)
		}

		g.AddNode(nodeID, label, NodeProcess)
		pidMap[p.PID] = nodeID
	}

	// Add Parent-Child Edges (SPAWN)
	for _, p := range procs {
		if p.PPID != 0 {
			srcID := fmt.Sprintf("PROC_%d", p.PPID)
			dstID := fmt.Sprintf("PROC_%d", p.PID)
			// Only add edge if parent exists in our snapshot
			if _, ok := pidMap[p.PPID]; ok {
				g.AddEdge(srcID, dstID, "SPAWNS")
			}
		}
	}

	// 2. Get Network Connections
	conns, err := winsys.GetTcpConnections()
	if err == nil {
		for _, c := range conns {
			// Create Network Node
			// RemoteAddr:RemotePort
			if c.RemotePort == 0 {
				continue // Skip listening ports for now, or handle differently
			}

			remoteAddr := fmt.Sprintf("%s:%d", c.RemoteAddr, c.RemotePort)
			netNodeID := fmt.Sprintf("NET_%s", remoteAddr)

			g.AddNode(netNodeID, remoteAddr, NodeNetwork)

			// Link Process -> Network
			// Field is OwnerPID, not PID
			procID := fmt.Sprintf("PROC_%d", c.OwnerPID)
			if _, ok := pidMap[c.OwnerPID]; ok {
				g.AddEdge(procID, netNodeID, "CONNECTS_TO")
			}
		}
	}

	return g, nil
}
