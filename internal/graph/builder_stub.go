//go:build !windows

package graph

import "fmt"

func BuildSnapshot() (*AttackGraph, error) {
	return nil, fmt.Errorf("graph generation is not yet supported on this operating system")
}
