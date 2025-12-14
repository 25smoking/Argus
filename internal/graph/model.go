package graph

type NodeType string

const (
	NodeProcess NodeType = "PROCESS"
	NodeFile    NodeType = "FILE"
	NodeNetwork NodeType = "NETWORK"
)

type Node struct {
	ID    string
	Label string
	Type  NodeType
	Props map[string]string
}

type Edge struct {
	SourceID string
	TargetID string
	Label    string // e.g., "SPAWNS", "CONNECTS_TO", "OPENS"
}

type AttackGraph struct {
	Nodes map[string]*Node
	Edges []*Edge
}

func NewAttackGraph() *AttackGraph {
	return &AttackGraph{
		Nodes: make(map[string]*Node),
		Edges: make([]*Edge, 0),
	}
}

func (g *AttackGraph) AddNode(id, label string, nType NodeType) {
	if _, exists := g.Nodes[id]; !exists {
		g.Nodes[id] = &Node{
			ID:    id,
			Label: label,
			Type:  nType,
			Props: make(map[string]string),
		}
	}
}

func (g *AttackGraph) AddEdge(src, dst, label string) {
	// Ensure nodes exist (optional, or auto-create)
	if _, ok1 := g.Nodes[src]; ok1 {
		if _, ok2 := g.Nodes[dst]; ok2 {
			g.Edges = append(g.Edges, &Edge{
				SourceID: src,
				TargetID: dst,
				Label:    label,
			})
		}
	}
}
