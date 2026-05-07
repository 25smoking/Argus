package graph

type NodeType string

const (
	NodeHost     NodeType = "HOST"
	NodePlugin   NodeType = "PLUGIN"
	NodeFinding  NodeType = "FINDING"
	NodeRule     NodeType = "RULE"
	NodeEvidence NodeType = "EVIDENCE"
	NodeProcess  NodeType = "PROCESS"
	NodeFile     NodeType = "FILE"
	NodeNetwork  NodeType = "NETWORK"
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
	Nodes   map[string]*Node
	Edges   []*Edge
	edgeSet map[string]bool
}

func NewAttackGraph() *AttackGraph {
	return &AttackGraph{
		Nodes:   make(map[string]*Node),
		Edges:   make([]*Edge, 0),
		edgeSet: make(map[string]bool),
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

func (g *AttackGraph) AddNodeWithProps(id, label string, nType NodeType, props map[string]string) {
	g.AddNode(id, label, nType)
	for k, v := range props {
		g.Nodes[id].Props[k] = v
	}
}

func (g *AttackGraph) AddEdge(src, dst, label string) {
	// Ensure nodes exist (optional, or auto-create)
	if _, ok1 := g.Nodes[src]; ok1 {
		if _, ok2 := g.Nodes[dst]; ok2 {
			key := src + "\x00" + dst + "\x00" + label
			if g.edgeSet[key] {
				return
			}
			g.edgeSet[key] = true
			g.Edges = append(g.Edges, &Edge{
				SourceID: src,
				TargetID: dst,
				Label:    label,
			})
		}
	}
}
