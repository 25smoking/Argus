package graph

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

func RenderSVG(g *AttackGraph) string {
	if g == nil || len(g.Nodes) == 0 {
		return ""
	}

	type positioned struct {
		Node *Node
		X    int
		Y    int
	}

	columns := []NodeType{NodeHost, NodePlugin, NodeRule, NodeFinding, NodeProcess, NodeNetwork, NodeFile, NodeEvidence}
	nodesByType := make(map[NodeType][]*Node)
	for _, node := range g.Nodes {
		nodesByType[node.Type] = append(nodesByType[node.Type], node)
	}
	for typ := range nodesByType {
		sort.Slice(nodesByType[typ], func(i, j int) bool {
			return nodesByType[typ][i].Label < nodesByType[typ][j].Label
		})
	}

	positions := make(map[string]positioned)
	maxRows := 1
	xStep, yStep := 170, 86
	for col, typ := range columns {
		nodes := nodesByType[typ]
		if len(nodes) > 10 {
			nodes = nodes[:10]
		}
		if len(nodes) > maxRows {
			maxRows = len(nodes)
		}
		for row, node := range nodes {
			positions[node.ID] = positioned{Node: node, X: 28 + col*xStep, Y: 34 + row*yStep}
		}
	}

	width := 28 + len(columns)*xStep
	height := 90 + maxRows*yStep
	out := fmt.Sprintf(`<svg class="attack-svg" viewBox="0 0 %d %d" role="img" aria-label="Argus attack graph">`, width, height)
	out += `<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L0,6 L7,3 z" fill="#64748b"/></marker></defs>`

	edgeCount := 0
	for _, edge := range g.Edges {
		src, ok1 := positions[edge.SourceID]
		dst, ok2 := positions[edge.TargetID]
		if !ok1 || !ok2 {
			continue
		}
		if edgeCount >= 80 {
			break
		}
		x1, y1 := src.X+132, src.Y+26
		x2, y2 := dst.X, dst.Y+26
		out += fmt.Sprintf(`<path d="M%d %d C%d %d,%d %d,%d %d" fill="none" stroke="#94a3b8" stroke-width="1.2" marker-end="url(#arrow)"/>`, x1, y1, x1+45, y1, x2-45, y2, x2, y2)
		edgeCount++
	}

	nodes := make([]positioned, 0, len(positions))
	for _, pos := range positions {
		nodes = append(nodes, pos)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].X == nodes[j].X {
			return nodes[i].Y < nodes[j].Y
		}
		return nodes[i].X < nodes[j].X
	})
	for _, pos := range nodes {
		color := svgColor(pos.Node)
		label := html.EscapeString(strings.ReplaceAll(truncateLabel(pos.Node.Label, 42), "\n", " / "))
		out += fmt.Sprintf(`<g><rect x="%d" y="%d" width="132" height="52" rx="8" fill="%s" stroke="#cbd5e1"/><text x="%d" y="%d" font-size="10" fill="#0f172a"><tspan>%s</tspan></text><text x="%d" y="%d" font-size="8" fill="#64748b">%s</text></g>`,
			pos.X, pos.Y, color, pos.X+9, pos.Y+22, label, pos.X+9, pos.Y+39, html.EscapeString(string(pos.Node.Type)))
	}
	out += `</svg>`
	return out
}

func svgColor(node *Node) string {
	switch node.Type {
	case NodeHost:
		return "#dbeafe"
	case NodePlugin:
		return "#e0f2fe"
	case NodeFinding:
		return colorForSeverity(node.Props["level"])
	case NodeRule:
		return "#fef3c7"
	case NodeProcess:
		return "#ccfbf1"
	case NodeNetwork:
		return "#ffedd5"
	case NodeFile:
		return "#f5f3ff"
	default:
		return "#f8fafc"
	}
}
