package graph

import (
	"fmt"
	"io"
	"strings"
)

// ExportDOT writes the graph in Graphviz DOT format to the writer
func (g *AttackGraph) ExportDOT(w io.Writer) error {
	if _, err := fmt.Fprintln(w, "digraph AttackGraph {"); err != nil {
		return err
	}

	// Default styles
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintln(w, "  node [shape=box, style=filled, fontname=\"Arial\"];")
	fmt.Fprintln(w, "  edge [fontname=\"Arial\", fontsize=10];")

	// Write Nodes
	for _, node := range g.Nodes {
		color := "white"
		shape := "box"

		switch node.Type {
		case NodeProcess:
			color = "#e1f5fe" // Light Blue
			shape = "component"
		case NodeNetwork:
			color = "#fff3e0" // Light Orange
			shape = "ellipse"
		case NodeFile:
			color = "#f3e5f5" // Light Purple
			shape = "note"
		}

		// Escape label quotes and newlines
		label := strings.ReplaceAll(node.Label, "\"", "\\\"")
		label = strings.ReplaceAll(label, "\n", "\\n")
		fmt.Fprintf(w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", shape=\"%s\"];\n",
			node.ID, label, color, shape)
	}

	// Write Edges
	for _, edge := range g.Edges {
		fmt.Fprintf(w, "  \"%s\" -> \"%s\" [label=\"%s\"];\n",
			edge.SourceID, edge.TargetID, edge.Label)
	}

	if _, err := fmt.Fprintln(w, "}"); err != nil {
		return err
	}
	return nil
}
