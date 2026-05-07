package graph

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/25smoking/Argus/internal/core"
)

var networkEvidenceRE = regexp.MustCompile(`^(.+)\((\d+)\)\s+->\s+(.+):(\d+)(?:/(\w+))?$`)

func BuildFromReport(report core.ScanReport) *AttackGraph {
	g := NewAttackGraph()
	hostID := "host"
	hostname := report.ScanSession.Hostname
	hostLabel := fmt.Sprintf("%s\n%s/%s", hostname, report.ScanSession.OS, report.ScanSession.Arch)
	g.AddNode(hostID, hostLabel, NodeHost)

	for idx, finding := range report.Findings {
		if strings.EqualFold(finding.Level, "pass") {
			continue
		}
		pluginID := safeID("plugin_" + finding.Plugin)
		g.AddNode(pluginID, finding.Plugin, NodePlugin)
		g.AddEdge(hostID, pluginID, "SCANNED_BY")

		findingID := fmt.Sprintf("finding_%03d", idx+1)
		g.AddNodeWithProps(findingID, fmt.Sprintf("%s\n%s", strings.ToUpper(finding.Level), finding.Description), NodeFinding, map[string]string{"level": finding.Level})
		g.AddEdge(pluginID, findingID, "FOUND")

		if finding.RuleName != "" {
			ruleID := safeID("rule_" + finding.RuleName)
			g.AddNode(ruleID, finding.RuleName, NodeRule)
			g.AddEdge(ruleID, findingID, "MATCHED")
		}

		addEvidenceNodes(g, findingID, finding)
	}

	return g
}

func addEvidenceNodes(g *AttackGraph, findingID string, finding core.Result) {
	evidence := finding.Evidence
	if len(evidence) == 0 && finding.Reference != "" {
		evidence = []string{finding.Reference}
	}
	for idx, item := range evidence {
		if idx >= 12 {
			break
		}
		if match := networkEvidenceRE.FindStringSubmatch(item); len(match) >= 5 {
			processName, pid, endpoint, port := match[1], match[2], match[3], match[4]
			procID := safeID("proc_" + processName + "_" + pid)
			netID := safeID("net_" + endpoint + "_" + port)
			g.AddNode(procID, fmt.Sprintf("%s\nPID %s", processName, pid), NodeProcess)
			g.AddNode(netID, endpoint+":"+port, NodeNetwork)
			g.AddEdge(procID, netID, "CONNECTS_TO")
			g.AddEdge(findingID, procID, "EVIDENCE")
			continue
		}
		nodeType := NodeEvidence
		if looksLikePath(item) {
			nodeType = NodeFile
		}
		evID := safeID(fmt.Sprintf("ev_%s_%d", findingID, idx))
		g.AddNode(evID, truncateLabel(item, 120), nodeType)
		g.AddEdge(findingID, evID, "EVIDENCE")
	}
}

func safeID(value string) string {
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "node"
	}
	return out
}

func looksLikePath(value string) bool {
	return strings.HasPrefix(value, "/") || strings.Contains(value, ":\\") || strings.Contains(value, "\\")
}

func truncateLabel(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
