package core

type ScanReport struct {
	ScanSession    ScanSession     `json:"scan_session"`
	RuleBundle     *RuleBundleInfo `json:"rule_bundle,omitempty"`
	Profile        string          `json:"profile"`
	Coverage       Coverage        `json:"coverage"`
	Summary        Summary         `json:"summary"`
	Findings       []Result        `json:"findings"`
	Evidence       []EvidenceItem  `json:"evidence"`
	Timeline       []TimelineItem  `json:"timeline"`
	SkippedModules []SkippedModule `json:"skipped_modules"`
	AttackGraph    *GraphSnapshot  `json:"attack_graph,omitempty"`
}

type ScanSession struct {
	CaseID            string `json:"case_id,omitempty"`
	Hostname          string `json:"hostname"`
	User              string `json:"user,omitempty"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	StartedAt         string `json:"started_at"`
	EndedAt           string `json:"ended_at"`
	Duration          string `json:"duration"`
	Offline           bool   `json:"offline"`
	NoNetwork         bool   `json:"no_network"`
	NetworkPolicyText string `json:"network_policy_text,omitempty"`
}

type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Pass     int `json:"pass"`
	Error    int `json:"error"`
	Total    int `json:"total"`
}

type EvidenceItem struct {
	ID      string `json:"id"`
	Plugin  string `json:"plugin"`
	Summary string `json:"summary"`
}

type TimelineItem struct {
	Time    string `json:"time"`
	Plugin  string `json:"plugin"`
	Level   string `json:"level"`
	Summary string `json:"summary"`
}

type GraphSnapshot struct {
	DotPath string `json:"dot_path"`
	Nodes   int    `json:"nodes"`
	Edges   int    `json:"edges"`
}

func Summarize(results []Result) Summary {
	var s Summary
	for _, r := range results {
		switch normalizeLevel(r.Level) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low", "warning", "notice":
			s.Low++
		case "pass":
			s.Pass++
		case "error":
			s.Error++
		default:
			s.Info++
		}
	}
	s.Total = len(results)
	return s
}

func normalizeLevel(level string) string {
	switch level {
	case "CRITICAL", "Critical":
		return "critical"
	case "HIGH", "High":
		return "high"
	case "MEDIUM", "Medium":
		return "medium"
	case "LOW", "Low":
		return "low"
	case "INFO", "Info":
		return "info"
	default:
		return level
	}
}
