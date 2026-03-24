package output

type ProtectionRecord struct {
	Host                     string   `json:"host"`
	Provider                 string   `json:"provider"`
	Class                    string   `json:"class"`
	DetectionMode            string   `json:"detection_mode"`
	MatchedTarget            string   `json:"matched_target"`
	FinalCNAME               string   `json:"final_cname"`
	Owner                    string   `json:"owner,omitempty"`
	CheckedTXTNames          []string `json:"checked_txt_names"`
	TXTHits                  []string `json:"txt_hits"`
	ProtectionReason         string   `json:"protection_reason"`
	DetectionReason          string   `json:"detection_reason"`
	ResolverUsed             string   `json:"resolver_used"`
	Status                   string   `json:"status"`
	Severity                 string   `json:"severity"`
	Confidence               string   `json:"confidence"`
	Tags                     []string `json:"tags"`
	ManualValidationRequired bool     `json:"manual_validation_required"`
}

type FindingRecord struct {
	Host                     string   `json:"host"`
	Provider                 string   `json:"provider"`
	Class                    string   `json:"class"`
	DetectionMode            string   `json:"detection_mode"`
	MatchedTarget            string   `json:"matched_target"`
	FinalCNAME               string   `json:"final_cname"`
	FindingType              string   `json:"finding_type"`
	Evidence                 []string `json:"evidence"`
	DetectionReason          string   `json:"detection_reason"`
	ResolverUsed             string   `json:"resolver_used"`
	Status                   string   `json:"status"`
	Severity                 string   `json:"severity"`
	Confidence               string   `json:"confidence"`
	Tags                     []string `json:"tags"`
	ManualValidationRequired bool     `json:"manual_validation_required"`
}

type ErrorRecord struct {
	Host         string `json:"host"`
	Provider     string `json:"provider,omitempty"`
	Stage        string `json:"stage"`
	Error        string `json:"error"`
	ResolverUsed string `json:"resolver_used"`
}

type Summary struct {
	TotalInputHosts uint64 `json:"total_input_hosts"`
	ProviderMatches uint64 `json:"provider_matches"`
	Protected       uint64 `json:"protected"`
	Unprotected     uint64 `json:"unprotected"`
	Findings        uint64 `json:"findings"`
	Errors          uint64 `json:"errors"`
}
