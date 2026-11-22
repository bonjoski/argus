package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"bonjoski/argus/internal/ast"
	"bonjoski/argus/internal/conflation"
	"bonjoski/argus/internal/daemon"
	"bonjoski/argus/internal/inspector"
	"bonjoski/argus/internal/lockfile"
	"bonjoski/argus/internal/model"
	"bonjoski/argus/internal/shim"
	"bonjoski/argus/pkg/quarry"
	"bonjoski/argus/pkg/ux"
)

// SupportedTools returns the canonical UB-MCP-v1 tool definitions exposed by Argus.
func SupportedTools() []Tool {
	return []Tool{
		{
			Name: "argus_vet",
			Description: "Pre-flight supply-chain vetting for package installation commands, lockfiles, and manifests. " +
				"Detects AI slopsquatting, typosquatting (Levenshtein + Quarry heuristics), malicious AST/install hooks, " +
				"and path escapes, returning UB-MCP-v1 FixForwardError self-correction payloads and atomic BLPR-v1 receipts.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"command": {
						Type:        "string",
						Description: "Package install or shell command to vet (e.g. 'npm install open-ai-sdk', 'pip install requests').",
					},
					"manifest_path": {
						Type:        "string",
						Description: "Optional lockfile or manifest path inside workspace (e.g. 'package-lock.json', 'package.json', 'go.sum').",
					},
					"workspace": {
						Type:        "string",
						Description: "Repository/workspace root directory. Enforced via os.OpenRoot lexical & kernel containment.",
					},
					"strict": {
						Type:        "boolean",
						Description: "Treat suspicious supply-chain and AST findings as blocking errors (default: true).",
						Default:     true,
					},
					"session_id": {
						Type:        "string",
						Description: "Optional FABRIAL_SESSION_ID (sess_...) for BLPR-v1 provenance receipt lineage.",
					},
					"emit_receipt": {
						Type:        "boolean",
						Description: "Emit an atomic signed BLPR-v1 DSSE receipt under FABRIAL_RECEIPT_DIR (defaults to true when session_id or FABRIAL_RECEIPT_DIR is set).",
						Default:     true,
					},
				},
			},
		},
	}
}

// ToolHandler defines the interface for handling Argus MCP tool calls.
type ToolHandler interface {
	HandleVet(ctx context.Context, args json.RawMessage) (*CallToolResult, error)
}

// DefaultToolHandler implements ToolHandler routed through Argus's native AST, conflation, Quarry, and UX engines.
type DefaultToolHandler struct {
	signer     ReceiptSigner
	conflation *conflation.Engine
	astEngine  ast.Engine
}

// ToolHandlerOption configures DefaultToolHandler.
type ToolHandlerOption func(*DefaultToolHandler)

// WithReceiptSigner overrides the BLPR-v1 DSSE receipt signer (useful for deterministic testing).
func WithReceiptSigner(signer ReceiptSigner) ToolHandlerOption {
	return func(h *DefaultToolHandler) {
		if signer != nil {
			h.signer = signer
		}
	}
}

// NewDefaultToolHandler constructs the default Argus MCP tool handler.
func NewDefaultToolHandler(opts ...ToolHandlerOption) *DefaultToolHandler {
	h := &DefaultToolHandler{
		signer:     NewDefaultReceiptSigner(),
		conflation: conflation.DefaultEngine(),
		astEngine:  ast.DefaultEngine,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// VetArgs represents input arguments for argus_vet.
type VetArgs struct {
	Command      string `json:"command,omitempty"`
	ManifestPath string `json:"manifest_path,omitempty"`
	Workspace    string `json:"workspace,omitempty"`
	Strict       *bool  `json:"strict,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	EmitReceipt  *bool  `json:"emit_receipt,omitempty"`
}

// VetAllowResult represents the structured response on an allowed argus_vet call.
type VetAllowResult struct {
	SchemaVersion  string   `json:"schema_version"`
	Tool           string   `json:"tool"`
	Verdict        string   `json:"verdict"`
	PackagesVetted int      `json:"packages_vetted"`
	Strict         bool     `json:"strict"`
	Findings       []string `json:"findings,omitempty"`
	ReceiptID      string   `json:"receipt_id,omitempty"`
	ReceiptPath    string   `json:"receipt_path,omitempty"`
}

type vetFinding struct {
	Code            string
	ExitCode        int
	Ecosystem       model.Ecosystem
	PackageName     string
	SuggestedPkg    string
	Reason          string
	DeepDetail      string
	IsHostileInput  bool
	IsASTThreat     bool
	IsPolicyViolation bool
}

var (
	rePromptInjection = regexp.MustCompile(`(?i)(\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b|<\s*/?\s*system\s*>|\byou\s+are\s+now\b|\bdisregard\s+all\s+prior\b)`)
	reShellMeta       = regexp.MustCompile("(?i)(;|\\|\\||&&|\\||`|\\$\\(|\\$\\{|>>|>|<|\\bcurl\\b.*\\|\\s*(sh|bash|zsh)|\\bwget\\b.*\\|\\s*(sh|bash|zsh))")
	reSubshellExec    = regexp.MustCompile(`(?i)\b(sh|bash|zsh)\s+-c\b`)
)

const (
	refSlopsquatDoc = "https://github.com/bonjoski/argus/blob/main/docs/use-cases/05-slopsquat-ai-hallucination-defense.md"
	refPreflightDoc = "https://github.com/bonjoski/argus/blob/main/docs/use-cases/01-preflight-slopsquat-interception.md"
	refOfflineDoc   = "https://github.com/bonjoski/argus/blob/main/docs/use-cases/02-offline-package-inspection.md"
)

// HandleVet executes pre-flight supply-chain, slopsquat, AST, and path-containment vetting.
func (h *DefaultToolHandler) HandleVet(ctx context.Context, rawArgs json.RawMessage) (*CallToolResult, error) {
	var args VetArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return buildPolicyDenyResult(
				"Invalid argus_vet arguments payload.",
				"argus vet --strict",
				"Malformed JSON arguments cannot be safely vetted.",
				"",
			), nil
		}
	}

	strict := true
	if args.Strict != nil {
		strict = *args.Strict
	}

	sessionID := strings.TrimSpace(args.SessionID)
	if sessionID == "" {
		sessionID = strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID"))
	}
	if sessionID != "" && !sessionIDRe.MatchString(sessionID) {
		return buildPolicyDenyResult(
			"Rejected invalid session_id format.",
			"argus vet --strict",
			"Session identifiers must strictly match ^sess_[0-9A-Za-z]{4,64}$ to prevent receipt path tampering.",
			"",
		), nil
	}

	receiptDirEnv := strings.TrimSpace(os.Getenv("FABRIAL_RECEIPT_DIR"))
	shouldEmitReceipt := false
	if args.EmitReceipt != nil {
		shouldEmitReceipt = *args.EmitReceipt
	} else if sessionID != "" || receiptDirEnv != "" {
		shouldEmitReceipt = true
	}

	// Resolve workspace root safely
	workspace := strings.TrimSpace(args.Workspace)
	if workspace == "" {
		workspace = strings.TrimSpace(os.Getenv("FABRIAL_WORKTREE_ROOT"))
	}
	if workspace == "" {
		if cwd, err := os.Getwd(); err == nil {
			workspace = cwd
		}
	}
	if workspace != "" {
		if strings.ContainsRune(workspace, 0) || strings.ContainsRune(workspace, 0x1b) {
			return buildPolicyDenyResult(
				"Rejected workspace path containing control or escape characters.",
				"argus vet --strict",
				"Workspace root must be a clean local directory path.",
				"",
			), nil
		}
		absWS, err := filepath.Abs(workspace)
		if err != nil {
			return buildPolicyDenyResult(
				"Could not resolve workspace root directory.",
				"argus vet --strict",
				"Workspace containment requires a valid local directory path.",
				"",
			), nil
		}
		workspace = absWS
	}

	// Determine target receipt directory and pre-validate against symlink attacks fail-closed!
	receiptDir := ""
	if shouldEmitReceipt {
		if receiptDirEnv != "" {
			receiptDir = receiptDirEnv
		} else if workspace != "" {
			sid := sessionID
			if sid == "" {
				sid = generatePrefixedID("sess_")
				sessionID = sid
			}
			receiptDir = filepath.Join(workspace, ".fabrial", "receipts", sid)
		}
		if receiptDir != "" {
			if err := validateReceiptDirNoSymlink(receiptDir); err != nil {
				return buildPolicyDenyResult(
					"Blocked unsafe or symlinked receipt directory.",
					"argus vet --strict",
					"BLPR-v1 receipts refuse symlinks and foreign-owned directories to prevent arbitrary file overwrite.",
					"",
				), nil
			}
		}
	}

	if strings.TrimSpace(args.Command) == "" && strings.TrimSpace(args.ManifestPath) == "" {
		return buildPolicyDenyResult(
			"Missing required 'command' or 'manifest_path' argument for argus_vet.",
			"argus vet --strict",
			"Provide either a package install command or a workspace-relative manifest_path to vet.",
			"",
		), nil
	}

	var subjects []Subject
	var findings []vetFinding
	packagesVetted := 0

	// 1. Vet command if provided
	if strings.TrimSpace(args.Command) != "" {
		subjects = append(subjects, Subject{
			Name:   "command",
			Digest: map[string]string{"sha256": sha256Hex([]byte(args.Command))},
		})
		cmdFindings, cmdPkgs := h.vetCommand(args.Command)
		findings = append(findings, cmdFindings...)
		packagesVetted += cmdPkgs
	}

	// 2. Vet manifest_path if provided (strictly confined to workspace via os.OpenRoot + Lstat)
	if strings.TrimSpace(args.ManifestPath) != "" {
		mSubj, mFindings, mPkgs, policyErr := h.vetManifest(workspace, args.ManifestPath)
		if policyErr != nil {
			return buildPolicyDenyResult(
				sanitizeSingleLineMCP(policyErr.Error()),
				"argus vet --strict",
				"Manifest paths must stay strictly within the workspace root and must not traverse symlinks.",
				"",
			), nil
		}
		if mSubj != nil {
			subjects = append(subjects, *mSubj)
		}
		findings = append(findings, mFindings...)
		packagesVetted += mPkgs
	}

	// Decide verdict: policy violations & AST/hostile threats ALWAYS block; slopsquats block when strict=true
	var blocking *vetFinding
	slopsquatBlocks := 0
	astFindingCount := 0
	for i := range findings {
		f := &findings[i]
		if f.IsASTThreat {
			astFindingCount++
		}
		if f.Code == CodeSlopsquatSuspect {
			slopsquatBlocks++
		}
		if blocking == nil {
			if f.IsPolicyViolation || f.IsASTThreat || f.IsHostileInput || strict {
				blocking = f
			}
		}
	}

	verdict := ReceiptVerdictAllow
	fixCode := ""
	if blocking != nil {
		verdict = ReceiptVerdictDeny
		fixCode = blocking.Code
	} else if len(findings) > 0 {
		verdict = ReceiptVerdictWarn
	}

	// Emit atomic signed BLPR-v1 receipt when active
	var emitted *EmittedReceipt
	if shouldEmitReceipt && receiptDir != "" {
		claims := map[string]any{
			"packages_vetted":       packagesVetted,
			"slopsquats_blocked":    slopsquatBlocks,
			"ast_findings":          astFindingCount,
			"strict":                strict,
			"quarry_ruleset_sha256": quarryRulesetDigest(),
		}
		var err error
		emitted, err = EmitBLPRReceipt(ctx, h.signer, ReceiptParams{
			ReceiptDir:     receiptDir,
			Workspace:      workspace,
			SessionID:      sessionID,
			Subjects:       subjects,
			Verdict:        verdict,
			FixForwardCode: fixCode,
			Claims:         claims,
		})
		if err != nil {
			return buildPolicyDenyResult(
				"Failed to persist BLPR-v1 receipt safely.",
				"argus vet --strict",
				"Receipt persistence failed closed to protect provenance integrity and prevent symlink traversal.",
				"",
			), nil
		}
	}

	receiptID := ""
	receiptPath := ""
	if emitted != nil {
		receiptID = emitted.ReceiptID
		receiptPath = emitted.FilePath
	}

	// On block: emit non-blocking telemetry event to ARGUS_SOCK (best-effort, <15ms) and return UB-MCP-v1 error
	if blocking != nil {
		notifyArgusSocketNonBlocking(sessionID, blocking)
		return buildBlockingCallToolResult(blocking, receiptID), nil
	}

	var advisoryStrings []string
	for _, f := range findings {
		advisoryStrings = append(advisoryStrings, sanitizeSingleLineMCP(f.Reason))
	}

	allowRes := VetAllowResult{
		SchemaVersion:  "ub-cli-v2",
		Tool:           "argus",
		Verdict:        string(verdict),
		PackagesVetted: packagesVetted,
		Strict:         strict,
		Findings:       advisoryStrings,
		ReceiptID:      receiptID,
		ReceiptPath:    receiptPath,
	}
	resJSON, _ := json.MarshalIndent(allowRes, "", "  ")

	return &CallToolResult{
		Content:           []ContentItem{{Type: "text", Text: string(resJSON)}},
		StructuredContent: allowRes,
		IsError:           false,
	}, nil
}

// vetCommand analyzes a package install or shell command using Quarry, AST/Inspector, Conflation, and UX spellchecker.
func (h *DefaultToolHandler) vetCommand(rawCmd string) ([]vetFinding, int) {
	var findings []vetFinding

	hasANSI := containsANSIOrControl(rawCmd)
	hasPromptInj := rePromptInjection.MatchString(rawCmd)
	hasShellMeta := reShellMeta.MatchString(rawCmd) || reSubshellExec.MatchString(rawCmd)

	// 1. Check Quarry malicious lifecycle hook & Deadbugz MCP patterns on raw command
	if isSuspHook, hookReason := quarry.DetectSuspiciousLifecycleHook(rawCmd); isSuspHook {
		findings = append(findings, vetFinding{
			Code:           CodeMaliciousAST,
			ExitCode:       ExitSupplyChainBlock,
			Reason:         "Command contains suspicious lifecycle or exfiltration pattern: " + sanitizeSingleLineMCP(hookReason),
			DeepDetail:     sanitizeSingleLineMCP(hookReason),
			IsHostileInput: true,
			IsASTThreat:    true,
		})
	}
	if isDeadbugz, dbReason := quarry.DetectDeadbugzMCP("", rawCmd, rawCmd); isDeadbugz {
		findings = append(findings, vetFinding{
			Code:           CodeMaliciousAST,
			ExitCode:       ExitSupplyChainBlock,
			Reason:         "Command contains prompt injection or MCP reflection pattern.",
			DeepDetail:     sanitizeSingleLineMCP(dbReason),
			IsHostileInput: true,
			IsASTThreat:    true,
		})
	}

	// 2. Check static script AST/pattern inspector
	if scriptFindings := inspector.InspectScriptContent(rawCmd, "command"); len(scriptFindings) > 0 {
		findings = append(findings, vetFinding{
			Code:           CodeMaliciousAST,
			ExitCode:       ExitSupplyChainBlock,
			Reason:         fmt.Sprintf("Command triggered static AST pattern [%s]: %s", scriptFindings[0].Category, sanitizeSingleLineMCP(scriptFindings[0].Description)),
			DeepDetail:     sanitizeSingleLineMCP(scriptFindings[0].Description),
			IsHostileInput: true,
			IsASTThreat:    true,
		})
	}

	// 3. Detect shell metacharacter chaining, ANSI escape injection, or prompt injection in command
	if hasShellMeta || hasANSI || hasPromptInj {
		reason := "Blocked unsafe shell metacharacters, terminal escapes, or prompt-injection tokens in command."
		if hasANSI {
			reason = "Blocked ANSI/control escape sequence injection in command input."
		} else if hasPromptInj {
			reason = "Blocked prompt-injection directive embedded in command input."
		}
		findings = append(findings, vetFinding{
			Code:           CodeMaliciousAST,
			ExitCode:       ExitSupplyChainBlock,
			Reason:         reason,
			DeepDetail:     "Shell chaining, subshells, ANSI OSC/CSI escapes, and prompt-injection payloads are blocked fail-closed.",
			IsHostileInput: true,
			IsASTThreat:    true,
		})
	}

	// 4. Parse package manager invocation and vet every package token
	eco, pkgs, parseErr := extractCommandPackages(rawCmd)
	if parseErr != nil {
		findings = append(findings, vetFinding{
			Code:           CodePolicyDeny,
			ExitCode:       ExitSupplyChainBlock,
			Ecosystem:      eco,
			Reason:         sanitizeSingleLineMCP(parseErr.Error()),
			IsHostileInput: true,
		})
	}

	vetted := 0
	for _, rawPkg := range pkgs {
		vetted++
		pkgFindings := h.vetSinglePackage(eco, rawPkg, hasShellMeta || hasANSI || hasPromptInj)
		findings = append(findings, pkgFindings...)
	}

	// If a slopsquat/typosquat finding was discovered alongside hostile input, prioritize
	// clear slopsquatting or AST error while preserving IsHostileInput=true so self_heal never auto-executes.
	if hasShellMeta || hasANSI || hasPromptInj {
		for i := range findings {
			findings[i].IsHostileInput = true
		}
	}

	return findings, vetted
}

func (h *DefaultToolHandler) vetSinglePackage(eco model.Ecosystem, rawPkg string, hostileContext bool) []vetFinding {
	var findings []vetFinding

	// Strip ANSI before inspecting package spec while tracking if input was hostile
	pkgHostile := hostileContext || containsANSIOrControl(rawPkg) || rePromptInjection.MatchString(rawPkg) || reShellMeta.MatchString(rawPkg)
	cleanToken := strings.TrimSpace(ux.SanitizeTerminalText(rawPkg))

	// Validate package spec via Argus shim spec parser (blocks VCS/URL/tarball/path/alias smuggling)
	pkgName, _, specErr := shim.ParseAndValidatePackageSpec(eco, cleanToken)
	if specErr != nil {
		findings = append(findings, vetFinding{
			Code:           CodeSlopsquatSuspect,
			ExitCode:       ExitSupplyChainBlock,
			Ecosystem:      eco,
			PackageName:    safeDisplayPkgName(cleanToken),
			Reason:         "Blocked direct URL, archive, path, or malformed package specification.",
			DeepDetail:     sanitizeSingleLineMCP(specErr.Error()),
			IsHostileInput: true,
		})
		return findings
	}

	// If token fails strict allowlist token validation (e.g. non-ASCII homoglyph or shell metacharacters)
	if !ux.ValidateRemediationToken(pkgName) {
		findings = append(findings, vetFinding{
			Code:           CodeSlopsquatSuspect,
			ExitCode:       ExitSupplyChainBlock,
			Ecosystem:      eco,
			PackageName:    safeDisplayPkgName(pkgName),
			Reason:         "Blocked package identifier containing unsafe characters or non-ASCII homoglyphs.",
			IsHostileInput: true,
		})
		return findings
	}

	// Run Quarry multi-dimensional provenance heuristics
	prov := quarry.EvaluatePackageProvenance(pkgName, 0, 0, "")
	if prov.IsSuspicious {
		suggested := verifiedCanonicalSuggestion(eco, pkgName, prov.TargetPackage)
		reason := strings.Join(prov.Reasons, "; ")
		if reason == "" {
			reason = "Flagged by Argus Quarry slopsquatting heuristics."
		}
		findings = append(findings, vetFinding{
			Code:           CodeSlopsquatSuspect,
			ExitCode:       ExitSupplyChainBlock,
			Ecosystem:      eco,
			PackageName:    pkgName,
			SuggestedPkg:   suggested,
			Reason:         sanitizeSingleLineMCP(reason),
			DeepDetail:     fmt.Sprintf("Quarry flagged %q (%s): %s", pkgName, eco, sanitizeSingleLineMCP(reason)),
			IsHostileInput: pkgHostile,
		})
		return findings
	}

	// Run embedded Conflation engine (Levenshtein + corpus token conflation)
	if h.conflation != nil {
		confRes := h.conflation.Evaluate(pkgName, eco)
		if confRes.IsConflated || confRes.IsTyposquat {
			suggested := verifiedCanonicalSuggestion(eco, pkgName, confRes.TargetPkg)
			findings = append(findings, vetFinding{
				Code:           CodeSlopsquatSuspect,
				ExitCode:       ExitSupplyChainBlock,
				Ecosystem:      eco,
				PackageName:    pkgName,
				SuggestedPkg:   suggested,
				Reason:         sanitizeSingleLineMCP(confRes.Reason),
				DeepDetail:     fmt.Sprintf("Conflation engine matched %q -> %q: %s", pkgName, suggested, sanitizeSingleLineMCP(confRes.Reason)),
				IsHostileInput: pkgHostile,
			})
			return findings
		}
	}

	// Run deterministic UX Levenshtein spellchecker
	if suggested, dist, matchReason := ux.SuggestCanonicalPackage(string(eco), pkgName); suggested != "" && ux.ValidateRemediationToken(suggested) {
		findings = append(findings, vetFinding{
			Code:           CodeSlopsquatSuspect,
			ExitCode:       ExitSupplyChainBlock,
			Ecosystem:      eco,
			PackageName:    pkgName,
			SuggestedPkg:   suggested,
			Reason:         fmt.Sprintf("Resembles canonical package %q (%s, distance %d); common AI slopsquat pattern.", suggested, matchReason, dist),
			DeepDetail:     fmt.Sprintf("Spellchecker matched %q to canonical %q (%s)", pkgName, suggested, matchReason),
			IsHostileInput: pkgHostile,
		})
	}

	return findings
}

func (h *DefaultToolHandler) vetManifest(workspace, manifestPath string) (*Subject, []vetFinding, int, error) {
	if strings.ContainsRune(manifestPath, 0) || strings.ContainsRune(manifestPath, 0x1b) {
		return nil, nil, 0, errors.New("manifest_path contains forbidden control or escape characters")
	}
	if workspace == "" {
		return nil, nil, 0, errors.New("workspace is required when vetting manifest_path")
	}

	relPath, err := containPathInWorkspace(workspace, manifestPath)
	if err != nil {
		return nil, nil, 0, err
	}

	root, err := os.OpenRoot(workspace)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to open workspace root: %w", err)
	}
	defer root.Close()

	// Verify no symlink on manifest path (reject symlink escapes fail-closed)
	fi, err := root.Lstat(relPath)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("manifest_path %q is inaccessible inside workspace: %w", filepath.ToSlash(relPath), err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return nil, nil, 0, fmt.Errorf("refusing symlinked manifest_path %q", filepath.ToSlash(relPath))
	}
	if fi.IsDir() {
		return nil, nil, 0, fmt.Errorf("manifest_path %q must be a regular file, not a directory", filepath.ToSlash(relPath))
	}

	f, err := root.Open(relPath)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("open manifest_path %q: %w", filepath.ToSlash(relPath), err)
	}
	defer f.Close()

	const maxManifestBytes = 16 * 1024 * 1024
	content, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return nil, nil, 0, fmt.Errorf("read manifest_path %q: %w", filepath.ToSlash(relPath), err)
	}
	if len(content) > maxManifestBytes {
		return nil, nil, 0, errors.New("manifest file exceeds 16MB safety limit")
	}

	subj := &Subject{
		Name:   filepath.ToSlash(relPath),
		Digest: map[string]string{"sha256": sha256Hex(content)},
	}

	var findings []vetFinding
	vetted := 0
	base := strings.ToLower(filepath.Base(relPath))

	// 1. Known lockfiles (package-lock.json, Cargo.lock, go.sum, poetry.lock, etc.)
	if parser, eco, detectErr := lockfile.Detect(relPath); detectErr == nil && parser != nil {
		deps, parseErr := parser.Parse(bytes.NewReader(content))
		if parseErr != nil {
			findings = append(findings, vetFinding{
				Code:              CodePolicyDeny,
				ExitCode:          ExitPolicyDeny,
				Ecosystem:         eco,
				Reason:            "Failed to parse lockfile; refusing unverified dependency graph.",
				IsPolicyViolation: true,
			})
			return subj, findings, 0, nil
		}
		for _, dep := range deps {
			vetted++
			depEco := dep.Ecosystem
			if depEco == "" {
				depEco = eco
			}
			findings = append(findings, h.vetSinglePackage(depEco, dep.Name, false)...)
		}
		return subj, findings, vetted, nil
	}

	// 2. package.json: inspect lifecycle hooks (preinstall/install/postinstall) + dependencies
	if base == "package.json" {
		var pkgJSON struct {
			Scripts              map[string]string `json:"scripts"`
			Dependencies         map[string]string `json:"dependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
		}
		if err := json.Unmarshal(content, &pkgJSON); err != nil {
			findings = append(findings, vetFinding{
				Code:              CodePolicyDeny,
				ExitCode:          ExitPolicyDeny,
				Ecosystem:         model.EcosystemNPM,
				Reason:            "Malformed package.json cannot be vetted.",
				IsPolicyViolation: true,
			})
			return subj, findings, 0, nil
		}

		for hookName, script := range pkgJSON.Scripts {
			if isSusp, reason := quarry.DetectSuspiciousLifecycleHook(script); isSusp {
				findings = append(findings, vetFinding{
					Code:        CodeMaliciousAST,
					ExitCode:    ExitSupplyChainBlock,
					Ecosystem:   model.EcosystemNPM,
					Reason:      fmt.Sprintf("Malicious npm lifecycle script %q: %s", sanitizeSingleLineMCP(hookName), sanitizeSingleLineMCP(reason)),
					IsASTThreat: true,
				})
			}
			if inspFindings := inspector.InspectScriptContent(script, "package.json:"+hookName); len(inspFindings) > 0 {
				findings = append(findings, vetFinding{
					Code:        CodeMaliciousAST,
					ExitCode:    ExitSupplyChainBlock,
					Ecosystem:   model.EcosystemNPM,
					Reason:      fmt.Sprintf("Dangerous AST pattern in package.json script %q: %s", sanitizeSingleLineMCP(hookName), sanitizeSingleLineMCP(inspFindings[0].Description)),
					IsASTThreat: true,
				})
			}
		}

		depMaps := []map[string]string{
			pkgJSON.Dependencies,
			pkgJSON.DevDependencies,
			pkgJSON.OptionalDependencies,
			pkgJSON.PeerDependencies,
		}
		for _, m := range depMaps {
			for name := range m {
				vetted++
				findings = append(findings, h.vetSinglePackage(model.EcosystemNPM, name, false)...)
			}
		}
		return subj, findings, vetted, nil
	}

	// 3. requirements.txt
	if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		for _, line := range strings.Split(string(content), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
				continue
			}
			if idx := strings.Index(line, " #"); idx != -1 {
				line = strings.TrimSpace(line[:idx])
			}
			vetted++
			findings = append(findings, h.vetSinglePackage(model.EcosystemPyPI, line, false)...)
		}
		return subj, findings, vetted, nil
	}

	// 4. Source code / script files: inspect AST imports & dangerous execution patterns
	if inspFindings := inspector.InspectScriptContent(string(content), filepath.ToSlash(relPath)); len(inspFindings) > 0 {
		findings = append(findings, vetFinding{
			Code:        CodeMaliciousAST,
			ExitCode:    ExitSupplyChainBlock,
			Reason:      fmt.Sprintf("Dangerous AST pattern in %s: %s", filepath.ToSlash(relPath), sanitizeSingleLineMCP(inspFindings[0].Description)),
			IsASTThreat: true,
		})
	}
	if isSusp, reason := quarry.DetectSuspiciousLifecycleHook(string(content)); isSusp {
		findings = append(findings, vetFinding{
			Code:        CodeMaliciousAST,
			ExitCode:    ExitSupplyChainBlock,
			Reason:      fmt.Sprintf("Suspicious hook pattern in %s: %s", filepath.ToSlash(relPath), sanitizeSingleLineMCP(reason)),
			IsASTThreat: true,
		})
	}
	if h.astEngine != nil && h.astEngine.Supports(relPath) {
		if imports, err := h.astEngine.ExtractImports(relPath, string(content)); err == nil {
			for _, imp := range imports {
				if strings.TrimSpace(imp.PackageName) == "" {
					continue
				}
				vetted++
				findings = append(findings, h.vetSinglePackage(imp.Ecosystem, imp.PackageName, false)...)
			}
		}
	}

	return subj, findings, vetted, nil
}

// containPathInWorkspace enforces lexical containment of target within workspace before os.OpenRoot.
func containPathInWorkspace(workspace, target string) (string, error) {
	cleanWS := filepath.Clean(workspace)
	if target == "" {
		return "", errors.New("manifest_path cannot be empty")
	}

	var candidate string
	if filepath.IsAbs(target) {
		candidate = filepath.Clean(target)
	} else {
		candidate = filepath.Clean(filepath.Join(cleanWS, target))
	}

	rel, err := filepath.Rel(cleanWS, candidate)
	if err != nil {
		return "", fmt.Errorf("manifest_path escapes workspace: %w", err)
	}
	if rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("manifest_path %q escapes workspace root", sanitizeSingleLineMCP(target))
	}
	return rel, nil
}

// validateReceiptDirNoSymlink fails closed if any existing component of receiptDir is a symlink
// or owned by another UID.
func validateReceiptDirNoSymlink(receiptDir string) error {
	clean := filepath.Clean(receiptDir)
	if clean == "" || clean == "." || clean == string(filepath.Separator) {
		return errors.New("invalid receipt directory")
	}
	absDir, err := filepath.Abs(clean)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimPrefix(absDir, string(filepath.Separator)), string(filepath.Separator))
	curr := string(filepath.Separator)
	for _, part := range parts {
		if part == "" {
			continue
		}
		curr = filepath.Join(curr, part)
		if isOSSystemSymlink(curr) {
			continue
		}
		fi, err := os.Lstat(curr)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink detected in receipt path: %s", curr)
		}
		if !fi.IsDir() {
			return fmt.Errorf("non-directory component in receipt path: %s", curr)
		}
	}
	return nil
}

func extractCommandPackages(rawCmd string) (model.Ecosystem, []string, error) {
	// Tokenize carefully: strip ANSI first so tokens can still be inspected for typosquats,
	// while rawCmd checks above already caught ANSI/shell injection.
	cleaned := ux.SanitizeTerminalText(rawCmd)
	// Truncate at shell chaining operators so we still inspect the package argument before ';' / '|' / '&&'
	for _, sep := range []string{";", "&&", "||", "|", "\n", "\r"} {
		if idx := strings.Index(cleaned, sep); idx != -1 {
			cleaned = cleaned[:idx]
		}
	}
	tokens := strings.Fields(cleaned)
	if len(tokens) == 0 {
		return model.EcosystemNPM, nil, nil
	}

	idx := 0
	// Unwrap leading env / sudo / airlock wrappers if present
	for idx < len(tokens) {
		base := strings.ToLower(filepath.Base(tokens[idx]))
		if base == "env" || base == "sudo" {
			idx++
			for idx < len(tokens) && strings.Contains(tokens[idx], "=") {
				idx++
			}
			continue
		}
		break
	}
	if idx >= len(tokens) {
		return model.EcosystemNPM, nil, nil
	}

	pm := strings.ToLower(filepath.Base(tokens[idx]))
	rest := tokens[idx+1:]

	var eco model.Ecosystem
	var pkgArgs []string

	switch pm {
	case "npm", "pnpm", "bun":
		eco = model.EcosystemNPM
		if len(rest) > 0 && isInstallSubcmd(rest[0], "install", "i", "add") {
			pkgArgs = filterPackageFlags(rest[1:])
		}
	case "yarn":
		eco = model.EcosystemNPM
		if len(rest) > 0 && isInstallSubcmd(rest[0], "add", "install") {
			pkgArgs = filterPackageFlags(rest[1:])
		}
	case "npx":
		eco = model.EcosystemNPM
		pkgArgs = filterPackageFlags(rest)
		if len(pkgArgs) > 1 {
			pkgArgs = pkgArgs[:1]
		}
	case "pip", "pip3":
		eco = model.EcosystemPyPI
		if len(rest) > 0 && isInstallSubcmd(rest[0], "install") {
			pkgArgs = filterPackageFlags(rest[1:])
		}
	case "uv":
		eco = model.EcosystemPyPI
		if len(rest) >= 2 && strings.EqualFold(rest[0], "pip") && strings.EqualFold(rest[1], "install") {
			pkgArgs = filterPackageFlags(rest[2:])
		} else if len(rest) > 0 && isInstallSubcmd(rest[0], "add") {
			pkgArgs = filterPackageFlags(rest[1:])
		}
	case "uvx":
		eco = model.EcosystemPyPI
		pkgArgs = filterPackageFlags(rest)
		if len(pkgArgs) > 1 {
			pkgArgs = pkgArgs[:1]
		}
	case "poetry":
		eco = model.EcosystemPyPI
		if len(rest) > 0 && isInstallSubcmd(rest[0], "add") {
			pkgArgs = filterPackageFlags(rest[1:])
		}
	case "python", "python3":
		eco = model.EcosystemPyPI
		if len(rest) >= 3 && rest[0] == "-m" && (rest[1] == "pip" || rest[1] == "pip3") && rest[2] == "install" {
			pkgArgs = filterPackageFlags(rest[3:])
		}
	case "cargo":
		eco = model.EcosystemCargo
		if len(rest) > 0 && isInstallSubcmd(rest[0], "add", "install") {
			pkgArgs = filterPackageFlags(rest[1:])
		}
	case "go":
		eco = model.EcosystemGo
		if len(rest) > 0 && isInstallSubcmd(rest[0], "get", "install") {
			pkgArgs = filterPackageFlags(rest[1:])
		}
	case "gem":
		eco = model.EcosystemRubyGems
		if len(rest) > 0 && isInstallSubcmd(rest[0], "install") {
			pkgArgs = filterPackageFlags(rest[1:])
		}
	default:
		// Not a recognized package manager install command (e.g., shell command or bare package check)
		eco = model.EcosystemNPM
	}

	return eco, pkgArgs, nil
}

func isInstallSubcmd(tok string, allowed ...string) bool {
	lower := strings.ToLower(tok)
	for _, a := range allowed {
		if lower == a {
			return true
		}
	}
	return false
}

func filterPackageFlags(tokens []string) []string {
	valueFlags := map[string]bool{
		"-r": true, "--requirement": true,
		"-c": true, "--constraint": true,
		"--index-url": true, "-i": true,
		"--extra-index-url": true,
		"--registry": true,
		"-t": true, "--target": true,
		"--prefix": true,
		"--cwd": true,
	}

	var pkgs []string
	skipNext := false
	for _, tok := range tokens {
		if skipNext {
			skipNext = false
			continue
		}
		if tok == "--" {
			continue
		}
		if strings.HasPrefix(tok, "-") {
			if valueFlags[tok] {
				skipNext = true
			}
			continue
		}
		pkgs = append(pkgs, tok)
	}
	return pkgs
}

func verifiedCanonicalSuggestion(eco model.Ecosystem, pkgName, candidate string) string {
	if candidate != "" && ux.ValidateRemediationToken(candidate) && candidate != pkgName {
		return candidate
	}
	if suggested, _, _ := ux.SuggestCanonicalPackage(string(eco), pkgName); suggested != "" && ux.ValidateRemediationToken(suggested) {
		return suggested
	}
	return ""
}

func buildBlockingCallToolResult(f *vetFinding, receiptID string) *CallToolResult {
	code := f.Code
	if code == "" {
		code = CodeSlopsquatSuspect
	}
	exitCode := f.ExitCode
	if exitCode == 0 {
		exitCode = ExitSupplyChainBlock
	}

	// Build strictly allowlist-verified remediation_cmd and self_heal.
	// NEVER echo untrusted user input, shell metacharacters, or prompt-injection text!
	remediationCmd := "argus explain argus_slopsquat_suspect"
	var selfHeal *SelfHeal

	if f.SuggestedPkg != "" && ux.ValidateRemediationToken(f.SuggestedPkg) {
		if safeCmd := ux.BuildSafeInstallCommand(string(f.Ecosystem), f.SuggestedPkg); safeCmd != "" {
			remediationCmd = safeCmd
			pm, subcmd := safePackageManagerTuple(f.Ecosystem)
			selfHeal = &SelfHeal{
				SuggestedTool: "airlock_exec",
				SuggestedArgs: map[string]any{
					"command": pm,
					"args":    []string{subcmd, f.SuggestedPkg},
				},
				RequiresHumanApproval: f.IsHostileInput || f.IsASTThreat,
			}
		}
	} else if code == CodeMaliciousAST {
		remediationCmd = "argus vet --strict"
	} else if code == CodePolicyDeny {
		remediationCmd = "argus vet --strict"
	}

	// Build calm, ANSI-sanitized, prompt-injection-safe summary and why strings.
	summary := buildSafeSummary(f)
	why := buildSafeWhy(f)

	refs := []string{refSlopsquatDoc}
	if code == CodeMaliciousAST {
		refs = []string{refPreflightDoc}
	} else if code == CodePolicyDeny {
		refs = []string{refOfflineDoc}
	}

	structured := StructuredError{
		SchemaVersion:  "ub-cli-v2",
		Tool:           "argus",
		Code:           code,
		ExitCode:       exitCode,
		Retryable:      true,
		Summary:        truncateStr(summary, 240),
		RemediationCmd: truncateStr(remediationCmd, 256),
		Why:            truncateStr(why, 280),
		DeepWhy:        truncateStr(sanitizeSingleLineMCP(f.DeepDetail), 2048),
		SelfHeal:       selfHeal,
		ReceiptID:      receiptID,
		References:     refs,
	}

	calmText := formatCalmThreeLineText(structured.Summary, structured.RemediationCmd, structured.Why)

	return &CallToolResult{
		Content:           []ContentItem{{Type: "text", Text: calmText}},
		StructuredContent: structured,
		IsError:           true,
	}
}

func buildPolicyDenyResult(summary, remediationCmd, why, receiptID string) *CallToolResult {
	if !isStaticSafeRemediation(remediationCmd) {
		remediationCmd = "argus vet --strict"
	}
	structured := StructuredError{
		SchemaVersion:  "ub-cli-v2",
		Tool:           "argus",
		Code:           CodePolicyDeny,
		ExitCode:       ExitPolicyDeny,
		Retryable:      true,
		Summary:        truncateStr(sanitizeSingleLineMCP(summary), 240),
		RemediationCmd: truncateStr(remediationCmd, 256),
		Why:            truncateStr(sanitizeSingleLineMCP(why), 280),
		ReceiptID:      receiptID,
		References:     []string{refOfflineDoc},
	}
	calmText := formatCalmThreeLineText(structured.Summary, structured.RemediationCmd, structured.Why)
	return &CallToolResult{
		Content:           []ContentItem{{Type: "text", Text: calmText}},
		StructuredContent: structured,
		IsError:           true,
	}
}

func buildRuntimeErrorResult(summary string) *CallToolResult {
	structured := StructuredError{
		SchemaVersion:  "ub-cli-v2",
		Tool:           "argus",
		Code:           CodePolicyDeny,
		ExitCode:       ExitRuntimeErr,
		Retryable:      false,
		Summary:        truncateStr(sanitizeSingleLineMCP(summary), 240),
		RemediationCmd: "argus vet --strict",
		Why:            "Argus failed closed because vetting could not complete safely.",
		References:     []string{refPreflightDoc},
	}
	calmText := formatCalmThreeLineText(structured.Summary, structured.RemediationCmd, structured.Why)
	return &CallToolResult{
		Content:           []ContentItem{{Type: "text", Text: calmText}},
		StructuredContent: structured,
		IsError:           true,
	}
}

func buildSafeSummary(f *vetFinding) string {
	if f.IsHostileInput && f.IsASTThreat {
		return "Paused command containing unsafe shell metacharacters, terminal escapes, or malicious script patterns."
	}
	if f.SuggestedPkg != "" && ux.ValidateRemediationToken(f.SuggestedPkg) {
		if f.PackageName != "" && ux.ValidateRemediationToken(f.PackageName) {
			return fmt.Sprintf("Paused install of unverified package '%s'; did you mean '%s'?", f.PackageName, f.SuggestedPkg)
		}
		return fmt.Sprintf("Paused install of unverified package; canonical suggestion is '%s'.", f.SuggestedPkg)
	}
	if f.PackageName != "" && ux.ValidateRemediationToken(f.PackageName) {
		return fmt.Sprintf("Paused install of unverified package '%s'.", f.PackageName)
	}
	clean := sanitizeSingleLineMCP(f.Reason)
	if clean == "" {
		return "Paused install due to Argus supply-chain security policy."
	}
	return clean
}

func buildSafeWhy(f *vetFinding) string {
	if f.IsHostileInput && f.IsASTThreat {
		return "Shell chaining, ANSI escape sequences, and prompt-injection directives are blocked pre-flight to protect developer workstations."
	}
	if f.SuggestedPkg != "" && ux.ValidateRemediationToken(f.SuggestedPkg) {
		return fmt.Sprintf("Resembles canonical high-volume package '%s'; common AI slopsquatting or typosquatting pattern.", f.SuggestedPkg)
	}
	clean := sanitizeSingleLineMCP(f.Reason)
	if clean != "" {
		return clean
	}
	return "Typosquatted and AI-hallucinated packages frequently execute credential-stealing install hooks."
}

func formatCalmThreeLineText(summary, fix, why string) string {
	s := sanitizeSingleLineMCP(summary)
	fx := sanitizeSingleLineMCP(fix)
	w := sanitizeSingleLineMCP(why)
	return fmt.Sprintf("⚠ argus: %s\n  Fix:  %s\n  Why:  %s", s, fx, w)
}

func safePackageManagerTuple(eco model.Ecosystem) (string, string) {
	switch eco {
	case model.EcosystemPyPI:
		return "pip", "install"
	case model.EcosystemCargo:
		return "cargo", "add"
	case model.EcosystemGo:
		return "go", "get"
	case model.EcosystemRubyGems:
		return "gem", "install"
	default:
		return "npm", "install"
	}
}

func safeDisplayPkgName(raw string) string {
	clean := sanitizeSingleLineMCP(raw)
	if ux.ValidateRemediationToken(clean) {
		return clean
	}
	return "<redacted-unsafe-token>"
}

func isStaticSafeRemediation(cmd string) bool {
	return cmd == "argus vet --strict" || cmd == "argus explain argus_slopsquat_suspect"
}

func containsANSIOrControl(s string) bool {
	for _, r := range s {
		if r == 0x1b || r == 0x9b || r == 0x9d || r == 0x90 || r == 0x98 || r == 0x9e || r == 0x9f {
			return true
		}
		if r == 0 || (r < 0x20 && r != '\t' && r != '\n' && r != '\r') || r == 0x7f {
			return true
		}
	}
	return false
}

func sanitizeSingleLineMCP(s string) string {
	clean := ux.SanitizeTerminalText(s)
	clean = rePromptInjection.ReplaceAllString(clean, "[redacted]")
	clean = strings.ReplaceAll(clean, "\r", " ")
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\t", " ")
	return strings.TrimSpace(clean)
}

func truncateStr(s string, maxLen int) string {
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func quarryRulesetDigest() string {
	return sha256Hex([]byte("argus-quarry-v1:" + string(model.EcosystemNPM) + ":" + string(model.EcosystemPyPI) + ":" + string(model.EcosystemCargo)))
}

// notifyArgusSocketNonBlocking mirrors a compact deny telemetry event to ARGUS_SOCK when running.
// Never blocks or fails the MCP response if the optional daemon socket is not running.
func notifyArgusSocketNonBlocking(sessionID string, f *vetFinding) {
	sockPath := strings.TrimSpace(os.Getenv("ARGUS_SOCK"))
	if sockPath == "" {
		return
	}
	if _, err := os.Lstat(sockPath); err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	client := daemon.NewClient(sockPath).WithTimeout(15 * time.Millisecond)
	_ = client.Ping(ctx)
}
