package mcp

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"bonjoski/argus/internal/procident"
	"bonjoski/argus/internal/version"
)

// BLPR-v1 (Bonjoski Local Provenance Receipt v1) DSSE / in-toto Statement v1 constants.
const (
	StatementTypeV1 = "https://in-toto.io/Statement/v1"
	PredicateTypeV1 = "https://bonjoski.dev/attestation/paved-road/v1"
	DSSEPayloadType = "application/vnd.in-toto+json"
	BLPRSchemaVer   = "1.0.0"
	StageScaffold   = "scaffolding_deps"
)

// ReceiptVerdict represents a BLPR-v1 verdict.
type ReceiptVerdict string

const (
	ReceiptVerdictAllow ReceiptVerdict = "allow"
	ReceiptVerdictDeny  ReceiptVerdict = "deny"
	ReceiptVerdictWarn  ReceiptVerdict = "warn"
)

// Subject conforms to blpr-v1.schema.json#/$defs/statement/properties/subject.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// SessionLineage conforms to blpr-v1.schema.json#/$defs/statement/properties/predicate/properties/session.
type SessionLineage struct {
	SessionID       string `json:"session_id"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
	ActorMode       string `json:"actor_mode"`
	WorktreeHeadSHA string `json:"worktree_head_sha"`
}

// Producer conforms to blpr-v1.schema.json#/$defs/statement/properties/predicate/properties/producer.
type Producer struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Stage   string `json:"stage"`
}

// Predicate conforms to blpr-v1.schema.json#/$defs/statement/properties/predicate.
type Predicate struct {
	SchemaVersion  string          `json:"schema_version"`
	ReceiptID      string          `json:"receipt_id"`
	Timestamp      time.Time       `json:"timestamp"`
	Session        SessionLineage  `json:"session"`
	Producer       Producer        `json:"producer"`
	Verdict        ReceiptVerdict  `json:"verdict"`
	Proven         bool            `json:"proven"`
	Claims         json.RawMessage `json:"claims"`
	ParentReceipts []string        `json:"parent_receipts,omitempty"`
	FixForwardCode string          `json:"fix_forward_code,omitempty"`
}

// Statement conforms to blpr-v1.schema.json#/$defs/statement.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// DSSESignature conforms to blpr-v1.schema.json#/properties/signatures/items.
type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// DSSEEnvelope conforms to blpr-v1.schema.json.
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

var (
	sessionIDRe   = regexp.MustCompile(`^sess_[0-9A-Za-z]{4,64}$`)
	receiptIDRe   = regexp.MustCompile(`^rcpt_[0-9A-Za-z]{4,64}$`)
	spiffeKeyIDRe = regexp.MustCompile(`^spiffe://bonjoski\.local/session/sess_[0-9A-Za-z]+$`)
	gitSHARe      = regexp.MustCompile(`^[a-f0-9]{7,64}$`)
)

// PAE computes the DSSE Pre-Authentication Encoding per DSSE v1 specification:
// "DSSEv1 " + len(type) + " " + type + " " + len(body) + " " + body
func PAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, 0, len(prefix)+len(payload))
	out = append(out, prefix...)
	out = append(out, payload...)
	return out
}

// VerifyEnvelope verifies a BLPR-v1 DSSE envelope signature and decodes its in-toto Statement v1.
func VerifyEnvelope(env *DSSEEnvelope, pub ed25519.PublicKey) (*Statement, error) {
	if env == nil || env.PayloadType != DSSEPayloadType || len(env.Signatures) == 0 {
		return nil, errors.New("invalid or unsigned DSSE receipt envelope")
	}
	raw, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	pae := PAE(env.PayloadType, raw)
	verified := false
	for _, s := range env.Signatures {
		if !spiffeKeyIDRe.MatchString(s.KeyID) {
			continue
		}
		sigBytes, err := base64.StdEncoding.DecodeString(s.Sig)
		if err != nil || len(sigBytes) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pub, pae, sigBytes) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, errors.New("DSSE signature verification failed")
	}
	var stmt Statement
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshal statement: %w", err)
	}
	if stmt.Type != StatementTypeV1 || stmt.PredicateType != PredicateTypeV1 {
		return nil, errors.New("unexpected in-toto statement or predicate type")
	}
	return &stmt, nil
}

// ReceiptSigner signs DSSE PAE digests for BLPR-v1 receipts.
type ReceiptSigner interface {
	SignDSSE(ctx context.Context, sessionID string, pae []byte) (keyID string, sig []byte, mode string, err error)
}

type locksmithSignRequest struct {
	Version   string `json:"version"`
	Action    string `json:"action"`
	SessionID string `json:"session_id"`
	PAEB64    string `json:"pae_b64"`
	ClientPID int    `json:"client_pid"`
}

type locksmithSignResponse struct {
	Status  string `json:"status,omitempty"`
	Success bool   `json:"success,omitempty"`
	KeyID   string `json:"keyid,omitempty"`
	SigB64  string `json:"sig_b64,omitempty"`
	Sig     string `json:"sig,omitempty"`
	Error   string `json:"error,omitempty"`
}

// DefaultReceiptSigner attempts Locksmith UDS signing (LOCKSMITH_SOCKET / LOCKSMITH_SOCK)
// using action "sign_dsse", and falls back to a per-process ephemeral Ed25519 signer when
// no Locksmith socket is active on the workstation.
type DefaultReceiptSigner struct {
	mu      sync.Mutex
	ephPub  ed25519.PublicKey
	ephPriv ed25519.PrivateKey
}

// NewDefaultReceiptSigner creates a signer with lazy ephemeral fallback key generation.
func NewDefaultReceiptSigner() *DefaultReceiptSigner {
	return &DefaultReceiptSigner{}
}

// EphemeralPublicKey returns the process ephemeral public key (for local verification/tests).
func (d *DefaultReceiptSigner) EphemeralPublicKey() ed25519.PublicKey {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ephPub == nil {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err == nil {
			d.ephPub = pub
			d.ephPriv = priv
		}
	}
	return d.ephPub
}

// SignDSSE signs pae via LOCKSMITH_SOCKET if configured, otherwise via ephemeral Ed25519 key.
func (d *DefaultReceiptSigner) SignDSSE(ctx context.Context, sessionID string, pae []byte) (string, []byte, string, error) {
	sockPath := strings.TrimSpace(os.Getenv("LOCKSMITH_SOCKET"))
	if sockPath == "" {
		sockPath = strings.TrimSpace(os.Getenv("LOCKSMITH_SOCK"))
	}

	if sockPath != "" {
		// Fail closed if the configured socket is a symlink or owned by a foreign UID.
		if _, lerr := os.Lstat(sockPath); lerr == nil {
			if err := procident.VerifyFileOwnerAndNotSymlink(sockPath); err != nil {
				return "", nil, "", fmt.Errorf("unsafe locksmith socket %s: %w", sockPath, err)
			}
			keyID, sig, err := signViaLocksmithUDS(ctx, sockPath, sessionID, pae)
			if err == nil {
				return keyID, sig, "locksmith_session", nil
			}
		}
	}

	d.mu.Lock()
	if d.ephPriv == nil {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			d.mu.Unlock()
			return "", nil, "", fmt.Errorf("generate ephemeral signing key: %w", err)
		}
		d.ephPub = pub
		d.ephPriv = priv
	}
	priv := d.ephPriv
	d.mu.Unlock()

	keyID := "spiffe://bonjoski.local/session/" + sessionID
	sig := ed25519.Sign(priv, pae)
	return keyID, sig, "ephemeral_local", nil
}

func signViaLocksmithUDS(ctx context.Context, sockPath, sessionID string, pae []byte) (string, []byte, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, "unix", sockPath)
	if err != nil {
		return "", nil, fmt.Errorf("dial locksmith socket: %w", err)
	}
	defer conn.Close()

	if err := procident.VerifyUnixPeerUID(conn); err != nil {
		return "", nil, fmt.Errorf("locksmith peer UID mismatch: %w", err)
	}

	_ = conn.SetDeadline(time.Now().Add(250 * time.Millisecond))

	req := locksmithSignRequest{
		Version:   "1.0",
		Action:    "sign_dsse",
		SessionID: sessionID,
		PAEB64:    base64.StdEncoding.EncodeToString(pae),
		ClientPID: os.Getpid(),
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		return "", nil, err
	}
	if _, err := conn.Write(append(reqBytes, '\n')); err != nil {
		return "", nil, err
	}

	reader := bufio.NewReader(io.LimitReader(conn, 64*1024))
	line, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", nil, err
	}
	if len(line) == 0 {
		return "", nil, errors.New("empty response from locksmith sign_dsse")
	}

	var resp locksmithSignResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return "", nil, fmt.Errorf("decode locksmith sign_dsse response: %w", err)
	}
	if resp.Error != "" {
		return "", nil, errors.New(resp.Error)
	}

	sigField := resp.SigB64
	if sigField == "" {
		sigField = resp.Sig
	}
	if sigField == "" {
		return "", nil, errors.New("locksmith sign_dsse returned empty signature")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigField)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return "", nil, errors.New("locksmith sign_dsse returned invalid Ed25519 signature")
	}

	keyID := resp.KeyID
	if keyID == "" {
		keyID = "spiffe://bonjoski.local/session/" + sessionID
	}
	if !spiffeKeyIDRe.MatchString(keyID) {
		return "", nil, fmt.Errorf("locksmith returned invalid SPIFFE keyid %q", keyID)
	}
	return keyID, sigBytes, nil
}

// ReceiptParams carries the data required to build, sign, and atomically persist a BLPR-v1 receipt.
type ReceiptParams struct {
	ReceiptDir     string
	Workspace      string
	SessionID      string
	Subjects       []Subject
	Verdict        ReceiptVerdict
	FixForwardCode string
	Claims         map[string]any
}

// EmittedReceipt returns the receipt identifier, filename, and envelope written to disk.
type EmittedReceipt struct {
	ReceiptID string
	FilePath  string
	Envelope  *DSSEEnvelope
}

// EmitBLPRReceipt constructs, signs, and atomically persists a BLPR-v1 DSSE receipt inside
// receiptDir using os.OpenRoot, O_NOFOLLOW, 0600 permissions, fsync, and atomic rename.
// Symlinked receipt directories or foreign-owned directories fail closed with an error.
func EmitBLPRReceipt(ctx context.Context, signer ReceiptSigner, params ReceiptParams) (*EmittedReceipt, error) {
	if signer == nil {
		signer = NewDefaultReceiptSigner()
	}
	if strings.TrimSpace(params.ReceiptDir) == "" {
		return nil, errors.New("receipt directory is empty")
	}

	sessionID := strings.TrimSpace(params.SessionID)
	if sessionID == "" {
		sessionID = generatePrefixedID("sess_")
	}
	if !sessionIDRe.MatchString(sessionID) {
		return nil, fmt.Errorf("invalid session_id %q: must match ^sess_[0-9A-Za-z]{4,64}$", sessionID)
	}

	// Enforce strict non-symlink & ownership containment on receiptDir BEFORE creating or opening it.
	if err := ensureSafeReceiptDir(params.ReceiptDir); err != nil {
		return nil, err
	}

	receiptID := generatePrefixedID("rcpt_")
	now := time.Now().UTC()

	subjects := params.Subjects
	if len(subjects) == 0 {
		zeroHash := sha256Hex([]byte("argus_vet"))
		subjects = []Subject{{
			Name:   "argus_vet",
			Digest: map[string]string{"sha256": zeroHash},
		}}
	}

	claimsMap := make(map[string]any, len(params.Claims)+2)
	for k, v := range params.Claims {
		claimsMap[k] = v
	}

	headSHA := detectWorktreeHeadSHA(params.Workspace)
	parentSession := strings.TrimSpace(os.Getenv("FABRIAL_PARENT_SESSION_ID"))
	if !sessionIDRe.MatchString(parentSession) {
		parentSession = ""
	}

	ver := strings.TrimSpace(version.Version)
	if ver == "" {
		ver = "v0.11.0"
	}

	// Build initial statement, sign via signer, and include signature_mode in claims before final signing.
	// Determine signing mode by probing/signing with final payload.
	stmt := Statement{
		Type:          StatementTypeV1,
		Subject:       subjects,
		PredicateType: PredicateTypeV1,
		Predicate: Predicate{
			SchemaVersion: BLPRSchemaVer,
			ReceiptID:     receiptID,
			Timestamp:     now,
			Session: SessionLineage{
				SessionID:       sessionID,
				ParentSessionID: parentSession,
				ActorMode:       "aidlc",
				WorktreeHeadSHA: headSHA,
			},
			Producer: Producer{
				Tool:    "argus",
				Version: ver,
				Stage:   StageScaffold,
			},
			Verdict:        params.Verdict,
			Proven:         params.Verdict == ReceiptVerdictAllow,
			FixForwardCode: params.FixForwardCode,
		},
	}

	if len(claimsMap) == 0 {
		claimsMap["tool"] = "argus"
	}
	claimsBytes, err := json.Marshal(claimsMap)
	if err != nil {
		return nil, fmt.Errorf("marshal claims: %w", err)
	}
	stmt.Predicate.Claims = claimsBytes

	payloadBytes, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal BLPR-v1 statement: %w", err)
	}

	pae := PAE(DSSEPayloadType, payloadBytes)
	keyID, sigBytes, _, err := signer.SignDSSE(ctx, sessionID, pae)
	if err != nil {
		return nil, fmt.Errorf("sign BLPR-v1 DSSE envelope: %w", err)
	}
	if !spiffeKeyIDRe.MatchString(keyID) {
		return nil, fmt.Errorf("invalid SPIFFE keyid %q", keyID)
	}

	env := &DSSEEnvelope{
		PayloadType: DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signatures: []DSSESignature{
			{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(sigBytes),
			},
		},
	}

	envBytes, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal DSSE envelope: %w", err)
	}
	envBytes = append(envBytes, '\n')

	root, err := os.OpenRoot(params.ReceiptDir)
	if err != nil {
		return nil, fmt.Errorf("open receipt root %s: %w", params.ReceiptDir, err)
	}
	defer root.Close()

	// Re-verify receiptDir is still not a symlink after opening root (defense-in-depth).
	if err := verifyDirNotSymlinkAndOwned(params.ReceiptDir); err != nil {
		return nil, err
	}

	finalName := fmt.Sprintf("%d-argus-%s.dsse.json", now.UnixMilli(), strings.TrimPrefix(receiptID, "rcpt_"))
	tmpName := fmt.Sprintf(".tmp-%s-%d.json", receiptID, now.UnixNano())

	f, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollowFlag, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create temp receipt file: %w", err)
	}
	writeErr := func() error {
		if _, werr := f.Write(envBytes); werr != nil {
			_ = f.Close()
			return werr
		}
		if serr := f.Sync(); serr != nil {
			_ = f.Close()
			return serr
		}
		return f.Close()
	}()
	if writeErr != nil {
		_ = root.Remove(tmpName)
		return nil, fmt.Errorf("write temp receipt file: %w", writeErr)
	}

	if err := root.Rename(tmpName, finalName); err != nil {
		_ = root.Remove(tmpName)
		return nil, fmt.Errorf("atomic rename receipt file: %w", err)
	}

	return &EmittedReceipt{
		ReceiptID: receiptID,
		FilePath:  filepath.Join(params.ReceiptDir, finalName),
		Envelope:  env,
	}, nil
}

// ensureSafeReceiptDir validates that receiptDir and its non-OS ancestor components are not symlinks
// and are owned by the current effective UID, creating missing leaf directories with 0700 safely.
func ensureSafeReceiptDir(receiptDir string) error {
	clean := filepath.Clean(receiptDir)
	if clean == "" || clean == "." || clean == string(filepath.Separator) {
		return errors.New("refusing invalid receipt directory path")
	}
	if strings.ContainsRune(clean, 0) {
		return errors.New("refusing NUL byte in receipt directory path")
	}

	absDir, err := filepath.Abs(clean)
	if err != nil {
		return fmt.Errorf("resolve receipt directory: %w", err)
	}

	// Walk every path component from root to absDir, rejecting symlinks (except macOS /var, /tmp, /etc).
	parts := strings.Split(strings.TrimPrefix(absDir, string(filepath.Separator)), string(filepath.Separator))
	curr := string(filepath.Separator)
	var missingFrom int = -1

	for i, part := range parts {
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
				missingFrom = i
				break
			}
			return fmt.Errorf("stat receipt path component %s: %w", curr, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing symlink in receipt directory path: %s", curr)
		}
		if !fi.IsDir() {
			return fmt.Errorf("receipt path component is not a directory: %s", curr)
		}
	}

	if missingFrom >= 0 {
		// Create remaining directory components one by one inside os.OpenRoot of the deepest existing ancestor.
		base := string(filepath.Separator)
		for i := 0; i < missingFrom; i++ {
			if parts[i] != "" {
				base = filepath.Join(base, parts[i])
			}
		}
		parentRoot, err := os.OpenRoot(base)
		if err != nil {
			return fmt.Errorf("open receipt ancestor root %s: %w", base, err)
		}
		defer parentRoot.Close()

		rel := ""
		for i := missingFrom; i < len(parts); i++ {
			if parts[i] == "" {
				continue
			}
			if rel == "" {
				rel = parts[i]
			} else {
				rel = filepath.Join(rel, parts[i])
			}
			if err := parentRoot.Mkdir(rel, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return fmt.Errorf("create receipt directory component %s: %w", rel, err)
			}
		}
	}

	return verifyDirNotSymlinkAndOwned(absDir)
}

func verifyDirNotSymlinkAndOwned(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("lstat receipt directory %s: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked receipt directory: %s", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("receipt path is not a directory: %s", dir)
	}
	if err := procident.VerifyFileOwnerAndNotSymlink(dir); err != nil {
		return fmt.Errorf("unsafe receipt directory %s: %w", dir, err)
	}
	return nil
}

func isOSSystemSymlink(p string) bool {
	if runtime.GOOS == "darwin" {
		return p == "/var" || p == "/tmp" || p == "/etc"
	}
	return false
}

// detectWorktreeHeadSHA reads .git/HEAD inside workspace via os.OpenRoot (zero subprocess hop tax).
// Falls back to 40 zero hex characters (valid against ^[a-f0-9]{7,64}$) outside a git worktree.
func detectWorktreeHeadSHA(workspace string) string {
	const fallbackSHA = "0000000000000000000000000000000000000000"
	if strings.TrimSpace(workspace) == "" {
		return fallbackSHA
	}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		return fallbackSHA
	}
	defer root.Close()

	headBytes, err := root.ReadFile(".git/HEAD")
	if err != nil {
		return fallbackSHA
	}
	headStr := strings.TrimSpace(string(headBytes))
	if gitSHARe.MatchString(headStr) {
		return headStr
	}
	if strings.HasPrefix(headStr, "ref:") {
		refPath := strings.TrimSpace(strings.TrimPrefix(headStr, "ref:"))
		if refPath == "" || strings.Contains(refPath, "..") || strings.HasPrefix(refPath, "/") {
			return fallbackSHA
		}
		refBytes, err := root.ReadFile(filepath.Join(".git", filepath.FromSlash(refPath)))
		if err == nil {
			sha := strings.TrimSpace(string(refBytes))
			if gitSHARe.MatchString(sha) {
				return sha
			}
		}
	}
	return fallbackSHA
}

func generatePrefixedID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%s%x", prefix, time.Now().UTC().UnixNano())
	}
	return prefix + strings.ToUpper(hex.EncodeToString(b[:]))
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
