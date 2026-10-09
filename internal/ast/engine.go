package ast

// Engine defines the pluggable contract for source AST parsing and dependency extraction.
type Engine interface {
	Name() string
	Tier() int // Tier 1: Fast Native, Tier 2: Deep Tree-Sitter CST
	ExtractImports(filePath, content string) ([]ImportCandidate, error)
	Supports(filePath string) bool
}

// Tier1NativeEngine implements the fast, zero-dependency native lexer engine.
type Tier1NativeEngine struct{}

func NewTier1NativeEngine() *Tier1NativeEngine {
	return &Tier1NativeEngine{}
}

func (e *Tier1NativeEngine) Name() string { return "Native Fast Lexer (Tier 1)" }
func (e *Tier1NativeEngine) Tier() int    { return 1 }

func (e *Tier1NativeEngine) Supports(filePath string) bool {
	_, ok := DetectEcosystem(filePath)
	return ok
}

func (e *Tier1NativeEngine) ExtractImports(filePath, content string) ([]ImportCandidate, error) {
	return ExtractImports(filePath, content)
}

// DefaultEngine returns the active system AST engine.
var DefaultEngine Engine = NewTier2TreeSitterEngine()

// SetDefaultEngine swaps the active AST engine (Dependency Inversion).
func SetDefaultEngine(e Engine) {
	DefaultEngine = e
}
