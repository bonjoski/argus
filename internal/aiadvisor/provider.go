package aiadvisor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const maxResponseBytes = 4 << 20 // 4 MiB cap on upstream AI responses

var (
	ErrEmptyPrompt     = errors.New("aiadvisor: prompt content cannot be empty")
	ErrProviderFailed  = errors.New("aiadvisor: remote inference call failed")
	ErrInvalidResponse = errors.New("aiadvisor: malformed response from upstream AI")
)

// Role constants for chat completions.
const (
	RoleSystem    = "system"
	RoleUser      = "user"
	RoleAssistant = "assistant"
)

// Message represents a single turn in a conversational completion.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// TokenUsage holds token consumption metadata.
type TokenUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Request contains the payload for an AI completion.
type Request struct {
	Model        string    `json:"model"`
	SystemPrompt string    `json:"system_prompt,omitempty"`
	Messages     []Message `json:"messages"`
	Temperature  float64   `json:"temperature,omitempty"`
	MaxTokens    int       `json:"max_tokens,omitempty"`
}

// Response represents the completed AI completion.
type Response struct {
	Content      string     `json:"content"`
	Model        string     `json:"model"`
	FinishReason string     `json:"finish_reason,omitempty"`
	Usage        TokenUsage `json:"usage"`
}

// Provider defines the pluggable interface for BYO-AI LLM inference engines.
type Provider interface {
	Name() string
	Complete(ctx context.Context, req Request) (*Response, error)
}

// NewProviderFromEnv inspects environment variables and returns the most suitable BYO-AI Provider.
// Falls back to MockProvider if no cloud API keys or local Ollama host are configured.
func NewProviderFromEnv() Provider {
	if key := os.Getenv("GEMINI_API_KEY"); key != "" {
		return NewGeminiProvider(key, os.Getenv("GEMINI_MODEL"))
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return NewClaudeProvider(key, os.Getenv("ANTHROPIC_MODEL"))
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		return NewOpenAIProvider(key, os.Getenv("OPENAI_MODEL"), os.Getenv("OPENAI_BASE_URL"))
	}
	if host := os.Getenv("OLLAMA_HOST"); host != "" {
		model := os.Getenv("OLLAMA_MODEL")
		if model == "" {
			model = "llama3"
		}
		return NewOllamaProvider(host, model)
	}
	return NewMockProvider(
		"local-shield-advisor",
		"Recommendation: Store raw API tokens in Locksmith or hardware enclave; scrub plaintext files.",
	)
}

func resolveModel(reqModel, defaultModel string) string {
	if reqModel == "" || reqModel == "auto" {
		return defaultModel
	}
	return reqModel
}

// --- OpenAI-compatible Provider ---

type OpenAIProvider struct {
	apiKey     string
	model      string
	baseURL    string
	httpClient *http.Client
}

func NewOpenAIProvider(apiKey, model, baseURL string) *OpenAIProvider {
	if model == "" {
		model = "gpt-4o"
	}
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	return &OpenAIProvider{
		apiKey:     apiKey,
		model:      model,
		baseURL:    baseURL,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (o *OpenAIProvider) Name() string { return "openai-compatible" }

type openAIChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIChatRequest struct {
	Model       string              `json:"model"`
	Messages    []openAIChatMessage `json:"messages"`
	Temperature float64             `json:"temperature,omitempty"`
}

type openAIChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (o *OpenAIProvider) Complete(ctx context.Context, req Request) (*Response, error) {
	if len(req.Messages) == 0 {
		return nil, ErrEmptyPrompt
	}
	model := resolveModel(req.Model, o.model)

	messages := make([]openAIChatMessage, 0, len(req.Messages)+1)
	if req.SystemPrompt != "" {
		messages = append(messages, openAIChatMessage{Role: RoleSystem, Content: req.SystemPrompt})
	}
	for _, m := range req.Messages {
		messages = append(messages, openAIChatMessage{Role: m.Role, Content: m.Content})
	}

	bodyBytes, err := json.Marshal(openAIChatRequest{
		Model:       model,
		Messages:    messages,
		Temperature: req.Temperature,
	})
	if err != nil {
		return nil, fmt.Errorf("openai marshal error: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("openai request creation failed: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
	}

	httpResp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderFailed, err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("openai read response failed: %w", err)
	}

	var oResp openAIChatResponse
	if err := json.Unmarshal(respBytes, &oResp); err != nil {
		if httpResp.StatusCode >= 400 {
			return nil, fmt.Errorf("%w: HTTP %d", ErrProviderFailed, httpResp.StatusCode)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if oResp.Error != nil {
		return nil, fmt.Errorf("%w: API error: %s", ErrProviderFailed, oResp.Error.Message)
	}
	if httpResp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: HTTP %d", ErrProviderFailed, httpResp.StatusCode)
	}
	if len(oResp.Choices) == 0 {
		return nil, fmt.Errorf("%w: no choices returned", ErrInvalidResponse)
	}

	return &Response{
		Content:      oResp.Choices[0].Message.Content,
		Model:        model,
		FinishReason: oResp.Choices[0].FinishReason,
		Usage: TokenUsage{
			InputTokens:  oResp.Usage.PromptTokens,
			OutputTokens: oResp.Usage.CompletionTokens,
		},
	}, nil
}

// --- Anthropic Claude Provider ---

type ClaudeProvider struct {
	apiKey     string
	model      string
	httpClient *http.Client
	baseURL    string
}

func NewClaudeProvider(apiKey, model string) *ClaudeProvider {
	if model == "" {
		model = "claude-3-5-sonnet-20241022"
	}
	return &ClaudeProvider{
		apiKey:     apiKey,
		model:      model,
		httpClient: &http.Client{Timeout: 60 * time.Second},
		baseURL:    "https://api.anthropic.com/v1",
	}
}

func (c *ClaudeProvider) Name() string { return "anthropic-claude" }

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeRequest struct {
	Model       string          `json:"model"`
	MaxTokens   int             `json:"max_tokens"`
	System      string          `json:"system,omitempty"`
	Messages    []claudeMessage `json:"messages"`
	Temperature float64         `json:"temperature,omitempty"`
}

type claudeContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type claudeResponse struct {
	Content    []claudeContentBlock `json:"content"`
	StopReason string               `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *ClaudeProvider) Complete(ctx context.Context, req Request) (*Response, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("%w: ANTHROPIC_API_KEY is not configured", ErrProviderFailed)
	}
	if len(req.Messages) == 0 {
		return nil, ErrEmptyPrompt
	}

	model := resolveModel(req.Model, c.model)
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	cReq := claudeRequest{
		Model:       model,
		MaxTokens:   maxTokens,
		System:      req.SystemPrompt,
		Temperature: req.Temperature,
		Messages:    make([]claudeMessage, 0, len(req.Messages)),
	}
	for _, msg := range req.Messages {
		if msg.Role == RoleSystem {
			cReq.System = msg.Content
			continue
		}
		cReq.Messages = append(cReq.Messages, claudeMessage{Role: msg.Role, Content: msg.Content})
	}

	bodyBytes, err := json.Marshal(cReq)
	if err != nil {
		return nil, fmt.Errorf("claude marshal error: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.baseURL, "/")+"/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("claude request creation failed: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderFailed, err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("claude read response failed: %w", err)
	}

	var cResp claudeResponse
	if err := json.Unmarshal(respBytes, &cResp); err != nil {
		if httpResp.StatusCode >= 400 {
			return nil, fmt.Errorf("%w: HTTP %d", ErrProviderFailed, httpResp.StatusCode)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if cResp.Error != nil {
		return nil, fmt.Errorf("%w: API error (%s): %s", ErrProviderFailed, cResp.Error.Type, cResp.Error.Message)
	}
	if httpResp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: HTTP %d", ErrProviderFailed, httpResp.StatusCode)
	}

	var texts []string
	for _, block := range cResp.Content {
		if block.Type == "text" {
			texts = append(texts, block.Text)
		}
	}

	return &Response{
		Content:      strings.Join(texts, "\n"),
		Model:        model,
		FinishReason: cResp.StopReason,
		Usage: TokenUsage{
			InputTokens:  cResp.Usage.InputTokens,
			OutputTokens: cResp.Usage.OutputTokens,
		},
	}, nil
}

// --- Google Gemini Provider ---

type GeminiProvider struct {
	apiKey     string
	model      string
	httpClient *http.Client
	baseURL    string
}

func NewGeminiProvider(apiKey, model string) *GeminiProvider {
	if model == "" {
		model = "gemini-2.0-flash"
	}
	return &GeminiProvider{
		apiKey:     apiKey,
		model:      model,
		httpClient: &http.Client{Timeout: 60 * time.Second},
		baseURL:    "https://generativelanguage.googleapis.com/v1beta",
	}
}

func (g *GeminiProvider) Name() string { return "google-gemini" }

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiSystemInstruction struct {
	Parts []geminiPart `json:"parts"`
}

type geminiRequest struct {
	Contents          []geminiContent          `json:"contents"`
	SystemInstruction *geminiSystemInstruction `json:"systemInstruction,omitempty"`
}

type geminiCandidate struct {
	Content struct {
		Parts []geminiPart `json:"parts"`
	} `json:"content"`
	FinishReason string `json:"finishReason"`
}

type geminiResponse struct {
	Candidates    []geminiCandidate `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
	Error *struct {
		Message string `json:"message"`
		Code    int    `json:"code"`
	} `json:"error,omitempty"`
}

func (g *GeminiProvider) Complete(ctx context.Context, req Request) (*Response, error) {
	if g.apiKey == "" {
		return nil, fmt.Errorf("%w: GEMINI_API_KEY is not configured", ErrProviderFailed)
	}
	if len(req.Messages) == 0 {
		return nil, ErrEmptyPrompt
	}

	model := resolveModel(req.Model, g.model)

	gReq := geminiRequest{
		Contents: make([]geminiContent, 0, len(req.Messages)),
	}
	if req.SystemPrompt != "" {
		gReq.SystemInstruction = &geminiSystemInstruction{
			Parts: []geminiPart{{Text: req.SystemPrompt}},
		}
	}
	for _, msg := range req.Messages {
		role := "user"
		if msg.Role == RoleAssistant {
			role = "model"
		}
		gReq.Contents = append(gReq.Contents, geminiContent{
			Role:  role,
			Parts: []geminiPart{{Text: msg.Content}},
		})
	}

	bodyBytes, err := json.Marshal(gReq)
	if err != nil {
		return nil, fmt.Errorf("gemini marshal error: %w", err)
	}

	url := fmt.Sprintf("%s/models/%s:generateContent", strings.TrimRight(g.baseURL, "/"), model)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("gemini request creation failed: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-goog-api-key", g.apiKey)

	httpResp, err := g.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProviderFailed, err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("gemini read response failed: %w", err)
	}

	var gResp geminiResponse
	if err := json.Unmarshal(respBytes, &gResp); err != nil {
		if httpResp.StatusCode >= 400 {
			return nil, fmt.Errorf("%w: HTTP %d", ErrProviderFailed, httpResp.StatusCode)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	if gResp.Error != nil {
		return nil, fmt.Errorf("%w: API error (%d): %s", ErrProviderFailed, gResp.Error.Code, gResp.Error.Message)
	}
	if httpResp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: HTTP %d", ErrProviderFailed, httpResp.StatusCode)
	}
	if len(gResp.Candidates) == 0 || len(gResp.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("%w: no content generated by Gemini", ErrInvalidResponse)
	}

	textParts := make([]string, 0, len(gResp.Candidates[0].Content.Parts))
	for _, part := range gResp.Candidates[0].Content.Parts {
		textParts = append(textParts, part.Text)
	}

	return &Response{
		Content:      strings.Join(textParts, "\n"),
		Model:        model,
		FinishReason: gResp.Candidates[0].FinishReason,
		Usage: TokenUsage{
			InputTokens:  gResp.UsageMetadata.PromptTokenCount,
			OutputTokens: gResp.UsageMetadata.CandidatesTokenCount,
		},
	}, nil
}

// --- Local Ollama Provider ---

type OllamaProvider struct {
	baseURL    string
	model      string
	httpClient *http.Client
}

func NewOllamaProvider(baseURL, model string) *OllamaProvider {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	if model == "" {
		model = "qwen2.5-coder:latest"
	}
	return &OllamaProvider{
		baseURL:    strings.TrimRight(baseURL, "/"),
		model:      model,
		httpClient: &http.Client{Timeout: 120 * time.Second},
	}
}

func (o *OllamaProvider) Name() string { return "ollama-local" }

type ollamaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []ollamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type ollamaChatResponse struct {
	Model           string        `json:"model"`
	Message         ollamaMessage `json:"message"`
	Done            bool          `json:"done"`
	PromptEvalCount int           `json:"prompt_eval_count"`
	EvalCount       int           `json:"eval_count"`
}

func (o *OllamaProvider) Complete(ctx context.Context, req Request) (*Response, error) {
	if len(req.Messages) == 0 {
		return nil, ErrEmptyPrompt
	}
	model := resolveModel(req.Model, o.model)

	messages := make([]ollamaMessage, 0, len(req.Messages)+1)
	if req.SystemPrompt != "" {
		messages = append(messages, ollamaMessage{Role: RoleSystem, Content: req.SystemPrompt})
	}
	for _, m := range req.Messages {
		messages = append(messages, ollamaMessage{Role: m.Role, Content: m.Content})
	}

	bodyBytes, err := json.Marshal(ollamaChatRequest{
		Model:    model,
		Messages: messages,
		Stream:   false,
	})
	if err != nil {
		return nil, fmt.Errorf("ollama marshal error: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/api/chat", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("ollama request creation failed: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := o.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to connect to local Ollama daemon at %s: %v", ErrProviderFailed, o.baseURL, err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("ollama read response failed: %w", err)
	}
	if httpResp.StatusCode >= 400 {
		return nil, fmt.Errorf("%w: Ollama HTTP %d", ErrProviderFailed, httpResp.StatusCode)
	}

	var olResp ollamaChatResponse
	if err := json.Unmarshal(respBytes, &olResp); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidResponse, err)
	}

	return &Response{
		Content:      olResp.Message.Content,
		Model:        model,
		FinishReason: "stop",
		Usage: TokenUsage{
			InputTokens:  olResp.PromptEvalCount,
			OutputTokens: olResp.EvalCount,
		},
	}, nil
}

// --- Deterministic Offline Mock Provider ---

// MockProvider provides deterministic responses when no remote/local AI provider is configured.
type MockProvider struct {
	mu            sync.RWMutex
	name          string
	customReplies map[string]string
	defaultReply  string
	callCount     int
}

func NewMockProvider(name, defaultReply string) *MockProvider {
	if name == "" {
		name = "mock"
	}
	if defaultReply == "" {
		defaultReply = "Mock completion successfully processed."
	}
	return &MockProvider{
		name:          name,
		customReplies: make(map[string]string),
		defaultReply:  defaultReply,
	}
}

func (m *MockProvider) Name() string { return m.name }

func (m *MockProvider) SetReply(matchSubstring, reply string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.customReplies[matchSubstring] = reply
}

func (m *MockProvider) CallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.callCount
}

func (m *MockProvider) Complete(ctx context.Context, req Request) (*Response, error) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()

	if len(req.Messages) == 0 {
		return nil, ErrEmptyPrompt
	}

	lastMsg := req.Messages[len(req.Messages)-1].Content

	m.mu.RLock()
	defer m.mu.RUnlock()

	reply := m.defaultReply
	for match, custom := range m.customReplies {
		if strings.Contains(lastMsg, match) {
			reply = custom
			break
		}
	}

	return &Response{
		Content:      reply,
		Model:        fmt.Sprintf("%s-v1", m.name),
		FinishReason: "stop",
		Usage: TokenUsage{
			InputTokens:  len(lastMsg) / 4,
			OutputTokens: len(reply) / 4,
		},
	}, nil
}
