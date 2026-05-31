package cpawebhook

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type RequestEventHook struct{}

type requestEventPayload struct {
	EventID    string `json:"event_id"`
	EventType  string `json:"event_type"`
	AuthID     string `json:"auth_id"`
	AuthIndex  string `json:"auth_index,omitempty"`
	AuthName   string `json:"auth_name,omitempty"`
	AuthLabel  string `json:"auth_label,omitempty"`
	Provider   string `json:"provider,omitempty"`
	ProxyURL   string `json:"proxy_url,omitempty"`
	Model      string `json:"model,omitempty"`
	Success    bool   `json:"success"`
	StatusCode int    `json:"status_code,omitempty"`
	ErrorType  string `json:"error_type,omitempty"`
	Error      string `json:"error,omitempty"`
	OccurredAt string `json:"occurred_at"`
}

func NewRequestEventHook() RequestEventHook {
	return RequestEventHook{}
}

func (RequestEventHook) OnAuthRegistered(context.Context, *coreauth.Auth) {}

func (RequestEventHook) OnAuthUpdated(context.Context, *coreauth.Auth) {}

func (RequestEventHook) OnResult(ctx context.Context, result coreauth.Result) {
	_ = ctx
	if result.Success {
		return
	}
	webhookURL := strings.TrimSpace(os.Getenv("CPA_REQUEST_EVENT_WEBHOOK_URL"))
	if webhookURL == "" {
		return
	}
	secret := strings.TrimSpace(os.Getenv("CPA_WEBHOOK_SECRET"))
	if secret == "" {
		log.Warn("CPA_REQUEST_EVENT_WEBHOOK_URL is configured but CPA_WEBHOOK_SECRET is empty; skipping CPA request webhook")
		return
	}

	payload := buildRequestEventPayload(result)
	rawBody, err := json.Marshal(payload)
	if err != nil {
		log.WithError(err).Warn("failed to marshal CPA request webhook payload")
		return
	}
	SendWebhook(webhookURL, rawBody)
}

func buildRequestEventPayload(result coreauth.Result) requestEventPayload {
	payload := requestEventPayload{
		EventID:    uuid.NewString(),
		EventType:  classifyResultEvent(result),
		AuthID:     strings.TrimSpace(result.AuthID),
		Provider:   strings.TrimSpace(result.Provider),
		Model:      strings.TrimSpace(result.Model),
		Success:    result.Success,
		OccurredAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if result.Error != nil {
		payload.StatusCode = result.Error.StatusCode()
		payload.ErrorType = strings.TrimSpace(result.Error.Code)
		payload.Error = strings.TrimSpace(result.Error.Message)
	}
	if auth := result.Auth; auth != nil {
		auth.EnsureIndex()
		if payload.AuthID == "" {
			payload.AuthID = strings.TrimSpace(auth.ID)
		}
		payload.AuthIndex = strings.TrimSpace(auth.Index)
		payload.AuthName = strings.TrimSpace(auth.FileName)
		if payload.AuthName == "" {
			payload.AuthName = filepath.Base(payload.AuthID)
		}
		payload.AuthLabel = strings.TrimSpace(auth.Label)
		if payload.Provider == "" {
			payload.Provider = strings.TrimSpace(auth.Provider)
		}
		payload.ProxyURL = strings.TrimSpace(auth.ProxyURL)
		if payload.ProxyURL == "" && auth.Metadata != nil {
			if rawProxyURL, ok := auth.Metadata["proxy_url"].(string); ok {
				payload.ProxyURL = strings.TrimSpace(rawProxyURL)
			}
		}
	}
	if payload.AuthID == "" {
		payload.AuthID = payload.AuthName
	}
	return payload
}

func classifyResultEvent(result coreauth.Result) string {
	if result.Success {
		return "request_result"
	}
	if result.Error == nil {
		return "request_result"
	}
	switch result.Error.StatusCode() {
	case 401, 402, 403, 404, 429:
		return "request_result"
	}
	text := strings.ToLower(strings.TrimSpace(result.Error.Code + " " + result.Error.Message))
	for _, term := range []string{
		"proxy",
		"connect timeout",
		"connection refused",
		"no route to host",
		"context deadline exceeded",
		"deadline exceeded",
		"tls handshake",
		"handshake timeout",
		"eof",
	} {
		if strings.Contains(text, term) {
			return "request_proxy_failed"
		}
	}
	return "request_result"
}
