package management

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/cpawebhook"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

type cpaAuthFileEventPayload struct {
	EventID    string `json:"event_id"`
	EventType  string `json:"event_type"`
	AuthID     string `json:"auth_id"`
	AuthIndex  string `json:"auth_index"`
	AuthName   string `json:"auth_name"`
	AuthLabel  string `json:"auth_label,omitempty"`
	Provider   string `json:"provider"`
	Disabled   bool   `json:"disabled"`
	Status     string `json:"status"`
	ProxyURL   string `json:"proxy_url,omitempty"`
	OccurredAt string `json:"occurred_at"`
}

func (h *Handler) emitCPAAuthFileEvent(ctx context.Context, eventType string, auth *coreauth.Auth, fallbackName string) {
	_ = ctx
	eventType = strings.TrimSpace(eventType)
	if eventType == "" {
		return
	}
	webhookURL := strings.TrimSpace(os.Getenv("CPA_EVENT_WEBHOOK_URL"))
	if webhookURL == "" {
		return
	}
	secret := strings.TrimSpace(os.Getenv("CPA_WEBHOOK_SECRET"))
	if secret == "" {
		log.Warn("CPA_EVENT_WEBHOOK_URL is configured but CPA_WEBHOOK_SECRET is empty; skipping CPA auth file webhook")
		return
	}

	payload := buildCPAAuthFileEventPayload(eventType, auth, fallbackName)
	rawBody, err := json.Marshal(payload)
	if err != nil {
		log.WithError(err).Warn("failed to marshal CPA auth file webhook payload")
		return
	}
	cpawebhook.SendWebhook(webhookURL, rawBody)
}

func buildCPAAuthFileEventPayload(eventType string, auth *coreauth.Auth, fallbackName string) cpaAuthFileEventPayload {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	name := filepath.Base(strings.TrimSpace(fallbackName))
	payload := cpaAuthFileEventPayload{
		EventID:    uuid.NewString(),
		EventType:  eventType,
		AuthName:   name,
		OccurredAt: now,
	}
	if auth == nil {
		payload.AuthID = name
		if eventType == "auth_file_deleted" {
			payload.Disabled = true
			payload.Status = "deleted"
		}
		return payload
	}

	auth.EnsureIndex()
	payload.AuthID = strings.TrimSpace(auth.ID)
	payload.AuthIndex = strings.TrimSpace(auth.Index)
	if payload.AuthName == "" {
		payload.AuthName = strings.TrimSpace(auth.FileName)
	}
	if payload.AuthName == "" {
		payload.AuthName = payload.AuthID
	}
	payload.AuthLabel = strings.TrimSpace(auth.Label)
	payload.Provider = strings.TrimSpace(auth.Provider)
	payload.Disabled = auth.Disabled
	payload.Status = strings.TrimSpace(string(auth.Status))
	if payload.Status == "" {
		payload.Status = "active"
	}
	payload.ProxyURL = strings.TrimSpace(auth.ProxyURL)
	if payload.ProxyURL == "" && auth.Metadata != nil {
		if rawProxyURL, ok := auth.Metadata["proxy_url"].(string); ok {
			payload.ProxyURL = strings.TrimSpace(rawProxyURL)
		}
	}
	if eventType == "auth_file_deleted" {
		payload.Disabled = true
		if payload.Status == "" || payload.Status == "active" {
			payload.Status = "deleted"
		}
	}
	if payload.AuthID == "" {
		payload.AuthID = payload.AuthName
	}
	return payload
}
