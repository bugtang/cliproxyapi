package cpawebhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type capturedRequestWebhook struct {
	timestamp string
	signature string
	body      []byte
}

func TestRequestEventHook_SendsSignedProxyFailure(t *testing.T) {
	events := make(chan capturedRequestWebhook, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read webhook body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		events <- capturedRequestWebhook{
			timestamp: r.Header.Get("X-CPA-Timestamp"),
			signature: r.Header.Get("X-CPA-Webhook-Signature"),
			body:      body,
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	const secret = "request-secret"
	t.Setenv("CPA_REQUEST_EVENT_WEBHOOK_URL", server.URL)
	t.Setenv("CPA_WEBHOOK_SECRET", secret)

	hook := NewRequestEventHook()
	hook.OnResult(
		nil,
		coreauth.Result{
			AuthID:   "codex-user.json",
			Provider: "codex",
			Model:    "codex-auto-review",
			Success:  false,
			Auth: &coreauth.Auth{
				ID:       "codex-user.json",
				FileName: "codex-user.json",
				Provider: "codex",
				ProxyURL: "http://proxy.internal:18080",
			},
			Error: &coreauth.Error{
				Code:       "proxy_connect_failed",
				Message:    "proxy connect failed: context deadline exceeded",
				Retryable:  true,
				HTTPStatus: http.StatusBadGateway,
			},
		},
	)

	payload := readRequestWebhook(t, events, secret)
	if payload.EventType != "request_proxy_failed" {
		t.Fatalf("event_type = %q, want request_proxy_failed", payload.EventType)
	}
	if payload.AuthName != "codex-user.json" {
		t.Fatalf("auth_name = %q, want codex-user.json", payload.AuthName)
	}
	if payload.ProxyURL != "http://proxy.internal:18080" {
		t.Fatalf("proxy_url = %q, want http://proxy.internal:18080", payload.ProxyURL)
	}
	if payload.Model != "codex-auto-review" {
		t.Fatalf("model = %q, want codex-auto-review", payload.Model)
	}
	if payload.StatusCode != http.StatusBadGateway {
		t.Fatalf("status_code = %d, want %d", payload.StatusCode, http.StatusBadGateway)
	}
}

func TestRequestEventHook_DoesNotSendBusinessErrorAsProxyFailure(t *testing.T) {
	payload := buildRequestEventPayload(coreauth.Result{
		AuthID:   "codex-user.json",
		Provider: "codex",
		Model:    "codex-auto-review",
		Success:  false,
		Error: &coreauth.Error{
			Code:       "unauthorized",
			Message:    "401 unauthorized",
			HTTPStatus: http.StatusUnauthorized,
		},
	})

	if payload.EventType != "request_result" {
		t.Fatalf("event_type = %q, want request_result", payload.EventType)
	}
}

func readRequestWebhook(t *testing.T, events <-chan capturedRequestWebhook, secret string) requestEventPayload {
	t.Helper()
	select {
	case got := <-events:
		if got.timestamp == "" {
			t.Fatalf("webhook timestamp header is empty")
		}
		if got.signature != SignPayload(secret, got.timestamp, got.body) {
			t.Fatalf("invalid webhook signature: %q", got.signature)
		}
		var payload requestEventPayload
		if err := json.Unmarshal(got.body, &payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		if payload.EventID == "" {
			t.Fatalf("event_id is empty")
		}
		if payload.OccurredAt == "" {
			t.Fatalf("occurred_at is empty")
		}
		return payload
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for CPA request webhook")
	}
	return requestEventPayload{}
}
