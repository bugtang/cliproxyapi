package management

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/cpawebhook"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type capturedCPAAuthWebhook struct {
	timestamp string
	signature string
	body      []byte
}

func TestCPAAuthFileWebhook_LifecycleEvents(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	events := make(chan capturedCPAAuthWebhook, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read webhook body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		events <- capturedCPAAuthWebhook{
			timestamp: r.Header.Get("X-CPA-Timestamp"),
			signature: r.Header.Get("X-CPA-Webhook-Signature"),
			body:      body,
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	const secret = "test-shared-secret"
	t.Setenv("CPA_EVENT_WEBHOOK_URL", server.URL)
	t.Setenv("CPA_WEBHOOK_SECRET", secret)

	authDir := t.TempDir()
	store := &memoryAuthStore{}
	manager := coreauth.NewManager(store, nil, nil)
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.tokenStore = store

	uploadRec := httptest.NewRecorder()
	uploadCtx, _ := gin.CreateTestContext(uploadRec)
	uploadReq := httptest.NewRequest(
		http.MethodPost,
		"/v0/management/auth-files?name="+url.QueryEscape("codex-user.json"),
		strings.NewReader(`{"type":"codex","email":"user@example.com"}`),
	)
	uploadReq.Header.Set("Content-Type", "application/json")
	uploadCtx.Request = uploadReq
	h.UploadAuthFile(uploadCtx)
	if uploadRec.Code != http.StatusOK {
		t.Fatalf("expected upload status %d, got %d with body %s", http.StatusOK, uploadRec.Code, uploadRec.Body.String())
	}
	created := readCPAAuthWebhook(t, events, secret)
	if created.EventType != "auth_file_created" {
		t.Fatalf("created event_type = %q, want auth_file_created", created.EventType)
	}
	if created.AuthName != "codex-user.json" {
		t.Fatalf("created auth_name = %q, want codex-user.json", created.AuthName)
	}
	if created.Provider != "codex" {
		t.Fatalf("created provider = %q, want codex", created.Provider)
	}

	fieldsRec := httptest.NewRecorder()
	fieldsCtx, _ := gin.CreateTestContext(fieldsRec)
	fieldsReq := httptest.NewRequest(
		http.MethodPatch,
		"/v0/management/auth-files/fields",
		strings.NewReader(`{"name":"codex-user.json","proxy_url":"http://proxy.internal:18080"}`),
	)
	fieldsReq.Header.Set("Content-Type", "application/json")
	fieldsCtx.Request = fieldsReq
	h.PatchAuthFileFields(fieldsCtx)
	if fieldsRec.Code != http.StatusOK {
		t.Fatalf("expected fields status %d, got %d with body %s", http.StatusOK, fieldsRec.Code, fieldsRec.Body.String())
	}
	updated := readCPAAuthWebhook(t, events, secret)
	if updated.EventType != "auth_file_updated" {
		t.Fatalf("updated event_type = %q, want auth_file_updated", updated.EventType)
	}
	if updated.ProxyURL != "http://proxy.internal:18080" {
		t.Fatalf("updated proxy_url = %q, want http://proxy.internal:18080", updated.ProxyURL)
	}

	statusRec := httptest.NewRecorder()
	statusCtx, _ := gin.CreateTestContext(statusRec)
	statusReq := httptest.NewRequest(
		http.MethodPatch,
		"/v0/management/auth-files/status",
		strings.NewReader(`{"name":"codex-user.json","disabled":true}`),
	)
	statusReq.Header.Set("Content-Type", "application/json")
	statusCtx.Request = statusReq
	h.PatchAuthFileStatus(statusCtx)
	if statusRec.Code != http.StatusOK {
		t.Fatalf("expected status patch status %d, got %d with body %s", http.StatusOK, statusRec.Code, statusRec.Body.String())
	}
	disabled := readCPAAuthWebhook(t, events, secret)
	if disabled.EventType != "auth_file_disabled" {
		t.Fatalf("disabled event_type = %q, want auth_file_disabled", disabled.EventType)
	}
	if !disabled.Disabled || disabled.Status != "disabled" {
		t.Fatalf("disabled event state = disabled:%v status:%q, want disabled true/status disabled", disabled.Disabled, disabled.Status)
	}

	deleteRec := httptest.NewRecorder()
	deleteCtx, _ := gin.CreateTestContext(deleteRec)
	deleteReq := httptest.NewRequest(
		http.MethodDelete,
		"/v0/management/auth-files?name="+url.QueryEscape("codex-user.json"),
		nil,
	)
	deleteCtx.Request = deleteReq
	h.DeleteAuthFile(deleteCtx)
	if deleteRec.Code != http.StatusOK {
		t.Fatalf("expected delete status %d, got %d with body %s", http.StatusOK, deleteRec.Code, deleteRec.Body.String())
	}
	deleted := readCPAAuthWebhook(t, events, secret)
	if deleted.EventType != "auth_file_deleted" {
		t.Fatalf("deleted event_type = %q, want auth_file_deleted", deleted.EventType)
	}
	if !deleted.Disabled {
		t.Fatalf("deleted disabled = false, want true")
	}
	if _, err := os.Stat(filepath.Join(authDir, "codex-user.json")); !os.IsNotExist(err) {
		t.Fatalf("expected auth file to be removed, stat err: %v", err)
	}
}

func TestListAuthFiles_ExposesProxyURL(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	authPath := filepath.Join(authDir, "proxy.json")
	if err := os.WriteFile(authPath, []byte(`{"type":"codex","proxy_url":"http://proxy.internal:18080"}`), 0o600); err != nil {
		t.Fatalf("failed to write auth file: %v", err)
	}
	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	record := &coreauth.Auth{
		ID:       "proxy.json",
		FileName: "proxy.json",
		Provider: "codex",
		ProxyURL: "http://proxy.internal:18080",
		Attributes: map[string]string{
			"path": authPath,
		},
		Metadata: map[string]any{
			"type": "codex",
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/auth-files", nil)
	h.ListAuthFiles(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected list status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var payload struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode list payload: %v", err)
	}
	if len(payload.Files) != 1 {
		t.Fatalf("files count = %d, want 1", len(payload.Files))
	}
	if got, _ := payload.Files[0]["proxy_url"].(string); got != "http://proxy.internal:18080" {
		t.Fatalf("proxy_url = %q, want http://proxy.internal:18080", got)
	}
}

func readCPAAuthWebhook(t *testing.T, events <-chan capturedCPAAuthWebhook, secret string) cpaAuthFileEventPayload {
	t.Helper()
	select {
	case got := <-events:
		if got.timestamp == "" {
			t.Fatalf("webhook timestamp header is empty")
		}
		if got.signature != cpawebhook.SignPayload(secret, got.timestamp, got.body) {
			t.Fatalf("invalid webhook signature: %q", got.signature)
		}
		var payload cpaAuthFileEventPayload
		if err := json.Unmarshal(got.body, &payload); err != nil {
			t.Fatalf("failed to decode webhook payload: %v", err)
		}
		if payload.EventID == "" {
			t.Fatalf("event_id is empty")
		}
		if payload.AuthID == "" {
			t.Fatalf("auth_id is empty")
		}
		if payload.OccurredAt == "" {
			t.Fatalf("occurred_at is empty")
		}
		return payload
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for CPA auth webhook")
	}
	return cpaAuthFileEventPayload{}
}
