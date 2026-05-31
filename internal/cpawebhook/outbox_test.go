package cpawebhook

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOutboxRetriesAndRemovesDeliveredWebhook(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(body) == 0 {
			t.Errorf("webhook body is empty")
		}
		if r.Header.Get("X-CPA-Timestamp") == "" || r.Header.Get("X-CPA-Webhook-Signature") == "" {
			t.Errorf("missing webhook signature headers")
		}
		if attempts == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	t.Setenv(envWebhookSecret, "outbox-secret")
	t.Setenv(envOutboxRetrySeconds, "1")
	outboxDir := t.TempDir()

	if err := enqueueOutboxItem(outboxDir, server.URL, []byte(`{"event_id":"evt-1"}`)); err != nil {
		t.Fatalf("failed to enqueue outbox item: %v", err)
	}
	if err := processOutboxOnce(outboxDir); err != nil {
		t.Fatalf("first process failed: %v", err)
	}
	files, err := filepath.Glob(filepath.Join(outboxDir, "*.json"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("files after failed attempt = %d, want 1", len(files))
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatalf("failed to read retained outbox item: %v", err)
	}
	var retained outboxItem
	if err := json.Unmarshal(raw, &retained); err != nil {
		t.Fatalf("failed to decode retained outbox item: %v", err)
	}
	if retained.Attempts != 1 || retained.LastError == "" || retained.NextAttemptAt == "" {
		t.Fatalf("retained item missing retry state: %+v", retained)
	}
	retained.NextAttemptAt = ""
	if err := rewriteOutboxItem(files[0], retained); err != nil {
		t.Fatalf("failed to rewrite retained outbox item: %v", err)
	}

	if err := processOutboxOnce(outboxDir); err != nil {
		t.Fatalf("second process failed: %v", err)
	}
	files, err = filepath.Glob(filepath.Join(outboxDir, "*.json"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("files after successful retry = %d, want 0", len(files))
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestSendWebhookUsesOutboxWhenConfigured(t *testing.T) {
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	t.Setenv(envWebhookSecret, "outbox-secret")
	outboxDir := t.TempDir()
	t.Setenv(envWebhookOutboxDir, outboxDir)

	SendWebhook(server.URL, []byte(`{"event_id":"evt-2"}`))
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for outbox delivery")
	}
}
