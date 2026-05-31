package cpawebhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	envWebhookSecret       = "CPA_WEBHOOK_SECRET"
	envWebhookOutboxDir    = "CPA_WEBHOOK_OUTBOX_DIR"
	envOutboxRetrySeconds  = "CPA_WEBHOOK_OUTBOX_RETRY_SECONDS"
	defaultRetrySeconds    = 10
	defaultMaxRetrySeconds = 300
)

type outboxItem struct {
	ID            string          `json:"id"`
	URL           string          `json:"url"`
	Body          json.RawMessage `json:"body"`
	CreatedAt     string          `json:"created_at"`
	Attempts      int             `json:"attempts"`
	LastAttemptAt string          `json:"last_attempt_at,omitempty"`
	NextAttemptAt string          `json:"next_attempt_at,omitempty"`
	LastError     string          `json:"last_error,omitempty"`
}

var (
	workerMu      sync.Mutex
	workerStarted bool
)

func SendWebhook(webhookURL string, rawBody []byte) {
	webhookURL = strings.TrimSpace(webhookURL)
	if webhookURL == "" || len(rawBody) == 0 {
		return
	}
	if strings.TrimSpace(os.Getenv(envWebhookSecret)) == "" {
		log.Warn("CPA webhook URL is configured but CPA_WEBHOOK_SECRET is empty; skipping CPA webhook")
		return
	}
	outboxDir := strings.TrimSpace(os.Getenv(envWebhookOutboxDir))
	if outboxDir == "" {
		go func() {
			if err := deliverSignedWebhook(webhookURL, rawBody); err != nil {
				log.WithError(err).Warn("failed to deliver CPA webhook")
			}
		}()
		return
	}
	if err := enqueueOutboxItem(outboxDir, webhookURL, rawBody); err != nil {
		log.WithError(err).Warn("failed to enqueue CPA webhook outbox item; attempting direct delivery")
		go func() {
			if errDeliver := deliverSignedWebhook(webhookURL, rawBody); errDeliver != nil {
				log.WithError(errDeliver).Warn("failed to deliver CPA webhook after enqueue failure")
			}
		}()
		return
	}
	StartOutboxWorker()
	go func() {
		if err := processOutboxOnce(outboxDir); err != nil {
			log.WithError(err).Debug("CPA webhook outbox immediate processing failed")
		}
	}()
}

func StartOutboxWorker() {
	outboxDir := strings.TrimSpace(os.Getenv(envWebhookOutboxDir))
	if outboxDir == "" {
		return
	}
	workerMu.Lock()
	if workerStarted {
		workerMu.Unlock()
		return
	}
	workerStarted = true
	workerMu.Unlock()

	interval := outboxRetryInterval()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := processOutboxOnce(outboxDir); err != nil {
				log.WithError(err).Debug("CPA webhook outbox processing failed")
			}
			<-ticker.C
		}
	}()
}

func enqueueOutboxItem(outboxDir string, webhookURL string, rawBody []byte) error {
	if err := os.MkdirAll(outboxDir, 0o700); err != nil {
		return err
	}
	item := outboxItem{
		ID:        uuid.NewString(),
		URL:       webhookURL,
		Body:      append([]byte(nil), rawBody...),
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	raw, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(outboxDir, item.ID+".json")
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func processOutboxOnce(outboxDir string) error {
	if strings.TrimSpace(outboxDir) == "" {
		return nil
	}
	entries, err := os.ReadDir(outboxDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	now := time.Now().UTC()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(outboxDir, entry.Name())
		if err := processOutboxFile(path, now); err != nil {
			log.WithError(err).Warnf("failed to process CPA webhook outbox item %s", entry.Name())
		}
	}
	return nil
}

func processOutboxFile(path string, now time.Time) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var item outboxItem
	if err := json.Unmarshal(raw, &item); err != nil {
		return quarantineBadOutboxFile(path, err)
	}
	if item.URL == "" || len(item.Body) == 0 {
		return quarantineBadOutboxFile(path, fmt.Errorf("missing url or body"))
	}
	if item.NextAttemptAt != "" {
		if next, errParse := time.Parse(time.RFC3339Nano, item.NextAttemptAt); errParse == nil && next.After(now) {
			return nil
		}
	}
	if err := deliverSignedWebhook(item.URL, item.Body); err != nil {
		item.Attempts++
		item.LastError = err.Error()
		item.LastAttemptAt = now.Format(time.RFC3339Nano)
		item.NextAttemptAt = now.Add(nextRetryDelay(item.Attempts)).Format(time.RFC3339Nano)
		return rewriteOutboxItem(path, item)
	}
	return os.Remove(path)
}

func quarantineBadOutboxFile(path string, cause error) error {
	badPath := strings.TrimSuffix(path, ".json") + ".bad"
	if err := os.Rename(path, badPath); err != nil {
		return fmt.Errorf("%v; failed to move bad outbox item: %w", cause, err)
	}
	return cause
}

func rewriteOutboxItem(path string, item outboxItem) error {
	raw, err := json.MarshalIndent(item, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func nextRetryDelay(attempts int) time.Duration {
	base := outboxRetryInterval()
	if attempts <= 1 {
		return base
	}
	multiplier := 1 << min(attempts-1, 5)
	delay := time.Duration(multiplier) * base
	maxDelay := time.Duration(defaultMaxRetrySeconds) * time.Second
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

func outboxRetryInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv(envOutboxRetrySeconds))
	if raw == "" {
		return time.Duration(defaultRetrySeconds) * time.Second
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds <= 0 {
		return time.Duration(defaultRetrySeconds) * time.Second
	}
	return time.Duration(seconds) * time.Second
}

func deliverSignedWebhook(webhookURL string, rawBody []byte) error {
	secret := strings.TrimSpace(os.Getenv(envWebhookSecret))
	if secret == "" {
		return fmt.Errorf("CPA_WEBHOOK_SECRET is empty")
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	signature := SignPayload(secret, timestamp, rawBody)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(rawBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "CLIProxyAPI-CPA-Webhook")
	req.Header.Set("X-CPA-Timestamp", timestamp)
	req.Header.Set("X-CPA-Webhook-Signature", signature)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}
	return nil
}

func SignPayload(secret string, timestamp string, rawBody []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
