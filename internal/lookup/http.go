package lookup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Shared client behaviour: 10 s per request, one retry after 1 s on 429/5xx
// (cli-spec §11). Small helpers, not an abstraction layer — each adapter owns
// its own structs and endpoint.

var httpClient = &http.Client{Timeout: 10 * time.Second}

// ErrDegraded marks a source that did not answer: the row renders an explicit
// "not available" cell, never a failure (spec §5.3).
type ErrDegraded struct {
	Source string
	Err    error
}

func (e *ErrDegraded) Error() string {
	return fmt.Sprintf("%s: %v", e.Source, e.Err)
}

func (e *ErrDegraded) Unwrap() error { return e.Err }

// ErrNotFound marks a definitive 404: the identifier is absent from the
// source, which is an answer ("no record"), not a degradation.
var ErrNotFound = errors.New("not found")

func getJSON(ctx context.Context, url string, header map[string]string, out any) error {
	return do(ctx, http.MethodGet, url, header, nil, out)
}

func postJSON(ctx context.Context, url string, body any, out any) error {
	return do(ctx, http.MethodPost, url, nil, body, out)
}

func do(ctx context.Context, method, url string, header map[string]string, body any, out any) error {
	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyBytes = b
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
		}
		var rd io.Reader
		if bodyBytes != nil {
			rd = bytes.NewReader(bodyBytes)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, rd)
		if err != nil {
			return err
		}
		if bodyBytes != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range header {
			req.Header.Set(k, v)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue // network error: one retry, then degrade
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("%s: status %d", url, resp.StatusCode)
			continue // one retry, then degrade
		}
		if resp.StatusCode == http.StatusNotFound {
			return &ErrDegraded{Source: url, Err: ErrNotFound}
		}
		if resp.StatusCode != http.StatusOK {
			return &ErrDegraded{Source: url, Err: fmt.Errorf("status %d", resp.StatusCode)}
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(b, out); err != nil {
			return &ErrDegraded{Source: url, Err: err}
		}
		return nil
	}
	return &ErrDegraded{Source: url, Err: lastErr}
}
