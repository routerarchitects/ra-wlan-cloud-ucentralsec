package integration

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

type apiClient struct {
	baseURL string
	http    *http.Client
	tokens  map[string]string
}

type apiResponse struct {
	StatusCode int
	Body       []byte
	JSON       map[string]any
}

func NewHTTPClient(tlsRootCA string) (*http.Client, error) {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if strings.TrimSpace(tlsRootCA) == "" {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		httpClient.Transport = transport
		return httpClient, nil
	}
	pemBytes, err := os.ReadFile(tlsRootCA)
	if err != nil {
		return nil, fmt.Errorf("read TLS root CA %q: %w", tlsRootCA, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("parse TLS root CA %q: invalid PEM", tlsRootCA)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	httpClient.Transport = transport
	return httpClient, nil
}

func newAPIClient(baseURL string, httpClient *http.Client) *apiClient {
	return &apiClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    httpClient,
		tokens:  map[string]string{},
	}
}

func (c *apiClient) do(actor, method, path, body string) (*apiResponse, error) {
	if method == "POST" && (strings.HasPrefix(path, "/api/v1/user/0") || strings.HasPrefix(path, "/api/v1/subuser/0")) {
		if !strings.Contains(path, "email_verification=") {
			if strings.Contains(path, "?") {
				path += "&email_verification=false"
			} else {
				path += "?email_verification=false"
			}
		}
	}
	return c.doWithHeaders(actor, method, path, body, nil)
}

func (c *apiClient) doWithHeaders(actor, method, path, body string, extraHeaders map[string]string) (*apiResponse, error) {
	fullURL := c.baseURL + path
	var resp *http.Response
	var err error
	var payload []byte
	var out *apiResponse

	maxAttempts := 8
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var reader io.Reader
		if strings.TrimSpace(body) != "" {
			reader = bytes.NewBufferString(body)
		}
		var req *http.Request
		req, err = http.NewRequest(method, fullURL, reader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		if reader != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for key, value := range extraHeaders {
			req.Header.Set(key, value)
		}
		if token := c.tokens[actor]; token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err = c.http.Do(req)
		if err != nil {
			if attempt < maxAttempts {
				time.Sleep(150 * time.Millisecond)
				continue
			}
			return nil, err
		}

		payload, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			if attempt < maxAttempts {
				time.Sleep(150 * time.Millisecond)
				continue
			}
			return nil, err
		}

		out = &apiResponse{StatusCode: resp.StatusCode, Body: payload}
		if len(bytes.TrimSpace(payload)) > 0 {
			_ = json.Unmarshal(payload, &out.JSON)
		}

		if out.JSON != nil {
			errCode, _ := out.JSON["ErrorCode"].(float64)
			if errCode == 13 || errCode == 10 || resp.StatusCode == http.StatusTooManyRequests {
				if attempt < maxAttempts {
					time.Sleep(300 * time.Millisecond)
					continue
				}
			}
		}
		break
	}
	return out, nil
}

func (c *apiClient) login(actor, email, password string) (*apiResponse, error) {
	bodyBytes, _ := json.Marshal(map[string]string{"userId": email, "password": password})
	resp, err := c.do("", http.MethodPost, "/api/v1/oauth2", string(bodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		if token, ok := stringAt(resp.JSON, "access_token"); ok && token != "" {
			c.tokens[actor] = token
		} else {
			return resp, fmt.Errorf("login response did not contain access_token; body=%s", string(resp.Body))
		}
	}
	return resp, nil
}

func statusMatches(expected string, actual int) bool {
	expected = strings.TrimSpace(expected)
	if expected == "" {
		return actual >= 200 && actual <= 299
	}
	for _, part := range regexp.MustCompile(`[|,]`).Split(expected, -1) {
		part = strings.TrimSpace(part)
		switch strings.ToLower(part) {
		case "2xx":
			if actual >= 200 && actual <= 299 {
				return true
			}
		case "3xx":
			if actual >= 300 && actual <= 399 {
				return true
			}
		case "4xx":
			if actual >= 400 && actual <= 499 {
				return true
			}
		case "5xx":
			if actual >= 500 && actual <= 599 {
				return true
			}
		default:
			if code, err := strconv.Atoi(part); err == nil && actual == code {
				return true
			}
		}
	}
	return false
}

func valueAt(obj map[string]any, path string) (any, bool) {
	if obj == nil {
		return nil, false
	}
	path = strings.TrimPrefix(path, "json.")
	var cur any = obj
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func stringAt(obj map[string]any, path string) (string, bool) {
	value, ok := valueAt(obj, path)
	if !ok {
		return "", false
	}
	switch v := value.(type) {
	case string:
		return v, true
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(v), true
	default:
		return fmt.Sprint(v), true
	}
}

func usersContainsID(obj map[string]any, id string) bool {
	if obj == nil {
		return false
	}
	usersRaw, ok := obj["users"]
	if !ok {
		return false
	}
	users, ok := usersRaw.([]any)
	if !ok {
		return false
	}
	for _, raw := range users {
		switch u := raw.(type) {
		case string:
			if u == id {
				return true
			}
		case map[string]any:
			if got, ok := stringAt(u, "id"); ok && got == id {
				return true
			}
		}
	}
	return false
}

func usersAreStrings(obj map[string]any) bool {
	if obj == nil {
		return false
	}
	usersRaw, ok := obj["users"]
	if !ok {
		return false
	}
	users, ok := usersRaw.([]any)
	if !ok {
		return false
	}
	for _, raw := range users {
		if _, ok := raw.(string); !ok {
			return false
		}
	}
	return true
}

func requireEnvOrSkip(t *testing.T, key string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		t.Skipf("%s is required for API integration tests", key)
	}
	return value
}

func loadDotEnvNoT() {
	pathCandidates := []string{"local_test.env"}
	if _, file, _, ok := runtime.Caller(0); ok {
		pathCandidates = append(pathCandidates, filepath.Join(filepath.Dir(file), "local_test.env"))
	}
	for _, path := range pathCandidates {
		if err := loadDotEnvFile(path); err == nil {
			return
		}
	}
}

func loadDotEnv(t *testing.T) {
	t.Helper()
	pathCandidates := []string{"local_test.env"}
	if _, file, _, ok := runtime.Caller(0); ok {
		pathCandidates = append(pathCandidates, filepath.Join(filepath.Dir(file), "local_test.env"))
	}
	for _, path := range pathCandidates {
		if err := loadDotEnvFile(path); err == nil {
			return
		}
	}
}

func loadDotEnvFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), `"'`)
		if key != "" && os.Getenv(key) == "" {
			if err := os.Setenv(key, value); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}
