package integration

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

type testCase struct {
	ID             string
	Name           string
	Actor          string
	Target         string
	Method         string
	Path           string
	Body           string
	ExpectedStatus string
	Extract        string
	Assertions     string
	Description    string
}

type testReportRow struct {
	CallerEmail     string
	Target          string
	TestDescription string
	ExpectedResult  string
	ActualResult    string
}

func NewHTTPClient(tlsRootCA string) (*http.Client, error) {
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}
	if strings.TrimSpace(tlsRootCA) == "" {
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
	return c.doWithHeaders(actor, method, path, body, nil)
}

func (c *apiClient) doWithHeaders(actor, method, path, body string, extraHeaders map[string]string) (*apiResponse, error) {
	fullURL := c.baseURL + path
	var reader io.Reader
	if strings.TrimSpace(body) != "" {
		reader = bytes.NewBufferString(body)
	}

	req, err := http.NewRequest(method, fullURL, reader)
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

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	out := &apiResponse{StatusCode: resp.StatusCode, Body: payload}
	if len(bytes.TrimSpace(payload)) > 0 {
		_ = json.Unmarshal(payload, &out.JSON)
	}
	return out, nil
}

func (c *apiClient) login(actor, email, password string) (*apiResponse, error) {
	bodyMap := map[string]string{
		"userId":   email,
		"password": password,
	}
	bodyBytes, _ := json.Marshal(bodyMap)
	resp, err := c.do("", http.MethodPost, "/api/v1/oauth2", string(bodyBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		accessToken, _ := stringAt(resp.JSON, "access_token")
		if accessToken == "" {
			return resp, fmt.Errorf("login for actor %q succeeded but response did not contain access_token; body=%s", actor, string(resp.Body))
		}
		c.tokens[actor] = accessToken
	}
	return resp, nil
}

func loadTestCases(t *testing.T) []testCase {
	t.Helper()

	path := os.Getenv("OWSEC_TEST_CASES_CSV")
	if path == "" {
		_, file, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("unable to find test directory for default test_cases.csv")
		}
		path = filepath.Join(filepath.Dir(file), "test_cases.csv")
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open test cases CSV %q: %v", path, err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	r.FieldsPerRecord = -1

	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("read test cases CSV %q: %v", path, err)
	}
	if len(records) < 2 {
		t.Fatalf("test cases CSV %q must contain a header and at least one row", path)
	}

	headers := map[string]int{}
	for i, h := range records[0] {
		headers[strings.TrimSpace(h)] = i
	}

	get := func(row []string, key string) string {
		idx, ok := headers[key]
		if !ok || idx >= len(row) {
			return ""
		}
		return strings.TrimSpace(row[idx])
	}

	cases := make([]testCase, 0, len(records)-1)
	for _, row := range records[1:] {
		if len(row) == 0 || strings.HasPrefix(strings.TrimSpace(row[0]), "#") {
			continue
		}
		cases = append(cases, testCase{
			ID:             get(row, "id"),
			Name:           get(row, "name"),
			Actor:          get(row, "actor"),
			Target:         get(row, "target"),
			Method:         strings.ToUpper(get(row, "method")),
			Path:           get(row, "path"),
			Body:           get(row, "body"),
			ExpectedStatus: get(row, "expected_status"),
			Extract:        get(row, "extract"),
			Assertions:     get(row, "assertions"),
			Description:    get(row, "description"),
		})
	}
	return cases
}

var placeholderRe = regexp.MustCompile(`\{\{([A-Za-z0-9_]+)\}\}`)

func expandRequiredVars(input string, vars map[string]string) (string, error) {
	missingKey := ""
	output := placeholderRe.ReplaceAllStringFunc(input, func(match string) string {
		key := strings.TrimSuffix(strings.TrimPrefix(match, "{{"), "}}")
		value, ok := vars[key]
		if !ok {
			missingKey = key
			return ""
		}
		return value
	})
	if missingKey != "" {
		return "", fmt.Errorf("missing variable %q while expanding %q", missingKey, input)
	}
	return output, nil
}

func checkStatus(tc testCase, resp *apiResponse) error {
	if statusMatches(tc.ExpectedStatus, resp.StatusCode) {
		return nil
	}
	return fmt.Errorf("%s expected HTTP status %q, got %d. Body: %s", tc.ID, tc.ExpectedStatus, resp.StatusCode, string(resp.Body))
}

func expectedResultText(tc testCase) string {
	parts := []string{}
	if strings.TrimSpace(tc.ExpectedStatus) != "" {
		parts = append(parts, "HTTP "+strings.TrimSpace(tc.ExpectedStatus))
	}
	if strings.TrimSpace(tc.Assertions) != "" {
		parts = append(parts, "assertions="+strings.TrimSpace(tc.Assertions))
	}
	if len(parts) == 0 {
		return "success"
	}
	return strings.Join(parts, "; ")
}

func actualResultText(resp *apiResponse, err error) string {
	if err != nil {
		return "FAIL: " + err.Error()
	}
	return fmt.Sprintf("PASS: HTTP %d; assertions passed", resp.StatusCode)
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
			code, err := strconv.Atoi(part)
			if err == nil && actual == code {
				return true
			}
		}
	}
	return false
}

func applyExtracts(extractSpec string, resp *apiResponse, vars map[string]string, createdUserVars *[]string) error {
	if strings.TrimSpace(extractSpec) == "" {
		return nil
	}
	for _, item := range strings.Split(extractSpec, ";") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("bad extract expression %q; want variable=json.path", item)
		}
		key := strings.TrimSpace(parts[0])
		path := strings.TrimSpace(parts[1])
		value, ok := valueAt(resp.JSON, path)
		if !ok {
			return fmt.Errorf("extract %q failed: JSON path %q not found. Body: %s", item, path, string(resp.Body))
		}
		vars[key] = fmt.Sprint(value)
		if strings.HasSuffix(strings.ToLower(key), "id") && strings.Contains(strings.ToLower(key), "root") == false {
			*createdUserVars = append(*createdUserVars, key)
		}
	}
	return nil
}

func runAssertions(assertionSpec string, resp *apiResponse, vars map[string]string) error {
	if strings.TrimSpace(assertionSpec) == "" {
		return nil
	}
	for _, raw := range strings.Split(assertionSpec, ";") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		assertion, err := expandRequiredVars(raw, vars)
		if err != nil {
			return err
		}
		opAndArg := strings.SplitN(assertion, ":", 2)
		op := opAndArg[0]
		switch op {
		case "eq":
			parts := strings.SplitN(assertion, ":", 3)
			if len(parts) != 3 {
				return fmt.Errorf("bad eq assertion %q; want eq:json.path:expected", assertion)
			}
			actual, ok := stringAt(resp.JSON, parts[1])
			if !ok {
				return fmt.Errorf("eq assertion path %q not found. Body: %s", parts[1], string(resp.Body))
			}
			if actual != parts[2] {
				return fmt.Errorf("eq assertion failed for %q: got %q, want %q. Body: %s", parts[1], actual, parts[2], string(resp.Body))
			}
		case "notEq":
			parts := strings.SplitN(assertion, ":", 3)
			if len(parts) != 3 {
				return fmt.Errorf("bad notEq assertion %q; want notEq:json.path:notExpected", assertion)
			}
			actual, ok := stringAt(resp.JSON, parts[1])
			if !ok {
				return fmt.Errorf("notEq assertion path %q not found. Body: %s", parts[1], string(resp.Body))
			}
			if actual == parts[2] {
				return fmt.Errorf("notEq assertion failed for %q: got disallowed value %q. Body: %s", parts[1], actual, string(resp.Body))
			}
		case "has":
			if len(opAndArg) != 2 {
				return fmt.Errorf("bad has assertion %q; want has:json.path", assertion)
			}
			if _, ok := valueAt(resp.JSON, opAndArg[1]); !ok {
				return fmt.Errorf("has assertion failed: path %q not found. Body: %s", opAndArg[1], string(resp.Body))
			}
		case "notHas":
			if len(opAndArg) != 2 {
				return fmt.Errorf("bad notHas assertion %q; want notHas:json.path", assertion)
			}
			if _, ok := valueAt(resp.JSON, opAndArg[1]); ok {
				return fmt.Errorf("notHas assertion failed: path %q unexpectedly present. Body: %s", opAndArg[1], string(resp.Body))
			}
		case "containsUserID":
			if len(opAndArg) != 2 {
				return fmt.Errorf("bad containsUserID assertion %q", assertion)
			}
			if !usersContainsID(resp.JSON, opAndArg[1]) {
				return fmt.Errorf("expected users list to contain id %q. Body: %s", opAndArg[1], string(resp.Body))
			}
		case "notContainsUserID":
			if len(opAndArg) != 2 {
				return fmt.Errorf("bad notContainsUserID assertion %q", assertion)
			}
			if usersContainsID(resp.JSON, opAndArg[1]) {
				return fmt.Errorf("expected users list not to contain id %q. Body: %s", opAndArg[1], string(resp.Body))
			}
		case "notHasUsersField":
			if len(opAndArg) != 2 {
				return fmt.Errorf("bad notHasUsersField assertion %q", assertion)
			}
			if usersContainField(resp.JSON, opAndArg[1]) {
				return fmt.Errorf("expected users list not to contain field %q. Body: %s", opAndArg[1], string(resp.Body))
			}
		case "usersAreStrings":
			if len(opAndArg) != 1 {
				return fmt.Errorf("bad usersAreStrings assertion %q", assertion)
			}
			if !usersAreStrings(resp.JSON) {
				return fmt.Errorf("expected users list to be an array of strings only. Body: %s", string(resp.Body))
			}
		default:
			return fmt.Errorf("unknown assertion operation %q in %q", op, assertion)
		}
	}
	return nil
}

func writeTestReportCSV(path string, rows []testReportRow) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create report directory for %q: %w", path, err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create report CSV %q: %w", path, err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	if err := writer.Write([]string{"caller_email", "target", "test_description", "expected_result", "actual_result"}); err != nil {
		return fmt.Errorf("write report header %q: %w", path, err)
	}
	for _, row := range rows {
		if err := writer.Write([]string{row.CallerEmail, row.Target, row.TestDescription, row.ExpectedResult, row.ActualResult}); err != nil {
			return fmt.Errorf("write report row %q: %w", path, err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush report CSV %q: %w", path, err)
	}
	return nil
}

func callerEmailForActor(actor string, vars map[string]string) string {
	switch strings.ToLower(strings.TrimSpace(actor)) {
	case "", "anonymous":
		return ""
	case "root":
		return vars["rootEmail"]
	case "admina":
		return vars["adminAEmail"]
	case "adminb":
		return vars["adminBEmail"]
	case "csra":
		return vars["csrAEmail"]
	case "csrb":
		return vars["csrBEmail"]
	case "subscribers":
		return vars["subscriberSEmail"]
	default:
		if email, ok := vars[actor+"Email"]; ok {
			return email
		}
		return actor
	}
}

func valueAt(obj map[string]any, path string) (any, bool) {
	if obj == nil {
		return nil, false
	}
	path = strings.TrimPrefix(path, "json.")
	parts := strings.Split(path, ".")
	var cur any = obj
	for _, part := range parts {
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

func usersContainField(obj map[string]any, field string) bool {
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
		user, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if _, ok := user[field]; ok {
			return true
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

func loadDotEnv(t *testing.T) {
	t.Helper()

	pathCandidates := []string{".env"}
	if _, file, _, ok := runtime.Caller(0); ok {
		pathCandidates = append(pathCandidates, filepath.Join(filepath.Dir(file), ".env"))
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
		value := strings.TrimSpace(parts[1])
		value = strings.Trim(value, `"'`)
		if key == "" {
			continue
		}
		if os.Getenv(key) == "" {
			if err := os.Setenv(key, value); err != nil {
				return err
			}
		}
	}
	return scanner.Err()
}

func envBool(key string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func urlEscape(s string) string {
	return url.QueryEscape(s)
}
