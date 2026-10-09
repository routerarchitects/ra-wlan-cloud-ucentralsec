package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestAdminRootAccessFromCSV is intentionally driven by test_cases.csv so QA can
// add or reorder scenarios without changing Go code. Only the ROOT account must
// already exist. Every other user in the scenario is created through the API.
func TestAdminRootAccessFromCSV(t *testing.T) {
	loadDotEnv(t)

	baseURL := requireEnvOrSkip(t, "OWSEC_BASE_URL")
	tlsRootCA := requireEnvOrSkip(t, "OW_RBAC_TLS_ROOT_CA")
	rootEmail := requireEnvOrSkip(t, "OWSEC_ROOT_EMAIL")
	rootPassword := requireEnvOrSkip(t, "OWSEC_ROOT_PASSWORD")

	runID := fmt.Sprintf("%d", time.Now().UnixNano())
	testPassword := fmt.Sprintf("TestUser-%s!9", runID)
	vars := map[string]string{
		"runID":        runID,
		"rootEmail":    rootEmail,
		"rootPassword": rootPassword,
		"testPassword": testPassword,
		"entityA":      "autotest-entity-a-" + runID,
		"entityB":      "autotest-entity-b-" + runID,

		"adminAEmail":                "autotest-admin-a-" + runID + "@example.com",
		"adminBEmail":                "autotest-admin-b-" + runID + "@example.com",
		"csrAEmail":                  "autotest-csr-a-" + runID + "@example.com",
		"csrBEmail":                  "autotest-csr-b-" + runID + "@example.com",
		"deleteAEmail":               "autotest-delete-a-" + runID + "@example.com",
		"rootDeleteEmail":            "autotest-root-delete-" + runID + "@example.com",
		"rootRoleChangeEmail":        "autotest-root-role-change-" + runID + "@example.com",
		"csrCreateAttemptEmail":      "autotest-csr-create-denied-" + runID + "@example.com",
		"adminAEmailEscaped":         url.QueryEscape("autotest-admin-a-" + runID + "@example.com"),
		"adminBEmailEscaped":         url.QueryEscape("autotest-admin-b-" + runID + "@example.com"),
		"csrAEmailEscaped":           url.QueryEscape("autotest-csr-a-" + runID + "@example.com"),
		"csrBEmailEscaped":           url.QueryEscape("autotest-csr-b-" + runID + "@example.com"),
		"deleteAEmailEscaped":        url.QueryEscape("autotest-delete-a-" + runID + "@example.com"),
		"rootDeleteEmailEscaped":     url.QueryEscape("autotest-root-delete-" + runID + "@example.com"),
		"rootRoleChangeEmailEscaped": url.QueryEscape("autotest-root-role-change-" + runID + "@example.com"),
		"updatedCSRName":             "Updated CSR A " + runID,
		"updatedPassword":            "UpdatedUser-" + runID + "!9",
		"createdByOverwriteAttempt":  "should-not-be-used-" + runID,
	}

	httpClient, err := NewHTTPClient(tlsRootCA)
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}

	client := newAPIClient(baseURL, httpClient)
	testCases := loadTestCases(t)
	createdUserVars := make([]string, 0, 8)
	reportRows := make([]testReportRow, 0, len(testCases))
	reportPath := outputCSVPath()

	if envBool("OWSEC_CLEANUP_ALL_DATA") {
		t.Cleanup(func() {
			cleanupUsers(t, client, vars, createdUserVars)
		})
	}

	for _, tc := range testCases {
		tc := tc
		actualResult := ""
		t.Run(tc.ID+"_"+sanitizeSubtestName(tc.Name), func(t *testing.T) {
			resp, err := executeTestCase(client, tc, vars, &createdUserVars)
			actualResult = actualResultText(resp, err)
			if err != nil {
				t.Error(err)
				return
			}
		})
		target, err := resolveTarget(tc, vars)
		if err != nil {
			t.Fatalf("resolve target for %s: %v", tc.ID, err)
		}
		expectedResult, err := resolveReportText(expectedResultText(tc), vars)
		if err != nil {
			t.Fatalf("resolve expected result for %s: %v", tc.ID, err)
		}
		reportRows = append(reportRows, testReportRow{
			CallerEmail:     callerEmailForActor(tc.Actor, vars),
			Target:          target,
			TestDescription: tc.Description,
			ExpectedResult:  expectedResult,
			ActualResult:    actualResult,
		})
	}

	if err := writeTestReportCSV(reportPath, reportRows); err != nil {
		t.Fatalf("write output CSV %q: %v", reportPath, err)
	}

	internalBaseURL := strings.TrimSpace(os.Getenv("OWSEC_INTERNAL_BASE_URL"))
	if internalBaseURL != "" {
		if err := verifyInternalUserRoutes(httpClient, internalBaseURL, vars["rootID"]); err != nil {
			t.Fatalf("verify internal user routes: %v", err)
		}
	}
}

func executeTestCase(client *apiClient, tc testCase, vars map[string]string, createdUserVars *[]string) (*apiResponse, error) {
	switch strings.ToUpper(tc.Method) {
	case "LOGIN":
		body, err := expandRequiredVars(tc.Body, vars)
		if err != nil {
			return nil, err
		}
		var loginBody struct {
			UserID   string `json:"userId"`
			Password string `json:"password"`
		}
		if err := json.Unmarshal([]byte(body), &loginBody); err != nil {
			return nil, fmt.Errorf("bad LOGIN body in CSV: %v; body=%s", err, body)
		}
		resp, err := client.login(tc.Actor, loginBody.UserID, loginBody.Password)
		if err != nil {
			return resp, fmt.Errorf("API call failed: %w", err)
		}
		if err := checkStatus(tc, resp); err != nil {
			return resp, err
		}
		if err := applyExtracts(tc.Extract, resp, vars, createdUserVars); err != nil {
			return resp, err
		}
		if err := runAssertions(tc.Assertions, resp, vars); err != nil {
			return resp, err
		}
		return resp, nil
	default:
		path, err := expandRequiredVars(tc.Path, vars)
		if err != nil {
			return nil, err
		}
		body, err := expandRequiredVars(tc.Body, vars)
		if err != nil {
			return nil, err
		}
		resp, err := client.do(tc.Actor, tc.Method, path, body)
		if err != nil {
			return resp, fmt.Errorf("API call failed: %w", err)
		}
		if err := checkStatus(tc, resp); err != nil {
			return resp, err
		}
		if err := applyExtracts(tc.Extract, resp, vars, createdUserVars); err != nil {
			return resp, err
		}
		if err := runAssertions(tc.Assertions, resp, vars); err != nil {
			return resp, err
		}
		return resp, nil
	}
}

func resolveTarget(tc testCase, vars map[string]string) (string, error) {
	target := strings.TrimSpace(tc.Target)
	if target == "" {
		return "", nil
	}
	resolved, err := expandRequiredVars(target, vars)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func resolveReportText(input string, vars map[string]string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", nil
	}
	return expandOptionalVars(input, vars), nil
}

func expandOptionalVars(input string, vars map[string]string) string {
	return placeholderRe.ReplaceAllStringFunc(input, func(match string) string {
		key := strings.TrimSuffix(strings.TrimPrefix(match, "{{"), "}}")
		if value, ok := vars[key]; ok {
			return value
		}
		return match
	})
}

func outputCSVPath() string {
	path := strings.TrimSpace(os.Getenv("OWSEC_OUTPUT_CSV"))
	if path != "" {
		return path
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "test_results.csv"
	}
	return filepath.Join(filepath.Dir(file), "test_results.csv")
}

func cleanupUsers(t *testing.T, client *apiClient, vars map[string]string, createdUserVars []string) {
	t.Helper()
	if client.tokens["root"] == "" {
		t.Log("root token was not acquired; skipping cleanup")
		return
	}

	seen := map[string]bool{}
	for i := len(createdUserVars) - 1; i >= 0; i-- {
		varName := createdUserVars[i]
		id := vars[varName]
		if id == "" || id == vars["rootID"] || seen[id] {
			continue
		}
		seen[id] = true

		resp, err := client.do("root", http.MethodDelete, "/api/v1/user/"+url.PathEscape(id), "")
		if err != nil {
			t.Logf("cleanup delete %s=%s failed: %v", varName, id, err)
			continue
		}
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
			t.Logf("cleanup delete %s=%s got HTTP %d body=%s", varName, id, resp.StatusCode, string(resp.Body))
		}
	}
}

func getInternalAuthEnv() (string, string) {
	name := strings.TrimSpace(os.Getenv("OWSEC_INTERNAL_NAME"))
	if name == "" {
		name = strings.TrimSpace(os.Getenv("X_INTERNAL_NAME"))
	}
	key := strings.TrimSpace(os.Getenv("OWSEC_INTERNAL_API_KEY"))
	if key == "" {
		key = strings.TrimSpace(os.Getenv("X_API_KEY"))
	}
	return name, key
}

func verifyInternalUserRoutes(httpClient *http.Client, internalBaseURL, rootID string) error {
	if strings.TrimSpace(rootID) == "" {
		return fmt.Errorf("rootID is required for internal route verification")
	}

	internalName, internalAPIKey := getInternalAuthEnv()
	if internalName == "" || internalAPIKey == "" {
		return fmt.Errorf("internal authentication requires OWSEC_INTERNAL_NAME (or X_INTERNAL_NAME) and OWSEC_INTERNAL_API_KEY (or X_API_KEY)")
	}

	internalClient := newAPIClient(strings.TrimSuffix(internalBaseURL, "/api/v1"), httpClient)

	// 1. Positive Internal Auth Checks (Authorized internal owprov service using private or public endpoint)
	positiveChecks := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/v1/user/" + url.PathEscape(rootID)},
		{method: http.MethodGet, path: "/api/v1/user/tip@ucentral.com?byEmail=true"},
	}

	for _, check := range positiveChecks {
		resp, err := internalClient.doWithHeaders("", check.method, check.path, "", map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       internalAPIKey,
		})
		if err != nil {
			return fmt.Errorf("positive internal request %s %s failed: %w", check.method, check.path, err)
		}
		if !statusMatches("200", resp.StatusCode) {
			return fmt.Errorf("positive internal request %s %s expected 200, got %d. Body: %s",
				check.method, check.path, resp.StatusCode, string(resp.Body))
		}
		var userObj map[string]interface{}
		if err := json.Unmarshal(resp.Body, &userObj); err != nil {
			return fmt.Errorf("positive internal request %s %s returned invalid JSON: %w", check.method, check.path, err)
		}
		if _, hasID := userObj["id"]; !hasID {
			return fmt.Errorf("positive internal request %s %s payload missing required 'id' field", check.method, check.path)
		}
		if _, hasCreatedBy := userObj["createdBy"]; !hasCreatedBy {
			return fmt.Errorf("positive internal request %s %s payload missing required 'createdBy' field", check.method, check.path)
		}
	}

	// 2. Negative Internal Auth Check: Non-existent email lookup should return 404 Not Found
	notFoundEmailResp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/user/nonexistent-user-xyz-999@example.com?byEmail=true", "", map[string]string{
		"X-INTERNAL-NAME": internalName,
		"X-API-KEY":       internalAPIKey,
	})
	if err != nil {
		return fmt.Errorf("negative internal request (non-existent email) failed: %w", err)
	}
	if !statusMatches("404", notFoundEmailResp.StatusCode) {
		return fmt.Errorf("negative internal request (non-existent email) expected 404, got %d. Body: %s",
			notFoundEmailResp.StatusCode, string(notFoundEmailResp.Body))
	}

	// 3. Negative Internal Auth Check: Valid API Key + Registered non-owprov Service URL (owfms at https://localhost:17004)
	unauthServiceResp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/user/"+url.PathEscape(rootID), "", map[string]string{
		"X-INTERNAL-NAME": "https://localhost:17004", // private endpoint of registered owfms service (not owprov)
		"X-API-KEY":       internalAPIKey,           // valid SHA256 API key
	})
	if err != nil {
		return fmt.Errorf("negative internal request (registered owfms service) failed: %w", err)
	}
	if !statusMatches("401|403", unauthServiceResp.StatusCode) {
		return fmt.Errorf("negative internal request (registered owfms service) expected 401/403 access denied, got %d. Body: %s",
			unauthServiceResp.StatusCode, string(unauthServiceResp.Body))
	}

	// 4. Negative Internal Auth Check: Valid API Key + Completely Unregistered / Unknown Service URL
	unregisteredSvcResp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/user/"+url.PathEscape(rootID), "", map[string]string{
		"X-INTERNAL-NAME": "https://unknown-service-domain:9999", // unregistered service URL
		"X-API-KEY":       internalAPIKey,
	})
	if err != nil {
		return fmt.Errorf("negative internal request (unregistered service) failed: %w", err)
	}
	if !statusMatches("401|403", unregisteredSvcResp.StatusCode) {
		return fmt.Errorf("negative internal request (unregistered service) expected 401/403 access denied, got %d. Body: %s",
			unregisteredSvcResp.StatusCode, string(unregisteredSvcResp.Body))
	}

	// 5. Positive Internal Auth Check: Valid API Key + owprov Public Endpoint (Both private and public endpoints accepted)
	publicEndpointResp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/user/"+url.PathEscape(rootID), "", map[string]string{
		"X-INTERNAL-NAME": "https://localhost:16005", // owprov public endpoint
		"X-API-KEY":       internalAPIKey,
	})
	if err != nil {
		return fmt.Errorf("positive internal request (owprov public endpoint) failed: %w", err)
	}
	if !statusMatches("200", publicEndpointResp.StatusCode) {
		return fmt.Errorf("positive internal request (owprov public endpoint) expected 200, got %d. Body: %s",
			publicEndpointResp.StatusCode, string(publicEndpointResp.Body))
	}

	// 5b. Negative Internal Auth Check: Valid API Key + owfms Public Endpoint
	unauthPublicResp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/user/"+url.PathEscape(rootID), "", map[string]string{
		"X-INTERNAL-NAME": "https://localhost:16004", // public endpoint of registered owfms service (not owprov)
		"X-API-KEY":       internalAPIKey,
	})
	if err != nil {
		return fmt.Errorf("negative internal request (owfms public endpoint) failed: %w", err)
	}
	if !statusMatches("401|403", unauthPublicResp.StatusCode) {
		return fmt.Errorf("negative internal request (owfms public endpoint) expected 401/403 access denied, got %d. Body: %s",
			unauthPublicResp.StatusCode, string(unauthPublicResp.Body))
	}

	// 6. Negative Internal Auth Check: Non-GET HTTP Methods (POST, PUT, DELETE) on Internal User Routes
	methodChecks := []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodPost, path: "/api/v1/user/0", body: `{"name":"test"}`},
		{method: http.MethodPut, path: "/api/v1/user/" + url.PathEscape(rootID), body: `{"name":"test"}`},
		{method: http.MethodDelete, path: "/api/v1/user/" + url.PathEscape(rootID), body: ""},
	}
	for _, check := range methodChecks {
		resp, err := internalClient.doWithHeaders("", check.method, check.path, check.body, map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       internalAPIKey,
		})
		if err != nil {
			return fmt.Errorf("negative internal request (%s %s) failed: %w", check.method, check.path, err)
		}
		if !statusMatches("400|401|403|405", resp.StatusCode) {
			return fmt.Errorf("negative internal request (%s %s) expected 400/401/403/405 access denied, got %d. Body: %s",
				check.method, check.path, resp.StatusCode, string(resp.Body))
		}
	}

	// 7. Negative Internal Auth Check: Invalid API Key + Authorized Service Name
	invalidKeyResp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/user/"+url.PathEscape(rootID), "", map[string]string{
		"X-INTERNAL-NAME": internalName,
		"X-API-KEY":       "invalid-key-12345",
	})
	if err != nil {
		return fmt.Errorf("negative internal request (invalid key) failed: %w", err)
	}
	if !statusMatches("401|403", invalidKeyResp.StatusCode) {
		return fmt.Errorf("negative internal request (invalid key) expected 401/403 access denied, got %d. Body: %s",
			invalidKeyResp.StatusCode, string(invalidKeyResp.Body))
	}

	// 8. Negative Internal Auth Check: Unauthenticated (Missing Headers)
	noAuthResp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/user/"+url.PathEscape(rootID), "", map[string]string{})
	if err != nil {
		return fmt.Errorf("negative internal request (unauthenticated) failed: %w", err)
	}
	if !statusMatches("401|403", noAuthResp.StatusCode) {
		return fmt.Errorf("negative internal request (unauthenticated) expected 401/403 access denied, got %d. Body: %s",
			noAuthResp.StatusCode, string(noAuthResp.Body))
	}

	return nil
}

func sanitizeSubtestName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "case"
	}
	replacer := strings.NewReplacer(" ", "_", "/", "_", "\\", "_", ":", "_", "?", "_", "&", "_")
	return replacer.Replace(s)
}

// TestInternalUserRoutesLive verifies internal IPC header authentication (X-INTERNAL-NAME & X-API-KEY)
// as well as internal /api/v1/users RBAC against a live ucentralsec C++ daemon instance.
func TestInternalUserRoutesLive(t *testing.T) {
	internalBaseURL := strings.TrimSpace(os.Getenv("OWSEC_INTERNAL_BASE_URL"))
	internalName, internalAPIKey := getInternalAuthEnv()

	if internalBaseURL == "" || internalName == "" || internalAPIKey == "" {
		t.Fatalf("Live daemon verification failed: OWSEC_INTERNAL_BASE_URL, OWSEC_INTERNAL_NAME (or X_INTERNAL_NAME), and OWSEC_INTERNAL_API_KEY (or X_API_KEY) environment variables are required.")
	}

	tlsRootCA := os.Getenv("OW_RBAC_TLS_ROOT_CA")
	httpClient, err := NewHTTPClient(tlsRootCA)
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}

	// Verify live internal routes using configured values
	rootID := os.Getenv("OWSEC_ROOT_ID")
	if rootID == "" || rootID == "0" {
		rootID = "11111111-0000-0000-6666-999999999999"
	}

	t.Run("SingularUser_IPC_Auth", func(t *testing.T) {
		if err := verifyInternalUserRoutes(httpClient, internalBaseURL, rootID); err != nil {
			t.Fatalf("live internal user routes verification failed: %v", err)
		}
	})

	baseURL := strings.TrimSpace(os.Getenv("OWSEC_BASE_URL"))
	if baseURL == "" {
		baseURL = strings.Replace(internalBaseURL, ":17001", ":16001", 1)
	}

	t.Run("PluralUsers_InternalAndPublic_RBAC", func(t *testing.T) {
		verifyInternalUsersPluralRoutes(t, httpClient, baseURL, internalBaseURL, internalName, internalAPIKey, rootID)
	})
}

func loginUserForTest(client *apiClient, email, password string) (string, error) {
	bodyMap := map[string]string{
		"userId":   email,
		"password": password,
	}
	bodyBytes, _ := json.Marshal(bodyMap)
	resp, err := client.doWithHeaders("", http.MethodPost, "/api/v1/oauth2", string(bodyBytes), nil)
	if err != nil {
		return "", fmt.Errorf("login request failed: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		token, _ := stringAt(resp.JSON, "access_token")
		if token != "" {
			return token, nil
		}
	}

	// Only permit first-boot password initialization if the target environment is explicitly
	// marked as ephemeral with OW_EPHEMERAL_TEST=true. Never rely solely on CI=true to avoid
	// mutating credentials on persistent lab or staging deployments.
	if strings.TrimSpace(os.Getenv("OW_EPHEMERAL_TEST")) != "true" {
		return "", fmt.Errorf("initial login for %s failed with status %d (password initialization disallowed without OW_EPHEMERAL_TEST=true): %s", email, resp.StatusCode, string(resp.Body))
	}

	// In ephemeral CI mode, if initial root login requires password change (fresh container boot), supply newPassword
	newPassword := strings.TrimSpace(os.Getenv("OWSEC_ROOT_NEW_PASSWORD"))
	if newPassword == "" {
		newPassword = "TestPassword123!"
	}
	changeBodyMap := map[string]string{
		"userId":      email,
		"password":    password,
		"newPassword": newPassword,
	}
	changeBodyBytes, _ := json.Marshal(changeBodyMap)
	resp, err = client.doWithHeaders("", http.MethodPost, "/api/v1/oauth2", string(changeBodyBytes), nil)
	if err != nil {
		return "", fmt.Errorf("login with newPassword failed: %w", err)
	}

	if resp.StatusCode == http.StatusOK {
		token, _ := stringAt(resp.JSON, "access_token")
		if token != "" {
			return token, nil
		}
	}

	// If password was already updated to newPassword in a previous CI step, retry with newPassword
	retryBodyMap := map[string]string{
		"userId":   email,
		"password": newPassword,
	}
	retryBodyBytes, _ := json.Marshal(retryBodyMap)
	resp, err = client.doWithHeaders("", http.MethodPost, "/api/v1/oauth2", string(retryBodyBytes), nil)
	if err != nil {
		return "", fmt.Errorf("retry login failed: %w", err)
	}
	if resp.StatusCode == http.StatusOK {
		token, _ := stringAt(resp.JSON, "access_token")
		if token != "" {
			return token, nil
		}
	}

	return "", fmt.Errorf("login for %s failed with status %d: %s", email, resp.StatusCode, string(resp.Body))
}

func createExpiredTokenInDB(t *testing.T, rootID string) (string, func(), error) {
	expiredToken := fmt.Sprintf("test-expired-token-%d", time.Now().UnixNano())

	if envToken := strings.TrimSpace(os.Getenv("OWSEC_EXPIRED_TOKEN")); envToken != "" {
		return envToken, func() {}, nil
	}

	// Fail closed if the environment is not explicitly designated as ephemeral
	if strings.TrimSpace(os.Getenv("OW_EPHEMERAL_TEST")) != "true" {
		return "", func() {}, fmt.Errorf("direct database expired-token fixture insertion disallowed unless OW_EPHEMERAL_TEST=true is explicitly configured")
	}

	insertSQL := fmt.Sprintf(
		"INSERT INTO tokens (token, refreshtoken, tokentype, username, created, expires, idletimeout, revocationdate, lastrefresh) VALUES ('%s', '', 'Bearer', '%s', 1, 1, 0, 0, 0);",
		expiredToken, rootID,
	)
	deleteSQL := fmt.Sprintf("DELETE FROM tokens WHERE token = '%s';", expiredToken)

	var failureErrs []string

	// 1. Explicit SQLite database path or ephemeral test path
	sqlitePath := strings.TrimSpace(os.Getenv("OWSEC_SQLITE_PATH"))
	if sqlitePath == "" {
		sqlitePath = "/tmp/owsec-data/data/security.db"
	}
	if _, err := os.Stat(sqlitePath); err == nil {
		// 1a. Try host sqlite3 CLI
		if cmd := exec.Command("sqlite3", sqlitePath, insertSQL); cmd.Run() == nil {
			cleanup := func() {
				delCmd := exec.Command("sqlite3", sqlitePath, deleteSQL)
				if out, delErr := delCmd.CombinedOutput(); delErr != nil {
					t.Errorf("cleanup failed: unable to delete expired token from SQLite %s: %v (output: %s)", sqlitePath, delErr, string(out))
				}
			}
			return expiredToken, cleanup, nil
		}

		// 1b. Try host python3 sqlite3 module
		pyInsert := fmt.Sprintf("import sqlite3; c=sqlite3.connect('%s'); c.execute('''%s'''); c.commit()", sqlitePath, insertSQL)
		pyDelete := fmt.Sprintf("import sqlite3; c=sqlite3.connect('%s'); c.execute('''%s'''); c.commit()", sqlitePath, deleteSQL)
		if cmd := exec.Command("python3", "-c", pyInsert); cmd.Run() == nil {
			cleanup := func() {
				delCmd := exec.Command("python3", "-c", pyDelete)
				if out, delErr := delCmd.CombinedOutput(); delErr != nil {
					t.Errorf("cleanup failed: unable to delete expired token via python3 from SQLite %s: %v (output: %s)", sqlitePath, delErr, string(out))
				}
			}
			return expiredToken, cleanup, nil
		} else {
			out, _ := exec.Command("python3", "-c", pyInsert).CombinedOutput()
			failureErrs = append(failureErrs, fmt.Sprintf("python3 on %s failed: %s", sqlitePath, strings.TrimSpace(string(out))))
		}
	} else {
		failureErrs = append(failureErrs, fmt.Sprintf("sqlite path %s not found: %v", sqlitePath, err))
	}

	// 2. Explicitly configured test container
	dbContainer := strings.TrimSpace(os.Getenv("OWSEC_DB_CONTAINER"))
	if dbContainer != "" {
		for _, p := range []string{"/owsec-data/data/security.db", "/owsec-data/security.db"} {
			cmd := exec.Command("docker", "exec", dbContainer, "sqlite3", p, insertSQL)
			if err := cmd.Run(); err == nil {
				cleanup := func() {
					delCmd := exec.Command("docker", "exec", dbContainer, "sqlite3", p, deleteSQL)
					if out, delErr := delCmd.CombinedOutput(); delErr != nil {
						t.Errorf("cleanup failed: unable to delete expired token from container %s (%s): %v (output: %s)", dbContainer, p, delErr, string(out))
					}
				}
				return expiredToken, cleanup, nil
			}
		}

		cmd := exec.Command("docker", "exec", dbContainer, "psql", "-U", "owsec", "-d", "owsec", "-c", insertSQL)
		if err := cmd.Run(); err == nil {
			cleanup := func() {
				delCmd := exec.Command("docker", "exec", dbContainer, "psql", "-U", "owsec", "-d", "owsec", "-c", deleteSQL)
				if out, delErr := delCmd.CombinedOutput(); delErr != nil {
					t.Errorf("cleanup failed: unable to delete expired token from PostgreSQL container %s: %v (output: %s)", dbContainer, delErr, string(out))
				}
			}
			return expiredToken, cleanup, nil
		}
		failureErrs = append(failureErrs, fmt.Sprintf("failed accessing database inside OWSEC_DB_CONTAINER (%s)", dbContainer))
	}

	errMsg := "no accessible test database target found to insert expired token (set OWSEC_SQLITE_PATH or OWSEC_DB_CONTAINER)"
	if len(failureErrs) > 0 {
		errMsg += ": " + strings.Join(failureErrs, "; ")
	}
	return "", func() {}, fmt.Errorf("%s", errMsg)
}

func verifyInternalUsersPluralRoutes(t *testing.T, httpClient *http.Client, baseURL, internalBaseURL, internalName, internalAPIKey, rootID string) {
	internalClient := newAPIClient(strings.TrimSuffix(internalBaseURL, "/api/v1"), httpClient)
	publicClient := newAPIClient(strings.TrimSuffix(baseURL, "/api/v1"), httpClient)

	rootEmail := strings.TrimSpace(os.Getenv("OWSEC_ROOT_EMAIL"))
	if rootEmail == "" {
		rootEmail = "tip@ucentral.com"
	}
	rootPassword := strings.TrimSpace(os.Getenv("OWSEC_ROOT_PASSWORD"))
	if rootPassword == "" {
		rootPassword = "openwifi"
	}

	// Obtain valid ROOT bearer token
	rootToken, err := loginUserForTest(publicClient, rootEmail, rootPassword)
	if err != nil {
		rootToken, err = loginUserForTest(internalClient, rootEmail, rootPassword)
		if err != nil {
			t.Fatalf("failed to obtain ROOT bearer token for users route test: %v", err)
		}
	}

	// Create temporary non-admin (CSR) user to obtain non-admin bearer token
	runID := time.Now().UnixNano()
	csrEmail := fmt.Sprintf("autotest-csr-internal-%d@example.com", runID)
	csrPassword := fmt.Sprintf("CsrPass-%d!9", runID)
	createBody := map[string]any{
		"email":           csrEmail,
		"name":            "AutoTest CSR",
		"currentPassword": csrPassword,
		"userRole":        "csr",
	}
	createBytes, _ := json.Marshal(createBody)

	createResp, err := publicClient.doWithHeaders("", http.MethodPost, "/api/v1/user/0", string(createBytes), map[string]string{
		"Authorization": "Bearer " + rootToken,
	})
	if err != nil {
		t.Fatalf("failed to create non-admin CSR user: %v", err)
	}
	if createResp.StatusCode != http.StatusOK && createResp.StatusCode != http.StatusCreated {
		t.Fatalf("create CSR user expected 200/201, got %d: %s", createResp.StatusCode, string(createResp.Body))
	}

	var createdUser map[string]any
	_ = json.Unmarshal(createResp.Body, &createdUser)
	csrUserID, _ := stringAt(createdUser, "id")

	cleanupUser := func(id, label string) {
		if id == "" {
			return
		}
		resp, err := publicClient.doWithHeaders("", http.MethodDelete, "/api/v1/user/"+id, "", map[string]string{
			"Authorization": "Bearer " + rootToken,
		})
		if err != nil {
			t.Errorf("cleanup failed for %s (%s): %v", label, id, err)
		} else if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
			t.Errorf("cleanup for %s (%s) returned unexpected status %d: %s", label, id, resp.StatusCode, string(resp.Body))
		}
	}

	t.Cleanup(func() {
		cleanupUser(csrUserID, "CSR user")
	})

	csrToken, err := loginUserForTest(publicClient, csrEmail, csrPassword)
	if err != nil {
		csrToken, err = loginUserForTest(internalClient, csrEmail, csrPassword)
		if err != nil {
			t.Fatalf("failed to login as non-admin CSR user: %v", err)
		}
	}

	// Create two admins (Admin-A and Admin-B) and two scoped users (User-A1 and User-B1) to test ADMIN tenant isolation
	adminAPassword := fmt.Sprintf("AdminAPass-%d!9", runID)
	adminAEmail := fmt.Sprintf("autotest-admin-a-%d@example.com", runID)
	createAdminABody, _ := json.Marshal(map[string]any{
		"email":           adminAEmail,
		"name":            "AutoTest Admin A",
		"currentPassword": adminAPassword,
		"userRole":        "admin",
	})
	createAdminAResp, err := publicClient.doWithHeaders("", http.MethodPost, "/api/v1/user/0", string(createAdminABody), map[string]string{
		"Authorization": "Bearer " + rootToken,
	})
	if err != nil {
		t.Fatalf("failed to create Admin A: %v", err)
	}
	if createAdminAResp.StatusCode != http.StatusOK && createAdminAResp.StatusCode != http.StatusCreated {
		t.Fatalf("create Admin A expected 200/201, got %d: %s", createAdminAResp.StatusCode, string(createAdminAResp.Body))
	}
	var createdAdminA map[string]any
	_ = json.Unmarshal(createAdminAResp.Body, &createdAdminA)
	adminAID, _ := stringAt(createdAdminA, "id")

	t.Cleanup(func() {
		cleanupUser(adminAID, "Admin A")
	})

	adminAToken, err := loginUserForTest(publicClient, adminAEmail, adminAPassword)
	if err != nil {
		adminAToken, err = loginUserForTest(internalClient, adminAEmail, adminAPassword)
		if err != nil {
			t.Fatalf("failed to login as Admin A: %v", err)
		}
	}

	adminBPassword := fmt.Sprintf("AdminBPass-%d!9", runID)
	adminBEmail := fmt.Sprintf("autotest-admin-b-%d@example.com", runID)
	createAdminBBody, _ := json.Marshal(map[string]any{
		"email":           adminBEmail,
		"name":            "AutoTest Admin B",
		"currentPassword": adminBPassword,
		"userRole":        "admin",
	})
	createAdminBResp, err := publicClient.doWithHeaders("", http.MethodPost, "/api/v1/user/0", string(createAdminBBody), map[string]string{
		"Authorization": "Bearer " + rootToken,
	})
	if err != nil {
		t.Fatalf("failed to create Admin B: %v", err)
	}
	if createAdminBResp.StatusCode != http.StatusOK && createAdminBResp.StatusCode != http.StatusCreated {
		t.Fatalf("create Admin B expected 200/201, got %d: %s", createAdminBResp.StatusCode, string(createAdminBResp.Body))
	}
	var createdAdminB map[string]any
	_ = json.Unmarshal(createAdminBResp.Body, &createdAdminB)
	adminBID, _ := stringAt(createdAdminB, "id")

	t.Cleanup(func() {
		cleanupUser(adminBID, "Admin B")
	})

	adminBToken, err := loginUserForTest(publicClient, adminBEmail, adminBPassword)
	if err != nil {
		adminBToken, err = loginUserForTest(internalClient, adminBEmail, adminBPassword)
		if err != nil {
			t.Fatalf("failed to login as Admin B: %v", err)
		}
	}

	// Admin-A creates User-A1
	userA1Password := fmt.Sprintf("UserA1Pass-%d!9", runID)
	userA1Email := fmt.Sprintf("autotest-usera1-%d@example.com", runID)
	createUserA1Body, _ := json.Marshal(map[string]any{
		"email":           userA1Email,
		"name":            "AutoTest User A1",
		"currentPassword": userA1Password,
		"userRole":        "csr",
	})
	createUserA1Resp, err := publicClient.doWithHeaders("", http.MethodPost, "/api/v1/user/0", string(createUserA1Body), map[string]string{
		"Authorization": "Bearer " + adminAToken,
	})
	if err != nil {
		t.Fatalf("Admin A failed to create User A1: %v", err)
	}
	if createUserA1Resp.StatusCode != http.StatusOK && createUserA1Resp.StatusCode != http.StatusCreated {
		t.Fatalf("Admin A create User A1 expected 200/201, got %d: %s", createUserA1Resp.StatusCode, string(createUserA1Resp.Body))
	}
	var createdUserA1 map[string]any
	_ = json.Unmarshal(createUserA1Resp.Body, &createdUserA1)
	userA1ID, _ := stringAt(createdUserA1, "id")

	t.Cleanup(func() {
		cleanupUser(userA1ID, "User A1")
	})

	// Admin-B creates User-B1
	userB1Password := fmt.Sprintf("UserB1Pass-%d!9", runID)
	userB1Email := fmt.Sprintf("autotest-userb1-%d@example.com", runID)
	createUserB1Body, _ := json.Marshal(map[string]any{
		"email":           userB1Email,
		"name":            "AutoTest User B1",
		"currentPassword": userB1Password,
		"userRole":        "csr",
	})
	createUserB1Resp, err := publicClient.doWithHeaders("", http.MethodPost, "/api/v1/user/0", string(createUserB1Body), map[string]string{
		"Authorization": "Bearer " + adminBToken,
	})
	if err != nil {
		t.Fatalf("Admin B failed to create User B1: %v", err)
	}
	if createUserB1Resp.StatusCode != http.StatusOK && createUserB1Resp.StatusCode != http.StatusCreated {
		t.Fatalf("Admin B create User B1 expected 200/201, got %d: %s", createUserB1Resp.StatusCode, string(createUserB1Resp.Body))
	}
	var createdUserB1 map[string]any
	_ = json.Unmarshal(createUserB1Resp.Body, &createdUserB1)
	userB1ID, _ := stringAt(createdUserB1, "id")

	t.Cleanup(func() {
		cleanupUser(userB1ID, "User B1")
	})

	// 1. Internal port + service-key + ROOT token delegation -> 200 OK (sees all users)
	t.Run("Internal_ServiceKey_RootTokenDelegation_200", func(t *testing.T) {
		resp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       internalAPIKey,
			"Authorization":   "Bearer " + rootToken,
		})
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200, got %d. Body: %s", resp.StatusCode, string(resp.Body))
		}
		var parsed map[string]any
		if err := json.Unmarshal(resp.Body, &parsed); err != nil {
			t.Fatalf("failed to parse JSON response: %v", err)
		}
		if _, hasUsers := parsed["users"]; !hasUsers {
			t.Fatalf("response missing required 'users' array/field. Body: %s", string(resp.Body))
		}
	})

	// 2. Internal port + service-key without Authorization header -> 401/403 Denied
	t.Run("Internal_ServiceKey_MissingToken_Denied", func(t *testing.T) {
		resp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       internalAPIKey,
		})
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if !statusMatches("401|403", resp.StatusCode) {
			t.Fatalf("expected HTTP 401/403 for service-key call without token, got %d. Body: %s", resp.StatusCode, string(resp.Body))
		}
	})

	// 2b. Internal port + service-key + raw token without Bearer scheme -> 401/403 Denied
	t.Run("Internal_ServiceKey_TokenWithoutBearerScheme_Denied", func(t *testing.T) {
		resp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       internalAPIKey,
			"Authorization":   rootToken, // raw token without "Bearer " scheme prefix
		})
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if !statusMatches("401|403", resp.StatusCode) {
			t.Fatalf("expected HTTP 401/403 for Authorization header without Bearer scheme, got %d. Body: %s", resp.StatusCode, string(resp.Body))
		}
	})

	// 3. Internal port + service-key + invalid token -> 401/403 Denied
	t.Run("Internal_ServiceKey_InvalidToken_Denied", func(t *testing.T) {
		resp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       internalAPIKey,
			"Authorization":   "Bearer invalid-token-12345",
		})
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if !statusMatches("401|403", resp.StatusCode) {
			t.Fatalf("expected HTTP 401/403 for invalid token, got %d. Body: %s", resp.StatusCode, string(resp.Body))
		}
	})

	// 3b. Internal port + valid service name + invalid service key + valid ROOT token -> 401/403 Denied
	t.Run("Internal_InvalidServiceKey_ValidRootToken_Denied", func(t *testing.T) {
		resp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       "invalid-service-key-99999",
			"Authorization":   "Bearer " + rootToken,
		})
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if !statusMatches("401|403", resp.StatusCode) {
			t.Fatalf("expected HTTP 401/403 for invalid service key despite valid root token, got %d. Body: %s", resp.StatusCode, string(resp.Body))
		}
	})

	// 4. Internal port + service-key + expired ROOT token -> 401/403 Denied (EXPIRED_TOKEN)
	t.Run("Internal_ServiceKey_ExpiredToken_Denied", func(t *testing.T) {
		expiredToken, cleanup, err := createExpiredTokenInDB(t, rootID)
		if err != nil {
			t.Fatalf("failed to prepare expired token fixture in database: %v", err)
		}
		defer cleanup()

		resp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       internalAPIKey,
			"Authorization":   "Bearer " + expiredToken,
		})
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if !statusMatches("401|403", resp.StatusCode) {
			t.Fatalf("expected HTTP 401/403 for expired token, got %d. Body: %s", resp.StatusCode, string(resp.Body))
		}
	})

	// 5. Internal port + service-key + non-admin (CSR) token delegation -> 401/403 Access Denied
	t.Run("Internal_ServiceKey_NonAdminTokenDelegation_Denied", func(t *testing.T) {
		resp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       internalAPIKey,
			"Authorization":   "Bearer " + csrToken,
		})
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if !statusMatches("401|403", resp.StatusCode) {
			t.Fatalf("expected HTTP 401/403 for non-admin token delegated user, got %d. Body: %s", resp.StatusCode, string(resp.Body))
		}
	})

	// 6. Internal port + User Bearer token (no X-INTERNAL-NAME) -> 401/403 Access Denied (internal requires service key)
	t.Run("Internal_UserBearerToken_Denied", func(t *testing.T) {
		resp, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"Authorization": "Bearer " + rootToken,
		})
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if !statusMatches("401|403", resp.StatusCode) {
			t.Fatalf("expected HTTP 401/403 for user bearer token on internal router, got %d. Body: %s", resp.StatusCode, string(resp.Body))
		}
	})

	// 7. Internal port + missing auth headers -> denied (401 or 403)
	t.Run("Internal_MissingAuth_Denied", func(t *testing.T) {
		respNoAuth, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", nil)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if !statusMatches("401|403", respNoAuth.StatusCode) {
			t.Fatalf("expected HTTP 401/403 for missing auth, got %d. Body: %s", respNoAuth.StatusCode, string(respNoAuth.Body))
		}
	})

	// 8. Public port + valid ROOT bearer -> 200 (still works, proving no regression)
	t.Run("Public_ValidRootBearer_200", func(t *testing.T) {
		resp, err := publicClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"Authorization": "Bearer " + rootToken,
		})
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 on public endpoint, got %d. Body: %s", resp.StatusCode, string(resp.Body))
		}
		var parsed map[string]any
		if err := json.Unmarshal(resp.Body, &parsed); err != nil {
			t.Fatalf("failed to parse JSON response: %v", err)
		}
		if _, hasUsers := parsed["users"]; !hasUsers {
			t.Fatalf("response missing required 'users' array/field. Body: %s", string(resp.Body))
		}
	})

	// 9. Internal port + service-key + Admin token delegation -> 200 OK with Admin scoping (Admin-A sees User-A1, cannot see User-B1)
	t.Run("Internal_ServiceKey_AdminIsolation_Scoping", func(t *testing.T) {
		// Admin-A listing on internal port
		respA, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       internalAPIKey,
			"Authorization":   "Bearer " + adminAToken,
		})
		if err != nil {
			t.Fatalf("request with Admin-A token failed: %v", err)
		}
		if respA.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 for Admin-A, got %d. Body: %s", respA.StatusCode, string(respA.Body))
		}

		var parsedA map[string]any
		if err := json.Unmarshal(respA.Body, &parsedA); err != nil {
			t.Fatalf("failed to parse Admin-A JSON response: %v", err)
		}
		usersListA, ok := parsedA["users"].([]any)
		if !ok {
			t.Fatalf("Admin-A response missing 'users' array: %s", string(respA.Body))
		}

		foundA1InA := false
		foundB1InA := false
		for _, u := range usersListA {
			userMap, ok := u.(map[string]any)
			if !ok {
				continue
			}
			id, _ := userMap["id"].(string)
			if id == userA1ID {
				foundA1InA = true
			}
			if id == userB1ID {
				foundB1InA = true
			}
		}

		if !foundA1InA {
			t.Fatalf("Admin-A expected to see userA1 (%s) created by Admin-A, but was not in list", userA1ID)
		}
		if foundB1InA {
			t.Fatalf("Admin-A saw userB1 (%s) created by Admin-B — ADMIN isolation violated!", userB1ID)
		}

		// Admin-B listing on internal port
		respB, err := internalClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       internalAPIKey,
			"Authorization":   "Bearer " + adminBToken,
		})
		if err != nil {
			t.Fatalf("request with Admin-B token failed: %v", err)
		}
		if respB.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 for Admin-B, got %d. Body: %s", respB.StatusCode, string(respB.Body))
		}

		var parsedB map[string]any
		if err := json.Unmarshal(respB.Body, &parsedB); err != nil {
			t.Fatalf("failed to parse Admin-B JSON response: %v", err)
		}
		usersListB, ok := parsedB["users"].([]any)
		if !ok {
			t.Fatalf("Admin-B response missing 'users' array: %s", string(respB.Body))
		}

		foundB1InB := false
		foundA1InB := false
		for _, u := range usersListB {
			userMap, ok := u.(map[string]any)
			if !ok {
				continue
			}
			id, _ := userMap["id"].(string)
			if id == userB1ID {
				foundB1InB = true
			}
			if id == userA1ID {
				foundA1InB = true
			}
		}

		if !foundB1InB {
			t.Fatalf("Admin-B expected to see userB1 (%s) created by Admin-B, but was not in list", userB1ID)
		}
		if foundA1InB {
			t.Fatalf("Admin-B saw userA1 (%s) created by Admin-A — ADMIN isolation violated!", userA1ID)
		}
	})

	// 10. Public port + valid ADMIN bearer -> 200 with ADMIN scoping (proves no regression for admin on public port)
	t.Run("Public_ValidAdminBearer_200", func(t *testing.T) {
		resp, err := publicClient.doWithHeaders("", http.MethodGet, "/api/v1/users", "", map[string]string{
			"Authorization": "Bearer " + adminAToken,
		})
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 on public endpoint for Admin-A, got %d. Body: %s", resp.StatusCode, string(resp.Body))
		}
		var parsed map[string]any
		if err := json.Unmarshal(resp.Body, &parsed); err != nil {
			t.Fatalf("failed to parse JSON response: %v", err)
		}
		usersList, ok := parsed["users"].([]any)
		if !ok {
			t.Fatalf("response missing required 'users' array/field. Body: %s", string(resp.Body))
		}
		foundA1 := false
		foundB1 := false
		for _, u := range usersList {
			userMap, ok := u.(map[string]any)
			if !ok {
				continue
			}
			id, _ := userMap["id"].(string)
			if id == userA1ID {
				foundA1 = true
			}
			if id == userB1ID {
				foundB1 = true
			}
		}
		if !foundA1 {
			t.Fatalf("Public Admin-A expected to see userA1 (%s), but was not in list", userA1ID)
		}
		if foundB1 {
			t.Fatalf("Public Admin-A saw userB1 (%s) created by Admin-B — ADMIN isolation violated!", userB1ID)
		}
	})
}

