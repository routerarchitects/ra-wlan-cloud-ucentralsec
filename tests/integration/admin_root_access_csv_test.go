package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
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

func verifyInternalUserRoutes(httpClient *http.Client, internalBaseURL, rootID string) error {
	if strings.TrimSpace(rootID) == "" {
		return fmt.Errorf("rootID is required for internal route verification")
	}

	internalName := strings.TrimSpace(os.Getenv("OWSEC_INTERNAL_NAME"))
	internalAPIKey := strings.TrimSpace(os.Getenv("OWSEC_INTERNAL_API_KEY"))
	if internalName == "" || internalAPIKey == "" {
		return nil
	}

	internalClient := newAPIClient(internalBaseURL, httpClient)
	checks := []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/api/v1/user/" + url.PathEscape(rootID)},
		{method: http.MethodGet, path: "/api/v1/users"},
	}

	for _, check := range checks {
		resp, err := internalClient.doWithHeaders("", check.method, check.path, "", map[string]string{
			"X-INTERNAL-NAME": internalName,
			"X-API-KEY":       internalAPIKey,
		})
		if err != nil {
			return fmt.Errorf("internal request %s %s failed: %w", check.method, check.path, err)
		}
		if !statusMatches("404", resp.StatusCode) {
			return fmt.Errorf("internal request %s %s expected 404, got %d. Body: %s",
				check.method, check.path, resp.StatusCode, string(resp.Body))
		}
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
