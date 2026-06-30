package integration

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestAdminRootAccess(t *testing.T) {
	loadDotEnv(t)
	baseURL, tlsRootCA, rootEmail, rootPassword := getEnvConfig(t)

	// Clean up all users except root once at the very start of the test suite

	t.Run("Root", func(t *testing.T) {
		runID, testPassword := generateRunParams()
		ctx := newTestContext(runID, testPassword, rootEmail, rootPassword)
		client := newClient(t, baseURL, tlsRootCA)

		runTestCases(t, client, ctx, rootTestCases)
	})

	t.Run("Admin", func(t *testing.T) {
		time.Sleep(100 * time.Millisecond)
		runID, testPassword := generateRunParams()
		ctx := newTestContext(runID, testPassword, rootEmail, rootPassword)
		client := newClient(t, baseURL, tlsRootCA)

		setupAdmins(t, client, ctx, rootPassword)

		runTestCases(t, client, ctx, adminTestCases)
	})

	t.Run("CSR", func(t *testing.T) {
		time.Sleep(100 * time.Millisecond)
		runID, testPassword := generateRunParams()
		ctx := newTestContext(runID, testPassword, rootEmail, rootPassword)
		client := newClient(t, baseURL, tlsRootCA)

		setupCsr(t, client, ctx, rootPassword)

		runTestCases(t, client, ctx, csrTestCases)
	})
}

func runTestCases(t *testing.T, client *apiClient, ctx *TestContext, testCases []IntegrationTestCase) {
	results := make([]testResultRow, 0, len(testCases))

	for idx, tc := range testCases {
		tc := tc
		row := testResultRow{
			SNo:            len(globalTestResults) + idx + 1,
			ID:             tc.ID,
			Name:           tc.Name,
			Actor:          tc.Actor,
			Method:         tc.Method,
			ExpectedStatus: tc.ExpectedStatus,
			Description:    tc.Description,
		}

		t.Run(tc.ID+"_"+tc.Name, func(t *testing.T) {
			path := interpolate(tc.Path, ctx, true)
			row.Path = path

			var targetUserID string
			if strings.HasPrefix(path, "/api/v1/user/") {
				parts := strings.Split(strings.TrimPrefix(path, "/api/v1/user/"), "?")
				targetUserID = parts[0]
			}
			if targetUserID == "0" {
				targetUserID = ""
			}

			var resp *apiResponse
			var err error

			if tc.IsLogin {
				bodyStr := interpolate(tc.Body, ctx, false)
				var loginBody struct {
					UserID   string `json:"userId"`
					Password string `json:"password"`
				}
				if errJson := json.Unmarshal([]byte(bodyStr), &loginBody); errJson != nil {
					t.Fatalf("invalid login body json: %v", errJson)
				}
				resp, err = client.login(tc.Actor, loginBody.UserID, loginBody.Password)
			} else {
				var bodyStr string
				if tc.Body != "" {
					bodyStr = interpolate(tc.Body, ctx, false)
				}
				resp, err = client.do(tc.Actor, tc.Method, path, bodyStr)
			}

			if err != nil {
				row.Result = fmt.Sprintf("FAIL: %v", err)
				t.Fatalf("API request failed: %v", err)
			}

			row.ActualStatus = resp.StatusCode

			if !statusMatches(tc.ExpectedStatus, resp.StatusCode) {
				row.Result = fmt.Sprintf("FAIL: expected %s, got %d. Body: %s", tc.ExpectedStatus, resp.StatusCode, string(resp.Body))
				t.Fatalf("HTTP Status check failed. Expected %s, got %d. Body: %s", tc.ExpectedStatus, resp.StatusCode, string(resp.Body))
			}

			if resp != nil && resp.JSON != nil {
				if tc.IsLogin {
					if token, ok := stringAt(resp.JSON, "access_token"); ok && token != "" {
						ctx.Tokens[tc.Actor] = token
					}
				}
				for key, pathStr := range tc.ExtractUserIDs {
					if val, ok := stringAt(resp.JSON, pathStr); ok && val != "" {
						ctx.UserIDs[key] = val
					}
				}
				for key, pathStr := range tc.ExtractOwners {
					if val, ok := stringAt(resp.JSON, pathStr); ok && val != "" {
						ctx.Owners[key] = val
					}
				}
				if id, ok := stringAt(resp.JSON, "id"); ok && id != "" {
					targetUserID = id
				}
			}

			if tc.Assert != nil {
				tc.Assert(t, resp, ctx)
			}

			row.TargetUserID = targetUserID
			row.Result = "PASS"
		})

		results = append(results, row)
	}

	globalTestResults = append(globalTestResults, results...)
}

func interpolate(s string, ctx *TestContext, escape bool) string {
	for k, v := range ctx.UserIDs {
		val := v
		if escape {
			val = url.PathEscape(v)
		}
		s = strings.ReplaceAll(s, "{"+k+"}", val)
	}
	for k, v := range ctx.Emails {
		val := v
		if escape {
			val = url.QueryEscape(v)
		}
		s = strings.ReplaceAll(s, "{emails."+k+"}", val)
	}
	s = strings.ReplaceAll(s, "{runID}", ctx.RunID)
	s = strings.ReplaceAll(s, "{testPassword}", ctx.TestPassword)
	s = strings.ReplaceAll(s, "{rootPassword}", ctx.RootPassword)
	return s
}

func TestMain(m *testing.M) {
	RunDbCleanup()
	code := m.Run()
	if len(globalTestResults) > 0 {
		printConsoleTable(globalTestResults)
	}
	os.Exit(code)
}
