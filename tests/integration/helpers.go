package integration

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type TestContext struct {
	RunID        string
	TestPassword string
	RootPassword string
	Tokens       map[string]string
	UserIDs      map[string]string
	Emails       map[string]string
	Owners       map[string]string
}

type IntegrationTestCase struct {
	ID             string
	Name           string
	Actor          string
	Method         string
	IsLogin        bool
	Path           string
	Body           string
	ExpectedStatus string
	ExtractUserIDs map[string]string
	ExtractOwners  map[string]string
	Assert         func(t *testing.T, resp *apiResponse, ctx *TestContext)
	Description    string
}

type testResultRow struct {
	SNo            int
	ID             string
	TargetUserID   string
	Method         string
	Path           string
	Actor          string
	Name           string
	ExpectedStatus string
	ActualStatus   int
	Result         string
	Description    string
}

var globalTestResults []testResultRow

func setupRoot(t *testing.T, client *apiClient, ctx *TestContext, rootPassword string) {
	resp, err := client.login("root", ctx.Emails["root"], rootPassword)
	if err != nil {
		t.Fatalf("setup root login failed: %v", err)
	}
	token, _ := stringAt(resp.JSON, "access_token")
	ctx.Tokens["root"] = token
}

func setupRootWithID(t *testing.T, client *apiClient, ctx *TestContext, rootPassword string) {
	setupRoot(t, client, ctx, rootPassword)
	resp, err := client.do("root", "GET", "/api/v1/oauth2?me=true", "")
	if err != nil {
		t.Fatalf("setup root profile failed: %v", err)
	}
	ctx.UserIDs["rootID"], _ = stringAt(resp.JSON, "id")
	ctx.Owners["rootOwner"], _ = stringAt(resp.JSON, "owner")
}

func setupAdmins(t *testing.T, client *apiClient, ctx *TestContext, rootPassword string) {
	setupRootWithID(t, client, ctx, rootPassword)

	// Create Admin A
	bodyAdminA := fmt.Sprintf(`{"email":"%s","name":"TC_ADMIN_02: Admin A Setup","currentPassword":"%s","userRole":"admin"}`,
		ctx.Emails["adminA"], ctx.TestPassword)
	respA, err := client.do("root", "POST", "/api/v1/user/0?entity=autotest-admin-a", bodyAdminA)
	if err != nil {
		t.Fatalf("setup Admin A failed: %v", err)
	}
	if respA.StatusCode != 200 {
		t.Fatalf("setup Admin A status got %d: %s", respA.StatusCode, string(respA.Body))
	}
	ctx.UserIDs["adminAID"], _ = stringAt(respA.JSON, "id")
	ctx.Owners["adminAOwner"], _ = stringAt(respA.JSON, "owner")

	// Create Admin B
	bodyAdminB := fmt.Sprintf(`{"email":"%s","name":"TC_ADMIN_01: Admin B Setup","currentPassword":"%s","userRole":"admin"}`,
		ctx.Emails["adminB"], ctx.TestPassword)
	respB, err := client.do("root", "POST", "/api/v1/user/0?entity=autotest-admin-b", bodyAdminB)
	if err != nil {
		t.Fatalf("setup Admin B failed: %v", err)
	}
	if respB.StatusCode != 200 {
		t.Fatalf("setup Admin B status got %d: %s", respB.StatusCode, string(respB.Body))
	}
	ctx.UserIDs["adminBID"], _ = stringAt(respB.JSON, "id")
	ctx.Owners["adminBOwner"], _ = stringAt(respB.JSON, "owner")

	// Log in Admin A & Admin B
	respLoginA, err := client.login("adminA", ctx.Emails["adminA"], ctx.TestPassword)
	if err != nil {
		t.Fatalf("setup login Admin A failed: %v", err)
	}
	ctx.Tokens["adminA"], _ = stringAt(respLoginA.JSON, "access_token")

	respLoginB, err := client.login("adminB", ctx.Emails["adminB"], ctx.TestPassword)
	if err != nil {
		t.Fatalf("setup login Admin B failed: %v", err)
	}
	ctx.Tokens["adminB"], _ = stringAt(respLoginB.JSON, "access_token")
}

func setupCsr(t *testing.T, client *apiClient, ctx *TestContext, rootPassword string) {
	setupAdmins(t, client, ctx, rootPassword)

	// Create CSR A (under Admin A)
	bodyCsrA := fmt.Sprintf(`{"email":"%s","name":"TC_CSR_01: CSR A Setup","currentPassword":"%s","userRole":"csr"}`,
		ctx.Emails["csrA"], ctx.TestPassword)
	respCsrA, err := client.do("adminA", "POST", "/api/v1/user/0", bodyCsrA)
	if err != nil {
		t.Fatalf("setup CSR A failed: %v", err)
	}
	if respCsrA.StatusCode != 200 {
		t.Fatalf("setup CSR A status got %d: %s", respCsrA.StatusCode, string(respCsrA.Body))
	}
	ctx.UserIDs["csrAID"], _ = stringAt(respCsrA.JSON, "id")
	ctx.Owners["csrAOwner"], _ = stringAt(respCsrA.JSON, "owner")

	// Log in CSR A
	respLoginCsrA, err := client.login("csrA", ctx.Emails["csrA"], ctx.TestPassword)
	if err != nil {
		t.Fatalf("setup login CSR A failed: %v", err)
	}
	ctx.Tokens["csrA"], _ = stringAt(respLoginCsrA.JSON, "access_token")
}

func getEnvConfig(t *testing.T) (string, string, string, string) {
	baseURL := requireEnvOrSkip(t, "OWSEC_BASE_URL")
	tlsRootCA := os.Getenv("OW_RBAC_TLS_ROOT_CA")
	rootEmail := requireEnvOrSkip(t, "OWSEC_ROOT_EMAIL")
	rootPassword := requireEnvOrSkip(t, "OWSEC_ROOT_PASSWORD")
	return baseURL, tlsRootCA, rootEmail, rootPassword
}

func generateRunParams() (string, string) {
	runID := fmt.Sprintf("%d", time.Now().UnixNano())
	testPassword := fmt.Sprintf("TestUser-%s!9", runID)
	return runID, testPassword
}

func newTestContext(runID, testPassword, rootEmail, rootPassword string) *TestContext {
	return &TestContext{
		RunID:        runID,
		TestPassword: testPassword,
		RootPassword: rootPassword,
		Tokens:       make(map[string]string),
		UserIDs:      make(map[string]string),
		Emails: map[string]string{
			"root":             rootEmail,
			"adminA":           "autotest-admin-a-" + runID + "@example.com",
			"adminB":           "autotest-admin-b-" + runID + "@example.com",
			"csrA":             "autotest-csr-a-" + runID + "@example.com",
			"csrB":             "autotest-csr-b-" + runID + "@example.com",
			"deleteA":          "autotest-delete-a-" + runID + "@example.com",
			"rootDelete":       "autotest-root-delete-" + runID + "@example.com",
			"rootSecondary":    "autotest-root-sec-" + runID + "@example.com",
			"rootRoleChange":   "autotest-root-role-change-" + runID + "@example.com",
			"csrCreateAttempt": "autotest-csr-create-denied-" + runID + "@example.com",
			"updatedPassword":  "UpdatedUser-" + runID + "!9",
		},
		Owners: make(map[string]string),
	}
}

func newClient(t *testing.T, baseURL, tlsRootCA string) *apiClient {
	httpClient, err := NewHTTPClient(tlsRootCA)
	if err != nil {
		t.Fatalf("failed to create HTTP client: %v", err)
	}
	return newAPIClient(baseURL, httpClient)
}

func printConsoleTable(rows []testResultRow) {
	separator := "+-------+------------------------+----------+----------------------------------------------------------------------------------+----------+--------------------------------------------------------------+------------+----------+----------+"
	fmt.Println("\n" + separator)
	fmt.Printf("| %-5s | %-22s | %-8s | %-80s | %-8s | %-60s | %-10s | %-8s | %-8s |\n",
		"S.NO.", "ID", "METHOD", "PATH", "ACTOR", "TEST CASE NAME", "EXPECTED", "ACTUAL", "RESULT")
	fmt.Println(separator)
	var failures []testResultRow
	for _, r := range rows {
		res := "PASS"
		if strings.HasPrefix(r.Result, "FAIL") {
			res = "FAIL"
			failures = append(failures, r)
		}
		pathStr := r.Path
		if len(pathStr) > 80 {
			pathStr = pathStr[:77] + "..."
		}
		nameStr := r.Name
		if len(nameStr) > 60 {
			nameStr = nameStr[:57] + "..."
		}
		fmt.Printf("| %-5d | %-22s | %-8s | %-80s | %-8s | %-60s | %-10s | %-8d | %-8s |\n",
			r.SNo, r.ID, r.Method, pathStr, r.Actor, nameStr, r.ExpectedStatus, r.ActualStatus, res)
	}
	fmt.Println(separator)
	if len(failures) > 0 {
		fmt.Println("\nDetailed Test Failures:")
		for _, f := range failures {
			fmt.Printf("[%s] %s (Actor: %s, %s %s)\n", f.ID, f.Name, f.Actor, f.Method, f.Path)
			fmt.Printf("  -> %s\n\n", f.Result)
		}
	}
}
