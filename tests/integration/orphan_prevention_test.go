package integration

import (
	"testing"
)

func TestWorkflowOrphanPrevention(t *testing.T) {
	loadDotEnv(t)
	baseURL, tlsRootCA, rootEmail, rootPassword := getEnvConfig(t)

	client := newClient(t, baseURL, tlsRootCA)

	runID, testPassword := generateRunParams()
	ctx := newTestContext(runID, testPassword, rootEmail, rootPassword)

	// Populate custom emails for Admin X, Admin Y, and CSR C
	ctx.Emails["adminX"] = "autotest-admin-x-" + runID + "@example.com"
	ctx.Emails["adminY"] = "autotest-admin-y-" + runID + "@example.com"
	ctx.Emails["csrC"] = "autotest-csr-c-" + runID + "@example.com"

	setupRootWithID(t, client, ctx, rootPassword)

	var orphanTestCases = []IntegrationTestCase{
		{
			ID:             "TC_WF_ORPHAN_01",
			Name:           "Root Creates Admin X",
			Actor:          "root",
			Method:         "POST",
			Path:           "/api/v1/user/0?entity=autotest-admin-x",
			Body:           `{"email":"{emails.adminX}","name":"TC_WF_ORPHAN_01: Admin X","currentPassword":"{testPassword}","userRole":"admin"}`,
			ExpectedStatus: "200",
			ExtractUserIDs: map[string]string{"adminXID": "id"},
		},
		{
			ID:             "TC_WF_ORPHAN_02",
			Name:           "Admin X Login",
			Actor:          "adminX",
			Method:         "POST",
			IsLogin:        true,
			Path:           "/api/v1/oauth2",
			Body:           `{"userId":"{emails.adminX}","password":"{testPassword}"}`,
			ExpectedStatus: "200",
		},
		{
			ID:             "TC_WF_ORPHAN_03",
			Name:           "Admin X Creates Admin Y",
			Actor:          "adminX",
			Method:         "POST",
			Path:           "/api/v1/user/0",
			Body:           `{"email":"{emails.adminY}","name":"TC_WF_ORPHAN_03: Admin Y","currentPassword":"{testPassword}","userRole":"admin"}`,
			ExpectedStatus: "200",
			ExtractUserIDs: map[string]string{"adminYID": "id"},
		},
		{
			ID:             "TC_WF_ORPHAN_04",
			Name:           "Admin Y Login",
			Actor:          "adminY",
			Method:         "POST",
			IsLogin:        true,
			Path:           "/api/v1/oauth2",
			Body:           `{"userId":"{emails.adminY}","password":"{testPassword}"}`,
			ExpectedStatus: "200",
		},
		{
			ID:             "TC_WF_ORPHAN_05",
			Name:           "Admin Y Creates CSR C",
			Actor:          "adminY",
			Method:         "POST",
			Path:           "/api/v1/user/0",
			Body:           `{"email":"{emails.csrC}","name":"TC_WF_ORPHAN_05: CSR C","currentPassword":"{testPassword}","userRole":"csr"}`,
			ExpectedStatus: "200",
			ExtractUserIDs: map[string]string{"csrCID": "id"},
		},
		{
			ID:             "TC_WF_ORPHAN_06",
			Name:           "Admin X Deletes Admin Y (Fails due to CSR C)",
			Actor:          "adminX",
			Method:         "DELETE",
			Path:           "/api/v1/user/{adminYID}",
			ExpectedStatus: "400",
			Description:    "Admin X tries to delete Admin Y. Fails because Admin Y has CSR C.",
		},
		{
			ID:             "TC_WF_ORPHAN_07",
			Name:           "Admin Y Deletes CSR C",
			Actor:          "adminY",
			Method:         "DELETE",
			Path:           "/api/v1/user/{csrCID}",
			ExpectedStatus: "200|204",
			Description:    "Admin Y deletes CSR C to remove dependency.",
		},
		{
			ID:             "TC_WF_ORPHAN_08",
			Name:           "Admin X Deletes Admin Y (Succeeds)",
			Actor:          "adminX",
			Method:         "DELETE",
			Path:           "/api/v1/user/{adminYID}",
			ExpectedStatus: "200|204",
			Description:    "Admin X deletes Admin Y after CSR C is deleted.",
		},
	}

	runTestCases(t, client, ctx, orphanTestCases)
}
