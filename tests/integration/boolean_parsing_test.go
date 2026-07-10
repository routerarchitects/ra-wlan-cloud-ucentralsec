package integration

import (
	"testing"
)

func TestBooleanQueryParsing(t *testing.T) {
	loadDotEnv(t)
	baseURL, tlsRootCA, rootEmail, rootPassword := getEnvConfig(t)

	runID, testPassword := generateRunParams()
	ctx := newTestContext(runID, testPassword, rootEmail, rootPassword)

	// Add our test user emails to context
	ctx.Emails["boolUser"] = "autotest-boolparse-" + runID + "@example.com"
	ctx.Emails["boolSubuser"] = "autotest-boolsubparse-" + runID + "@example.com"

	client := newClient(t, baseURL, tlsRootCA)

	// Authenticate root actor
	setupRootWithID(t, client, ctx, rootPassword)

	parsingTestCases := []IntegrationTestCase{
		// ------------------ USER ENDPOINTS ------------------

		// 1. Create User with email_verification=false (default when creating is true)
		{
			ID:             "TC_BOOL_USER_01",
			Name:           "Create User with email_verification=false",
			Actor:          "root",
			Method:         "POST",
			Path:           "/api/v1/user/0?email_verification=false",
			Body:           `{"email":"{emails.boolUser}","name":"Bool Parse User","currentPassword":"{testPassword}","userRole":"csr"}`,
			ExpectedStatus: "200",
			ExtractUserIDs: map[string]string{"boolUserID": "id"},
			Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
				waiting, _ := stringAt(resp.JSON, "waitingForEmailCheck")
				if waiting == "true" {
					t.Errorf("expected waitingForEmailCheck to be false, got true")
				}
				validated, _ := stringAt(resp.JSON, "validated")
				if validated != "true" {
					t.Errorf("expected validated to be true, got %s", validated)
				}
			},
			Description: "Verify email_verification=false during user creation doesn't require email verification.",
		},

		// 2. GET user byEmail (present & empty) -> should match email in path
		{
			ID:             "TC_BOOL_USER_02",
			Name:           "GET User byEmail (empty value)",
			Actor:          "root",
			Method:         "GET",
			Path:           "/api/v1/user/{emails.boolUser}?byEmail",
			ExpectedStatus: "200",
			Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
				email, _ := stringAt(resp.JSON, "email")
				if email != ctx.Emails["boolUser"] {
					t.Errorf("expected email %s, got %s", ctx.Emails["boolUser"], email)
				}
			},
			Description: "byEmail flag with empty value should evaluate to true.",
		},

		// 3. GET user byEmail=true
		{
			ID:             "TC_BOOL_USER_03",
			Name:           "GET User byEmail=true",
			Actor:          "root",
			Method:         "GET",
			Path:           "/api/v1/user/{emails.boolUser}?byEmail=true",
			ExpectedStatus: "200",
			Description:    "byEmail=true should evaluate to true.",
		},

		// 4. GET user byEmail=false -> should fail with 404 (tries to query "{emails.boolUser}" as UUID)
		{
			ID:             "TC_BOOL_USER_04",
			Name:           "GET User byEmail=false (404 expected)",
			Actor:          "root",
			Method:         "GET",
			Path:           "/api/v1/user/{emails.boolUser}?byEmail=false",
			ExpectedStatus: "404",
			Description:    "byEmail=false should evaluate to false and cause 404.",
		},

		// 5. GET user byEmail=invalid -> should fallback to false and 404
		{
			ID:             "TC_BOOL_USER_05",
			Name:           "GET User byEmail=invalid (404 expected)",
			Actor:          "root",
			Method:         "GET",
			Path:           "/api/v1/user/{emails.boolUser}?byEmail=invalid",
			ExpectedStatus: "404",
			Description:    "byEmail=invalid should fallback to false and cause 404.",
		},

		// 6. PUT user email_verification (present & empty) -> should trigger verification email
		{
			ID:             "TC_BOOL_USER_06",
			Name:           "PUT User email_verification (empty value)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/user/{boolUserID}?email_verification",
			Body:           `{"name":"Bool Parse User NameUpdate"}`,
			ExpectedStatus: "200",
			Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
				waiting, _ := stringAt(resp.JSON, "waitingForEmailCheck")
				if waiting != "true" {
					t.Errorf("expected email_verification to trigger waitingForEmailCheck=true")
				}
			},
			Description: "email_verification flag with empty value should trigger email verification.",
		},

		// 7. PUT user forgotPassword (present & empty) -> should bypass body check and return 200
		{
			ID:             "TC_BOOL_USER_07",
			Name:           "PUT User forgotPassword (empty value)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/user/{boolUserID}?forgotPassword",
			Body:           ``, // Empty body
			ExpectedStatus: "200",
			Description:    "forgotPassword flag with empty value should evaluate to true and bypass body validation.",
		},

		// 8. PUT user forgotPassword=true -> should bypass body check and return 200
		{
			ID:             "TC_BOOL_USER_08",
			Name:           "PUT User forgotPassword=true",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/user/{boolUserID}?forgotPassword=true",
			Body:           ``,
			ExpectedStatus: "200",
			Description:    "forgotPassword=true should bypass body validation.",
		},

		// 9. PUT user forgotPassword=false -> should fail with 400 (continues to parse empty body)
		{
			ID:             "TC_BOOL_USER_09",
			Name:           "PUT User forgotPassword=false (400 expected)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/user/{boolUserID}?forgotPassword=false",
			Body:           ``,
			ExpectedStatus: "400",
			Description:    "forgotPassword=false should evaluate to false and fail on body parsing.",
		},

		// 10. PUT user forgotPassword=invalid -> should fallback to false and fail with 400
		{
			ID:             "TC_BOOL_USER_10",
			Name:           "PUT User forgotPassword=invalid (400 expected)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/user/{boolUserID}?forgotPassword=invalid",
			Body:           ``,
			ExpectedStatus: "400",
			Description:    "forgotPassword=invalid should fallback to false and fail on body parsing.",
		},

		// 11. PUT user resetMFA (present & empty) -> should bypass body check and return 200
		{
			ID:             "TC_BOOL_USER_11",
			Name:           "PUT User resetMFA (empty value)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/user/{boolUserID}?resetMFA",
			Body:           ``,
			ExpectedStatus: "200",
			Description:    "resetMFA flag with empty value should evaluate to true and bypass body validation.",
		},

		// 12. PUT user resetMFA=true -> should bypass body check and return 200
		{
			ID:             "TC_BOOL_USER_12",
			Name:           "PUT User resetMFA=true",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/user/{boolUserID}?resetMFA=true",
			Body:           ``,
			ExpectedStatus: "200",
			Description:    "resetMFA=true should bypass body validation.",
		},

		// 13. PUT user resetMFA=false -> should fail with 400 (continues to parse empty body)
		{
			ID:             "TC_BOOL_USER_13",
			Name:           "PUT User resetMFA=false (400 expected)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/user/{boolUserID}?resetMFA=false",
			Body:           ``,
			ExpectedStatus: "400",
			Description:    "resetMFA=false should evaluate to false and fail on body parsing.",
		},

		// 14. PUT user resetMFA=invalid -> should fallback to false and fail with 400
		{
			ID:             "TC_BOOL_USER_14",
			Name:           "PUT User resetMFA=invalid (400 expected)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/user/{boolUserID}?resetMFA=invalid",
			Body:           ``,
			ExpectedStatus: "400",
			Description:    "resetMFA=invalid should fallback to false and fail on body parsing.",
		},


		// ------------------ SUBUSER ENDPOINTS ------------------

		// 15. Create Subuser with email_verification=false
		{
			ID:             "TC_BOOL_SUB_01",
			Name:           "Create Subuser with email_verification=false",
			Actor:          "root",
			Method:         "POST",
			Path:           "/api/v1/subuser/0?email_verification=false",
			Body:           `{"email":"{emails.boolSubuser}","name":"Bool Parse Subuser","currentPassword":"{testPassword}","userRole":"subscriber"}`,
			ExpectedStatus: "200",
			ExtractUserIDs: map[string]string{"boolSubuserID": "id"},
			Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
				waiting, _ := stringAt(resp.JSON, "waitingForEmailCheck")
				if waiting == "true" {
					t.Errorf("expected waitingForEmailCheck to be false, got true")
				}
				validated, _ := stringAt(resp.JSON, "validated")
				if validated != "true" {
					t.Errorf("expected validated to be true, got %s", validated)
				}
			},
			Description: "Verify email_verification=false during subuser creation doesn't require verification.",
		},

		// 16. GET subuser byEmail (present & empty)
		{
			ID:             "TC_BOOL_SUB_02",
			Name:           "GET Subuser byEmail (empty value)",
			Actor:          "root",
			Method:         "GET",
			Path:           "/api/v1/subuser/{emails.boolSubuser}?byEmail",
			ExpectedStatus: "200",
			Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
				email, _ := stringAt(resp.JSON, "email")
				if email != ctx.Emails["boolSubuser"] {
					t.Errorf("expected email %s, got %s", ctx.Emails["boolSubuser"], email)
				}
			},
			Description: "byEmail flag with empty value should evaluate to true on subuser.",
		},

		// 17. GET subuser byEmail=true
		{
			ID:             "TC_BOOL_SUB_03",
			Name:           "GET Subuser byEmail=true",
			Actor:          "root",
			Method:         "GET",
			Path:           "/api/v1/subuser/{emails.boolSubuser}?byEmail=true",
			ExpectedStatus: "200",
			Description:    "byEmail=true should evaluate to true on subuser.",
		},

		// 18. GET subuser byEmail=false -> 404
		{
			ID:             "TC_BOOL_SUB_04",
			Name:           "GET Subuser byEmail=false (404 expected)",
			Actor:          "root",
			Method:         "GET",
			Path:           "/api/v1/subuser/{emails.boolSubuser}?byEmail=false",
			ExpectedStatus: "404",
			Description:    "byEmail=false should evaluate to false on subuser.",
		},

		// 19. GET subuser byEmail=invalid -> 404
		{
			ID:             "TC_BOOL_SUB_05",
			Name:           "GET Subuser byEmail=invalid (404 expected)",
			Actor:          "root",
			Method:         "GET",
			Path:           "/api/v1/subuser/{emails.boolSubuser}?byEmail=invalid",
			ExpectedStatus: "404",
			Description:    "byEmail=invalid should fallback to false on subuser.",
		},

		// 20. PUT subuser email_verification (present & empty) -> should trigger verification email
		{
			ID:             "TC_BOOL_SUB_06",
			Name:           "PUT Subuser email_verification (empty value)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/subuser/{boolSubuserID}?email_verification",
			Body:           `{"name":"Bool Parse Subuser NameUpdate"}`,
			ExpectedStatus: "200",
			Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
				waiting, _ := stringAt(resp.JSON, "waitingForEmailCheck")
				if waiting != "true" {
					t.Errorf("expected email_verification to trigger waitingForEmailCheck=true on subuser")
				}
			},
			Description: "email_verification flag with empty value should trigger email verification on subuser.",
		},

		// 21. PUT subuser forgotPassword (present & empty) -> 200
		{
			ID:             "TC_BOOL_SUB_07",
			Name:           "PUT Subuser forgotPassword (empty value)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/subuser/{boolSubuserID}?forgotPassword",
			Body:           ``,
			ExpectedStatus: "200",
			Description:    "forgotPassword flag with empty value should evaluate to true on subuser.",
		},

		// 22. PUT subuser forgotPassword=true -> 200
		{
			ID:             "TC_BOOL_SUB_08",
			Name:           "PUT Subuser forgotPassword=true",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/subuser/{boolSubuserID}?forgotPassword=true",
			Body:           ``,
			ExpectedStatus: "200",
			Description:    "forgotPassword=true should bypass body validation on subuser.",
		},

		// 23. PUT subuser forgotPassword=false -> 400
		{
			ID:             "TC_BOOL_SUB_09",
			Name:           "PUT Subuser forgotPassword=false (400 expected)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/subuser/{boolSubuserID}?forgotPassword=false",
			Body:           ``,
			ExpectedStatus: "400",
			Description:    "forgotPassword=false should evaluate to false on subuser.",
		},

		// 24. PUT subuser forgotPassword=invalid -> 400
		{
			ID:             "TC_BOOL_SUB_10",
			Name:           "PUT Subuser forgotPassword=invalid (400 expected)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/subuser/{boolSubuserID}?forgotPassword=invalid",
			Body:           ``,
			ExpectedStatus: "400",
			Description:    "forgotPassword=invalid should fallback to false on subuser.",
		},

		// 25. PUT subuser resetPassword (present & empty) -> 200
		{
			ID:             "TC_BOOL_SUB_11",
			Name:           "PUT Subuser resetPassword (empty value)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/subuser/{boolSubuserID}?resetPassword",
			Body:           ``,
			ExpectedStatus: "200",
			Description:    "resetPassword flag with empty value should evaluate to true on subuser.",
		},

		// 26. PUT subuser resetPassword=true -> 200
		{
			ID:             "TC_BOOL_SUB_12",
			Name:           "PUT Subuser resetPassword=true",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/subuser/{boolSubuserID}?resetPassword=true",
			Body:           ``,
			ExpectedStatus: "200",
			Description:    "resetPassword=true should bypass body validation on subuser.",
		},

		// 27. PUT subuser resetPassword=false -> 400
		{
			ID:             "TC_BOOL_SUB_13",
			Name:           "PUT Subuser resetPassword=false (400 expected)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/subuser/{boolSubuserID}?resetPassword=false",
			Body:           ``,
			ExpectedStatus: "400",
			Description:    "resetPassword=false should evaluate to false on subuser.",
		},

		// 28. PUT subuser resetMFA (present & empty) -> 200
		{
			ID:             "TC_BOOL_SUB_14",
			Name:           "PUT Subuser resetMFA (empty value)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/subuser/{boolSubuserID}?resetMFA",
			Body:           ``,
			ExpectedStatus: "200",
			Description:    "resetMFA flag with empty value should evaluate to true on subuser.",
		},

		// 29. PUT subuser resetMFA=true -> 200
		{
			ID:             "TC_BOOL_SUB_15",
			Name:           "PUT Subuser resetMFA=true",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/subuser/{boolSubuserID}?resetMFA=true",
			Body:           ``,
			ExpectedStatus: "200",
			Description:    "resetMFA=true should bypass body validation on subuser.",
		},

		// 30. PUT subuser resetMFA=false -> 400
		{
			ID:             "TC_BOOL_SUB_16",
			Name:           "PUT Subuser resetMFA=false (400 expected)",
			Actor:          "root",
			Method:         "PUT",
			Path:           "/api/v1/subuser/{boolSubuserID}?resetMFA=false",
			Body:           ``,
			ExpectedStatus: "400",
			Description:    "resetMFA=false should evaluate to false on subuser.",
		},
	}

	t.Run("Boolean Query Parsing Semantics", func(t *testing.T) {
		runTestCases(t, client, ctx, parsingTestCases)
	})
}
