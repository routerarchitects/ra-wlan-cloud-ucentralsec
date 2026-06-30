package integration

import (
	"testing"
)

var rootTestCases = []IntegrationTestCase{
	{
		ID:             "TC_ROOT_01",
		Name:           "Root Login",
		Actor:          "root",
		Method:         "POST",
		IsLogin:        true,
		Path:           "/api/v1/oauth2",
		Body:           `{"userId":"{emails.root}","password":"{rootPassword}"}`,
		ExpectedStatus: "200",
		Description:    "Only root is expected to exist before the test starts.",
	},
	{
		ID:             "TC_ROOT_02",
		Name:           "Root Profile",
		Actor:          "root",
		Method:         "GET",
		Path:           "/api/v1/oauth2?me=true",
		ExpectedStatus: "200",
		ExtractUserIDs: map[string]string{"rootID": "id"},
		ExtractOwners:  map[string]string{"rootOwner": "owner"},
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			if email, _ := stringAt(resp.JSON, "email"); email != ctx.Emails["root"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["root"], email)
			}
		},
		Description:    "Read root profile for later ACL checks.",
	},
	{
		ID:             "TC_ROOT_03",
		Name:           "Root Cannot Delete Self",
		Actor:          "root",
		Method:         "DELETE",
		Path:           "/api/v1/user/{rootID}",
		ExpectedStatus: "401|403",
		Description:    "ROOT must never be able to delete itself.",
	},
	{
		ID:             "TC_ROOT_04",
		Name:           "Root Creates CSR (for Deletion)",
		Actor:          "root",
		Method:         "POST",
		Path:           "/api/v1/user/0?entity=autotest-admin-a",
		Body:           `{"email":"{emails.rootDelete}","name":"TC_ROOT_04: Root Delete Me","currentPassword":"{testPassword}","userRole":"csr"}`,
		ExpectedStatus: "200",
		ExtractUserIDs: map[string]string{"rootDeleteUserID": "id"},
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			if email, _ := stringAt(resp.JSON, "email"); email != ctx.Emails["rootDelete"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["rootDelete"], email)
			}
		},
		Description:    "Root creates a CSR user that root can delete to verify delete-other is still allowed.",
	},
	{
		ID:             "TC_ROOT_05",
		Name:           "Root Deletes CSR",
		Actor:          "root",
		Method:         "DELETE",
		Path:           "/api/v1/user/{rootDeleteUserID}",
		ExpectedStatus: "200|204",
		Description:    "ROOT can delete another user.",
	},
	{
		ID:             "TC_ROOT_06",
		Name:           "Root Creates Admin A",
		Actor:          "root",
		Method:         "POST",
		Path:           "/api/v1/user/0?entity=autotest-admin-a",
		Body:           `{"email":"{emails.adminA}","name":"TC_ROOT_06: Admin A","currentPassword":"{testPassword}","userRole":"admin","createdBy":"client-must-not-control-this","owner":"client-owner-must-not-win"}`,
		ExpectedStatus: "200",
		ExtractUserIDs: map[string]string{"adminAID": "id"},
		ExtractOwners:  map[string]string{"adminAOwner": "owner"},
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			if email, _ := stringAt(resp.JSON, "email"); email != ctx.Emails["adminA"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["adminA"], email)
			}
			if role, _ := stringAt(resp.JSON, "userRole"); role != "admin" {
				t.Errorf("expected role admin, got %s", role)
			}
			if owner, _ := stringAt(resp.JSON, "owner"); owner != "autotest-admin-a" {
				t.Errorf("expected owner autotest-admin-a, got %s", owner)
			}
		},
		Description:    "Root creates the first admin. owner should come from entity query param.",
	},
	{
		ID:             "TC_ROOT_07",
		Name:           "Root Creates Root",
		Actor:          "root",
		Method:         "POST",
		Path:           "/api/v1/user/0?entity=autotest-admin-a",
		Body:           `{"email":"{emails.rootSecondary}","name":"TC_ROOT_07: Root Secondary","currentPassword":"{testPassword}","userRole":"root"}`,
		ExpectedStatus: "200",
		ExtractUserIDs: map[string]string{"rootSecondaryID": "id"},
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			if email, _ := stringAt(resp.JSON, "email"); email != ctx.Emails["rootSecondary"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["rootSecondary"], email)
			}
			if role, _ := stringAt(resp.JSON, "userRole"); role != "root" {
				t.Errorf("expected role root, got %s", role)
			}
		},
		Description:    "Root can create another root user.",
	},
	{
		ID:             "TC_ROOT_08",
		Name:           "Root Deletes Secondary Root",
		Actor:          "root",
		Method:         "DELETE",
		Path:           "/api/v1/user/{rootSecondaryID}",
		ExpectedStatus: "200|204",
		Description:    "Root can delete another root user.",
	},
	{
		ID:             "TC_ROOT_09",
		Name:           "Root Cannot Demote Self",
		Actor:          "root",
		Method:         "PUT",
		Path:           "/api/v1/user/{rootID}",
		Body:           `{"userRole":"admin"}`,
		ExpectedStatus: "401|403",
		Description:    "ROOT must not be able to change its own role away from ROOT.",
	},
	{
		ID:             "TC_ROOT_10",
		Name:           "Root Creates Admin B",
		Actor:          "root",
		Method:         "POST",
		Path:           "/api/v1/user/0?entity=autotest-admin-b",
		Body:           `{"email":"{emails.adminB}","name":"TC_ROOT_10: Admin B","currentPassword":"{testPassword}","userRole":"admin"}`,
		ExpectedStatus: "200",
		ExtractUserIDs: map[string]string{"adminBID": "id"},
		ExtractOwners:  map[string]string{"adminBOwner": "owner"},
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			if email, _ := stringAt(resp.JSON, "email"); email != ctx.Emails["adminB"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["adminB"], email)
			}
			if role, _ := stringAt(resp.JSON, "userRole"); role != "admin" {
				t.Errorf("expected role admin, got %s", role)
			}
		},
		Description:    "Second admin is used to prove admin A cannot manage users created by admin B.",
	},
	{
		ID:             "TC_ROOT_11",
		Name:           "Root Creates Role-Change User",
		Actor:          "root",
		Method:         "POST",
		Path:           "/api/v1/user/0?entity=autotest-admin-a",
		Body:           `{"email":"{emails.rootRoleChange}","name":"TC_ROOT_11: Root Role Change","currentPassword":"{testPassword}","userRole":"csr"}`,
		ExpectedStatus: "200",
		ExtractUserIDs: map[string]string{"rootRoleChangeUserID": "id"},
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			if email, _ := stringAt(resp.JSON, "email"); email != ctx.Emails["rootRoleChange"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["rootRoleChange"], email)
			}
		},
		Description:    "CSR user used to verify root can change another user's role.",
	},
	{
		ID:             "TC_ROOT_12",
		Name:           "Root Changes User Role",
		Actor:          "root",
		Method:         "PUT",
		Path:           "/api/v1/user/{rootRoleChangeUserID}",
		Body:           `{"userRole":"installer"}`,
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			if role, _ := stringAt(resp.JSON, "userRole"); role != "installer" {
				t.Errorf("expected role installer, got %s", role)
			}
		},
		Description:    "ROOT can change another user's role.",
	},
}

var adminTestCases = []IntegrationTestCase{
	{
		ID:             "TC_ADMIN_01",
		Name:           "Admin A Login",
		Actor:          "adminA",
		Method:         "POST",
		IsLogin:        true,
		Path:           "/api/v1/oauth2",
		Body:           `{"userId":"{emails.adminA}","password":"{testPassword}"}`,
		ExpectedStatus: "200",
		Description:    "Newly created admin must be able to authenticate.",
	},
	{
		ID:             "TC_ADMIN_02",
		Name:           "Admin A Reads Own Profile",
		Actor:          "adminA",
		Method:         "GET",
		Path:           "/api/v1/user/{adminAID}",
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			id, _ := stringAt(resp.JSON, "id")
			if id != ctx.UserIDs["adminAID"] {
				t.Errorf("expected id %s, got %s", ctx.UserIDs["adminAID"], id)
			}
			email, _ := stringAt(resp.JSON, "email")
			if email != ctx.Emails["adminA"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["adminA"], email)
			}
		},
		Description:    "Admins can read their own profile.",
	},
	{
		ID:             "TC_ADMIN_03",
		Name:           "Admin A Cannot Delete Root",
		Actor:          "adminA",
		Method:         "DELETE",
		Path:           "/api/v1/user/{rootID}",
		ExpectedStatus: "401|403",
		Description:    "Admin must never delete ROOT.",
	},
	{
		ID:             "TC_ADMIN_04",
		Name:           "Admin A Creates CSR A",
		Actor:          "adminA",
		Method:         "POST",
		Path:           "/api/v1/user/0",
		Body:           `{"email":"{emails.csrA}","name":"TC_ADMIN_04: CSR A","currentPassword":"{testPassword}","userRole":"csr","owner":"client-owner-must-be-ignored"}`,
		ExpectedStatus: "200",
		ExtractUserIDs: map[string]string{"csrAID": "id"},
		ExtractOwners:  map[string]string{"csrAOwner": "owner"},
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			email, _ := stringAt(resp.JSON, "email")
			if email != ctx.Emails["csrA"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["csrA"], email)
			}
			role, _ := stringAt(resp.JSON, "userRole")
			if role != "csr" {
				t.Errorf("expected role csr, got %s", role)
			}
			owner, _ := stringAt(resp.JSON, "owner")
			if owner != ctx.Owners["adminAOwner"] {
				t.Errorf("expected owner %s, got %s", ctx.Owners["adminAOwner"], owner)
			}
		},
		Description:    "Admin-created user must still inherit admin owner.",
	},
	{
		ID:             "TC_ADMIN_05",
		Name:           "Admin A Cannot Create Partner",
		Actor:          "adminA",
		Method:         "POST",
		Path:           "/api/v1/user/0",
		Body:           `{"email":"autotest-partner-{runID}@example.com","name":"TC_ADMIN_05: Partner","currentPassword":"{testPassword}","userRole":"partner"}`,
		ExpectedStatus: "401|403",
		Description:    "ADMIN must not create PARTNER users.",
	},
	{
		ID:             "TC_ADMIN_06",
		Name:           "Admin A Cannot Create Root",
		Actor:          "adminA",
		Method:         "POST",
		Path:           "/api/v1/user/0",
		Body:           `{"email":"autotest-root-{runID}@example.com","name":"TC_ADMIN_06: Root","currentPassword":"{testPassword}","userRole":"root"}`,
		ExpectedStatus: "401|403",
		Description:    "ADMIN must not create ROOT users.",
	},
	{
		ID:             "TC_ADMIN_07",
		Name:           "Admin A Gets Own Created CSR",
		Actor:          "adminA",
		Method:         "GET",
		Path:           "/api/v1/user/{csrAID}",
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			id, _ := stringAt(resp.JSON, "id")
			if id != ctx.UserIDs["csrAID"] {
				t.Errorf("expected id %s, got %s", ctx.UserIDs["csrAID"], id)
			}
			email, _ := stringAt(resp.JSON, "email")
			if email != ctx.Emails["csrA"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["csrA"], email)
			}
		},
		Description:    "Admin can read user and see the creator id.",
	},
	{
		ID:             "TC_ADMIN_08",
		Name:           "Admin Cannot Delete Self",
		Actor:          "adminA",
		Method:         "DELETE",
		Path:           "/api/v1/user/{adminAID}",
		ExpectedStatus: "401|403",
		Description:    "Admin delete rule must reject self-deletion.",
	},
	{
		ID:             "TC_ADMIN_09",
		Name:           "Admin A Creates CSR (for Deletion)",
		Actor:          "adminA",
		Method:         "POST",
		Path:           "/api/v1/user/0",
		Body:           `{"email":"{emails.deleteA}","name":"TC_ADMIN_09: Delete Me A","currentPassword":"{testPassword}","userRole":"csr"}`,
		ExpectedStatus: "200",
		ExtractUserIDs: map[string]string{"deleteAID": "id"},
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			email, _ := stringAt(resp.JSON, "email")
			if email != ctx.Emails["deleteA"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["deleteA"], email)
			}
		},
		Description:    "CSR user used to verify positive delete path for admin-created user.",
	},
	{
		ID:             "TC_ADMIN_10",
		Name:           "Admin A Deletes CSR",
		Actor:          "adminA",
		Method:         "DELETE",
		Path:           "/api/v1/user/{deleteAID}",
		ExpectedStatus: "200|204",
		Description:    "Admin can delete a non-root user created by the same admin.",
	},
	{
		ID:             "TC_ADMIN_11",
		Name:           "Admin A Cannot Promote CSR to Root",
		Actor:          "adminA",
		Method:         "PUT",
		Path:           "/api/v1/user/{csrAID}",
		Body:           `{"userRole":"root"}`,
		ExpectedStatus: "401|403",
		Description:    "Admin cannot change any user role to ROOT.",
	},
	{
		ID:             "TC_ADMIN_12",
		Name:           "Admin A Can Change Created CSR Role to Installer",
		Actor:          "adminA",
		Method:         "PUT",
		Path:           "/api/v1/user/{csrAID}",
		Body:           `{"userRole":"installer"}`,
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			id, _ := stringAt(resp.JSON, "id")
			if id != ctx.UserIDs["csrAID"] {
				t.Errorf("expected id %s, got %s", ctx.UserIDs["csrAID"], id)
			}
			role, _ := stringAt(resp.JSON, "userRole")
			if role != "installer" {
				t.Errorf("expected role installer, got %s", role)
			}
		},
		Description:    "Admin can change a user they created to another non-root role.",
	},
	{
		ID:             "TC_ADMIN_13",
		Name:           "Admin A Cannot Overwrite createdBy",
		Actor:          "adminA",
		Method:         "PUT",
		Path:           "/api/v1/user/{csrAID}",
		Body:           `{"createdBy":"{adminBID}","name":"TC_ADMIN_13: Updated CSR A"}`,
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			id, _ := stringAt(resp.JSON, "id")
			if id != ctx.UserIDs["csrAID"] {
				t.Errorf("expected id %s, got %s", ctx.UserIDs["csrAID"], id)
			}
			name, _ := stringAt(resp.JSON, "name")
			expectedName := "TC_ADMIN_13: Updated CSR A"
			if name != expectedName {
				t.Errorf("expected name %s, got %s", expectedName, name)
			}
		},
		Description:    "createdBy is server-owned and must not be changed from request body.",
	},
	{
		ID:             "TC_ADMIN_14",
		Name:           "Admin A List is Scoped by createdBy",
		Actor:          "adminA",
		Method:         "GET",
		Path:           "/api/v1/users",
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			if !usersContainsID(resp.JSON, ctx.UserIDs["csrAID"]) {
				t.Errorf("expected users list to contain csrA ID %s", ctx.UserIDs["csrAID"])
			}
			if usersContainsID(resp.JSON, ctx.UserIDs["csrBID"]) {
				t.Errorf("expected users list NOT to contain csrB ID %s", ctx.UserIDs["csrBID"])
			}
			if usersContainsID(resp.JSON, ctx.UserIDs["adminAID"]) {
				t.Errorf("expected users list NOT to contain adminA ID %s", ctx.UserIDs["adminAID"])
			}
		},
		Description:    "Admin A list should include only users created by admin A.",
	},
	{
		ID:             "TC_ADMIN_15",
		Name:           "Admin A idOnly List is Scoped",
		Actor:          "adminA",
		Method:         "GET",
		Path:           "/api/v1/users?idOnly=true",
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			if !usersContainsID(resp.JSON, ctx.UserIDs["csrAID"]) {
				t.Errorf("expected idOnly list to contain csrA ID %s", ctx.UserIDs["csrAID"])
			}
			if usersContainsID(resp.JSON, ctx.UserIDs["csrBID"]) {
				t.Errorf("expected idOnly list NOT to contain csrB ID %s", ctx.UserIDs["csrBID"])
			}
			if usersContainsID(resp.JSON, ctx.UserIDs["adminAID"]) {
				t.Errorf("expected idOnly list NOT to contain adminA ID %s", ctx.UserIDs["adminAID"])
			}
			if !usersAreStrings(resp.JSON) {
				t.Errorf("expected users in idOnly response to be simple strings")
			}
		},
		Description:    "idOnly list should still apply admin createdBy scope.",
	},
	{
		ID:             "TC_ADMIN_16",
		Name:           "Admin B Login",
		Actor:          "adminB",
		Method:         "POST",
		IsLogin:        true,
		Path:           "/api/v1/oauth2",
		Body:           `{"userId":"{emails.adminB}","password":"{testPassword}"}`,
		ExpectedStatus: "200",
		Description:    "Admin B authenticates to create its own child user.",
	},
	{
		ID:             "TC_ADMIN_17",
		Name:           "Admin B Creates CSR B",
		Actor:          "adminB",
		Method:         "POST",
		Path:           "/api/v1/user/0",
		Body:           `{"email":"{emails.csrB}","name":"TC_ADMIN_17: CSR B","currentPassword":"{testPassword}","userRole":"csr"}`,
		ExpectedStatus: "200",
		ExtractUserIDs: map[string]string{"csrBID": "id"},
		ExtractOwners:  map[string]string{"csrBOwner": "owner"},
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			email, _ := stringAt(resp.JSON, "email")
			if email != ctx.Emails["csrB"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["csrB"], email)
			}
			role, _ := stringAt(resp.JSON, "userRole")
			if role != "csr" {
				t.Errorf("expected role csr, got %s", role)
			}
			owner, _ := stringAt(resp.JSON, "owner")
			if owner != ctx.Owners["adminBOwner"] {
				t.Errorf("expected owner %s, got %s", ctx.Owners["adminBOwner"], owner)
			}
		},
		Description:    "Admin B creates a user which admin A must not be able to read or delete.",
	},
	{
		ID:             "TC_ADMIN_18",
		Name:           "Admin B Gets Own Created CSR",
		Actor:          "adminB",
		Method:         "GET",
		Path:           "/api/v1/user/{csrBID}",
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			id, _ := stringAt(resp.JSON, "id")
			if id != ctx.UserIDs["csrBID"] {
				t.Errorf("expected id %s, got %s", ctx.UserIDs["csrBID"], id)
			}
			email, _ := stringAt(resp.JSON, "email")
			if email != ctx.Emails["csrB"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["csrB"], email)
			}
		},
		Description:    "Control check: Admin B can read its own child user and see the creator id.",
	},
	{
		ID:             "TC_ADMIN_19",
		Name:           "Admin B List is Scoped by createdBy",
		Actor:          "adminB",
		Method:         "GET",
		Path:           "/api/v1/users",
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			if !usersContainsID(resp.JSON, ctx.UserIDs["csrBID"]) {
				t.Errorf("expected users list to contain csrB ID %s", ctx.UserIDs["csrBID"])
			}
			if usersContainsID(resp.JSON, ctx.UserIDs["csrAID"]) {
				t.Errorf("expected users list NOT to contain csrA ID %s", ctx.UserIDs["csrAID"])
			}
			if usersContainsID(resp.JSON, ctx.UserIDs["adminBID"]) {
				t.Errorf("expected users list NOT to contain adminB ID %s", ctx.UserIDs["adminBID"])
			}
		},
		Description:    "Admin B list should include only users created by admin B.",
	},
	{
		ID:             "TC_ADMIN_20",
		Name:           "Admin A Cannot Get Admin B CSR",
		Actor:          "adminA",
		Method:         "GET",
		Path:           "/api/v1/user/{csrBID}",
		ExpectedStatus: "401|403",
		Description:    "Admin A cannot read user whose createdBy is admin B id.",
	},
	{
		ID:             "TC_ADMIN_21",
		Name:           "Admin A Cannot Delete Admin B CSR",
		Actor:          "adminA",
		Method:         "DELETE",
		Path:           "/api/v1/user/{csrBID}",
		ExpectedStatus: "401|403",
		Description:    "Admin delete rule must require target.createdBy to equal admin user id.",
	},
	{
		ID:             "TC_ADMIN_22",
		Name:           "Admin A Email Search Cannot Find Admin B CSR",
		Actor:          "adminA",
		Method:         "GET",
		Path:           "/api/v1/users?emailSearch={emails.csrB}",
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			if usersContainsID(resp.JSON, ctx.UserIDs["csrBID"]) {
				t.Errorf("expected emailSearch NOT to find csrB ID %s for Admin A", ctx.UserIDs["csrBID"])
			}
		},
		Description:    "Search filters must combine with createdBy scope.",
	},
	{
		ID:             "TC_ADMIN_23",
		Name:           "Root Can Get Admin B CSR",
		Actor:          "root",
		Method:         "GET",
		Path:           "/api/v1/user/{csrBID}",
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			id, _ := stringAt(resp.JSON, "id")
			if id != ctx.UserIDs["csrBID"] {
				t.Errorf("expected id %s, got %s", ctx.UserIDs["csrBID"], id)
			}
			email, _ := stringAt(resp.JSON, "email")
			if email != ctx.Emails["csrB"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["csrB"], email)
			}
		},
		Description:    "Root remains able to read all users.",
	},
}

var csrTestCases = []IntegrationTestCase{
	{
		ID:             "TC_CSR_01",
		Name:           "CSR A Login",
		Actor:          "csrA",
		Method:         "POST",
		IsLogin:        true,
		Path:           "/api/v1/oauth2",
		Body:           `{"userId":"{emails.csrA}","password":"{testPassword}"}`,
		ExpectedStatus: "200",
		Description:    "CSR user logs in so we can verify CSR cannot create users.",
	},
	{
		ID:             "TC_CSR_02",
		Name:           "CSR A Reads Own Profile",
		Actor:          "csrA",
		Method:         "GET",
		Path:           "/api/v1/user/{csrAID}",
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			id, _ := stringAt(resp.JSON, "id")
			if id != ctx.UserIDs["csrAID"] {
				t.Errorf("expected id %s, got %s", ctx.UserIDs["csrAID"], id)
			}
			email, _ := stringAt(resp.JSON, "email")
			if email != ctx.Emails["csrA"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["csrA"], email)
			}
		},
		Description:    "Non-admin users can read their own profile.",
	},
	{
		ID:             "TC_CSR_03",
		Name:           "CSR A Updates Own Profile",
		Actor:          "csrA",
		Method:         "PUT",
		Path:           "/api/v1/user/{csrAID}",
		Body:           `{"name":"TC_CSR_03: CSR A Updated","description":"TC_CSR_03: Updated description","location":"TC_CSR_03: Updated location","locale":"en_US"}`,
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			id, _ := stringAt(resp.JSON, "id")
			if id != ctx.UserIDs["csrAID"] {
				t.Errorf("expected id %s, got %s", ctx.UserIDs["csrAID"], id)
			}
			name, _ := stringAt(resp.JSON, "name")
			expectedName := "TC_CSR_03: CSR A Updated"
			if name != expectedName {
				t.Errorf("expected name %s, got %s", expectedName, name)
			}
		},
		Description:    "Non-admin self-service updates should allow safe profile fields.",
	},
	{
		ID:             "TC_CSR_04",
		Name:           "CSR Cannot Create User",
		Actor:          "csrA",
		Method:         "POST",
		Path:           "/api/v1/user/0",
		Body:           `{"email":"{emails.csrCreateAttempt}","name":"TC_CSR_04: CSR Create Denied","currentPassword":"{testPassword}","userRole":"subscriber"}`,
		ExpectedStatus: "401|403",
		Description:    "CSR is not ROOT or ADMIN, so user creation must return access denied.",
	},
	{
		ID:             "TC_CSR_05",
		Name:           "CSR A Changes Own Password",
		Actor:          "csrA",
		Method:         "PUT",
		Path:           "/api/v1/user/{csrAID}",
		Body:           `{"changePassword":true,"currentPassword":"{emails.updatedPassword}"}`,
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			id, _ := stringAt(resp.JSON, "id")
			if id != ctx.UserIDs["csrAID"] {
				t.Errorf("expected id %s, got %s", ctx.UserIDs["csrAID"], id)
			}
			email, _ := stringAt(resp.JSON, "email")
			if email != ctx.Emails["csrA"] {
				t.Errorf("expected email %s, got %s", ctx.Emails["csrA"], email)
			}
		},
		Description:    "Non-admin users can update their own password.",
	},
	{
		ID:             "TC_CSR_06",
		Name:           "CSR A Can Login with New Password",
		Actor:          "csrA",
		Method:         "POST",
		IsLogin:        true,
		Path:           "/api/v1/oauth2",
		Body:           `{"userId":"{emails.csrA}","password":"{emails.updatedPassword}"}`,
		ExpectedStatus: "200",
		Description:    "Password change must take effect for future logins.",
	},
	{
		ID:             "TC_CSR_07",
		Name:           "CSR A Enables Own MFA Email",
		Actor:          "csrA",
		Method:         "PUT",
		Path:           "/api/v1/user/{csrAID}",
		Body:           `{"userTypeProprietaryInfo":{"mfa":{"enabled":true,"method":"email"}}}`,
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			id, _ := stringAt(resp.JSON, "id")
			if id != ctx.UserIDs["csrAID"] {
				t.Errorf("expected id %s, got %s", ctx.UserIDs["csrAID"], id)
			}
			enabled, _ := stringAt(resp.JSON, "userTypeProprietaryInfo.mfa.enabled")
			if enabled != "true" {
				t.Errorf("expected MFA enabled true, got %s", enabled)
			}
			method, _ := stringAt(resp.JSON, "userTypeProprietaryInfo.mfa.method")
			if method != "email" {
				t.Errorf("expected MFA method email, got %s", method)
			}
		},
		Description:    "Non-admin users can update their own MFA settings.",
	},
	{
		ID:             "TC_CSR_08",
		Name:           "CSR A Resets Own MFA",
		Actor:          "csrA",
		Method:         "PUT",
		Path:           "/api/v1/user/{csrAID}?resetMFA=true",
		ExpectedStatus: "200",
		Assert: func(t *testing.T, resp *apiResponse, ctx *TestContext) {
			id, _ := stringAt(resp.JSON, "id")
			if id != ctx.UserIDs["csrAID"] {
				t.Errorf("expected id %s, got %s", ctx.UserIDs["csrAID"], id)
			}
			enabled, _ := stringAt(resp.JSON, "userTypeProprietaryInfo.mfa.enabled")
			if enabled == "true" {
				t.Errorf("expected MFA to be disabled, got enabled=true")
			}
		},
		Description:    "resetMFA should disable MFA for the current user.",
	},
	{
		ID:             "TC_CSR_09",
		Name:           "CSR A Cannot Update owner, createdBy, or userRole",
		Actor:          "csrA",
		Method:         "PUT",
		Path:           "/api/v1/user/{csrAID}",
		Body:           `{"owner":"autotest-admin-b","createdBy":"{adminBID}","userRole":"admin"}`,
		ExpectedStatus: "401|403",
		Description:    "Non-admin users cannot overwrite ownership or role fields.",
	},
	{
		ID:             "TC_CSR_10",
		Name:           "CSR A Cannot Update suspended, blackListed, or notes",
		Actor:          "csrA",
		Method:         "PUT",
		Path:           "/api/v1/user/{csrAID}",
		Body:           `{"suspended":true,"blackListed":true,"notes":[{"note":"blocked by test"}]}`,
		ExpectedStatus: "401|403",
		Description:    "Non-admin users cannot overwrite admin-status fields or append notes.",
	},
}
