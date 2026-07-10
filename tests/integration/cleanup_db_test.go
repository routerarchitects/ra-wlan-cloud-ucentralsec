package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func RunDbCleanup() {
	loadDotEnvNoT()
	baseURL := os.Getenv("OWSEC_BASE_URL")
	tlsRootCA := os.Getenv("OW_RBAC_TLS_ROOT_CA")
	rootEmail := os.Getenv("OWSEC_ROOT_EMAIL")
	rootPassword := os.Getenv("OWSEC_ROOT_PASSWORD")

	if baseURL == "" || rootEmail == "" || rootPassword == "" {
		fmt.Println("Database cleanup skipped: missing environment variables")
		return
	}

	httpClient, err := NewHTTPClient(tlsRootCA)
	if err != nil {
		fmt.Printf("Database cleanup failed to create client: %v\n", err)
		return
	}
	client := newAPIClient(baseURL, httpClient)

	fmt.Println("Starting database cleanup (deleting all users except root)...")
	_, err = client.login("root", rootEmail, rootPassword)
	if err != nil {
		fmt.Printf("cleanup login failed: %v. Database may be empty or credentials changed.\n", err)
		return
	}
	token := client.tokens["root"]
	if token == "" {
		fmt.Println("cleanup root token not acquired")
		return
	}

	resp, err := client.do("root", http.MethodGet, "/api/v1/users", "")
	if err != nil {
		fmt.Printf("cleanup list users failed: %v\n", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("cleanup list users got status %d: %s\n", resp.StatusCode, string(resp.Body))
		return
	}

	usersList, ok := resp.JSON["users"].([]any)
	if !ok {
		fmt.Println("No users found or invalid users format in cleanup")
		return
	}

	deletedCount := 0
	for _, uRaw := range usersList {
		uMap, ok := uRaw.(map[string]any)
		if !ok {
			continue
		}
		email, _ := uMap["email"].(string)
		id, _ := uMap["id"].(string)
		role, _ := uMap["userRole"].(string)

		isRoot := strings.ToLower(email) == strings.ToLower(rootEmail) || id == "11111111-0000-0000-6666-999999999999" || strings.ToLower(role) == "root"
		if !isRoot {
			delResp, err := client.do("root", http.MethodDelete, "/api/v1/user/"+url.PathEscape(id), "")
			if err != nil {
				fmt.Printf("Failed to delete user %s (%s): %v\n", email, id, err)
				continue
			}
			if delResp.StatusCode == http.StatusOK || delResp.StatusCode == http.StatusNoContent {
				deletedCount++
			} else {
				fmt.Printf("Failed to delete user %s (%s): HTTP %d\n", email, id, delResp.StatusCode)
			}
		}
	}
	fmt.Printf("Cleanup complete. Deleted %d non-root users.\n", deletedCount)
}
