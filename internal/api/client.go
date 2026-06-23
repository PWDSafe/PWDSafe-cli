// Package api is a small HTTP client for the PWDSafe API, see
// docs/openapi/openapi.yaml in the PWDSafe repo for the full contract.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Client talks to a PWDSafe instance.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// New creates a Client. token may be empty for unauthenticated requests
// (e.g. preflight, login).
func New(baseURL, token string) *Client {
	return &Client{
		BaseURL: baseURL,
		Token:   token,
		HTTP:    &http.Client{},
	}
}

// APIError represents a non-2xx JSON error response, e.g. {"message": "..."}.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s (HTTP %d)", e.Message, e.StatusCode)
	}

	return fmt.Sprintf("request failed with HTTP %d", e.StatusCode)
}

func (c *Client) do(method, path string, body any, out any) (*http.Response, error) {
	var reqBody io.Reader

	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}

		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out != nil && len(data) > 0 {
			if err := json.Unmarshal(data, out); err != nil {
				return resp, err
			}
		}

		return resp, nil
	}

	apiErr := &APIError{StatusCode: resp.StatusCode}

	var errBody struct {
		Message string `json:"message"`
	}

	if err := json.Unmarshal(data, &errBody); err == nil {
		apiErr.Message = errBody.Message
	}

	if out != nil && len(data) > 0 {
		// Allow callers to inspect the body of error responses too,
		// e.g. {"needs_2fa": true}.
		_ = json.Unmarshal(data, out)
	}

	return resp, apiErr
}

// PreflightResponse is the response from GET /api/vault/preflight.
type PreflightResponse struct {
	Salt                  string  `json:"salt"`
	UsesLoginHash         bool    `json:"uses_login_hash"`
	VaultConfigured       bool    `json:"vault_configured"`
	SeparateVaultPassword bool    `json:"separate_vault_password"`
	LoginSalt             *string `json:"login_salt"`
}

// Preflight calls GET /api/vault/preflight?email=...
func (c *Client) Preflight(email string) (*PreflightResponse, error) {
	var out PreflightResponse

	_, err := c.do(http.MethodGet, "/api/vault/preflight?email="+url.QueryEscape(email), nil, &out)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

// LoginRequest is the request body for POST /api/auth/login.
type LoginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	DeviceName string `json:"device_name"`
	TOTPCode   string `json:"totp_code,omitempty"`
}

// LoginResponse is the success response from POST /api/auth/login.
type LoginResponse struct {
	Token string `json:"token"`
	User  struct {
		ID                    int    `json:"id"`
		Email                 string `json:"email"`
		PrimaryGroup          int    `json:"primarygroup"`
		UsesLoginHash         bool   `json:"uses_login_hash"`
		SeparateVaultPassword bool   `json:"separate_vault_password"`
	} `json:"user"`
	VaultData struct {
		EncryptedPrivkey *string `json:"encrypted_privkey"`
		Salt             *string `json:"salt"`
		Pubkey           *string `json:"pubkey"`
	} `json:"vault_data"`
}

// loginResult is used to detect the {"needs_2fa": true} response shape,
// which is returned with HTTP 422 alongside a non-2xx APIError.
type loginResult struct {
	LoginResponse
	Needs2FA bool `json:"needs_2fa"`
}

// Login calls POST /api/auth/login. If the account requires a TOTP code and
// none was supplied (or it was invalid), needs2FA is true and resp is nil.
func (c *Client) Login(req LoginRequest) (resp *LoginResponse, needs2FA bool, err error) {
	var out loginResult

	_, err = c.do(http.MethodPost, "/api/auth/login", req, &out)
	if err != nil {
		var apiErr *APIError
		if ok := errors.As(err, &apiErr); ok && apiErr.StatusCode == 422 && out.Needs2FA {
			return nil, true, nil
		}

		return nil, false, err
	}

	return &out.LoginResponse, false, nil
}

// Logout calls POST /api/auth/logout, revoking the current token.
func (c *Client) Logout() error {
	_, err := c.do(http.MethodPost, "/api/auth/logout", nil, nil)
	return err
}

// Group is a single entry from GET /api/groups.
type Group struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	ParentID   *int   `json:"parent_id"`
	Permission string `json:"permission"`
	IsPrimary  bool   `json:"is_primary"`
}

// Groups calls GET /api/groups.
func (c *Client) Groups() ([]Group, error) {
	var out []Group

	_, err := c.do(http.MethodGet, "/api/groups", nil, &out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// CreateGroupRequest is the request body for POST /api/groups.
type CreateGroupRequest struct {
	Name     string `json:"name"`
	ParentID *int   `json:"parent_id,omitempty"`
}

// CreateGroup calls POST /api/groups.
func (c *Client) CreateGroup(req CreateGroupRequest) (*Group, error) {
	var out Group

	_, err := c.do(http.MethodPost, "/api/groups", req, &out)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

// GroupMember is a single entry from GET /api/groups/{group}/pubkeys.
type GroupMember struct {
	ID     int    `json:"id"`
	Pubkey string `json:"pubkey"`
}

// GroupPubkeys calls GET /api/groups/{group}/pubkeys, returning the RSA
// public keys of every member of the group, used to encrypt a new
// credential for each of them.
func (c *Client) GroupPubkeys(groupID int) ([]GroupMember, error) {
	var out struct {
		Users []GroupMember `json:"users"`
	}

	_, err := c.do(http.MethodGet, fmt.Sprintf("/api/groups/%d/pubkeys", groupID), nil, &out)
	if err != nil {
		return nil, err
	}

	return out.Users, nil
}

// EncryptedEntry is a per-user ciphertext entry for a new credential, as
// produced by vaultcrypto.EncryptCredentialData.
type EncryptedEntry struct {
	UserID int    `json:"userid"`
	Data   string `json:"data"`
}

// CreateCredentialRequest is the request body for
// POST /api/groups/{group}/credentials.
type CreateCredentialRequest struct {
	Name      string           `json:"name"`
	Url       string           `json:"url,omitempty"`
	Username  string           `json:"user"`
	Notes     *string          `json:"notes,omitempty"`
	Encrypted []EncryptedEntry `json:"encrypted"`
}

// CreateCredential calls POST /api/groups/{group}/credentials.
func (c *Client) CreateCredential(groupID int, req CreateCredentialRequest) (*CredentialSummary, error) {
	var out CredentialSummary

	_, err := c.do(http.MethodPost, fmt.Sprintf("/api/groups/%d/credentials", groupID), req, &out)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

// CredentialSummary is credential metadata without ciphertext.
type CredentialSummary struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Url      string `json:"url"`
	Username string `json:"username"`
	Notes    string `json:"notes"`
	GroupID  int    `json:"groupid"`
	HasTOTP  bool   `json:"has_totp"`
	Group    *struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"group"`
}

// MoveCredentialRequest is the request body for
// POST /api/credentials/{credential}/move.
type MoveCredentialRequest struct {
	GroupID   int              `json:"group_id"`
	Encrypted []EncryptedEntry `json:"encrypted"`
}

// MoveCredential calls POST /api/credentials/{credential}/move.
func (c *Client) MoveCredential(credentialID int, req MoveCredentialRequest) (*CredentialSummary, error) {
	var out CredentialSummary

	_, err := c.do(http.MethodPost, fmt.Sprintf("/api/credentials/%d/move", credentialID), req, &out)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

// GroupCredentials calls GET /api/groups/{group}/credentials.
func (c *Client) GroupCredentials(groupID int) ([]CredentialSummary, error) {
	var out []CredentialSummary

	_, err := c.do(http.MethodGet, fmt.Sprintf("/api/groups/%d/credentials", groupID), nil, &out)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// Credential is a single credential including ciphertext for the current
// user, from GET /api/credentials/{id}.
type Credential struct {
	CredentialSummary
	Data       string  `json:"data"`
	TOTPSecret *string `json:"totp_secret"`
}

// Credential calls GET /api/credentials/{id}.
func (c *Client) Credential(id int) (*Credential, error) {
	var out Credential

	_, err := c.do(http.MethodGet, fmt.Sprintf("/api/credentials/%d", id), nil, &out)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

// Device is a single entry from GET /api/auth/devices.
type Device struct {
	ID         int     `json:"id"`
	Name       string  `json:"name"`
	LastUsedAt *string `json:"last_used_at"`
	CreatedAt  string  `json:"created_at"`
	IsCurrent  bool    `json:"is_current"`
}

// Devices calls GET /api/auth/devices.
func (c *Client) Devices() ([]Device, error) {
	var out []Device

	_, err := c.do(http.MethodGet, "/api/auth/devices", nil, &out)
	if err != nil {
		return nil, err
	}

	return out, nil
}
