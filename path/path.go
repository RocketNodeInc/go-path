package path

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is a REST API client for Path.net
type Client struct {
	token      Token
	httpClient *http.Client
	// Represents the base API URL from which the service may be used by appending endpoints. It must not contain a
	// trailing slash
	baseURL string
}

// GetToken attempts to retrieve an access token from Path's API in order to use other endpoints. It will return an
// error if it does not succeed, otherwise it will set the client's token accordingly.
func (client *Client) GetToken(request AccessTokenRequest) error {
	endpoint := client.baseURL + "/token"

	// Unlike the rest of the API which consumes JSON, the /token endpoint expects URL-encoded POST data
	form := url.Values{
		"grant_type":    {request.GrantType},
		"username":      {request.Username},
		"password":      {request.Password},
		"scope":         {request.Scope},
		"client_id":     {request.ClientID},
		"client_secret": {request.ClientSecret},
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	body, err := client.handleRequest(req)
	if err != nil {
		return err
	}

	// Unmarshal the response body into a Token struct
	var receivedToken Token
	if err := json.Unmarshal(body, &receivedToken); err != nil {
		return err
	}

	// Set the client's accessToken for subsequent API requests
	client.token = receivedToken

	return nil
}

// GetToken attempts to retrieve an access token from Path's API in order to use other endpoints. It will return an
// error if it does not succeed, otherwise it will set the client's token accordingly.
func (client *Client) ChangePassword(oldPassword, newPassword string) error {
	endpoint := client.baseURL + "/account/password"

	form := url.Values{
		"old_password": {oldPassword},
		"new_password": {newPassword},
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	body, err := client.handleRequest(req)
	if err != nil {
		return err
	}

	var acknowledgement Acknowledgement
	if err := json.Unmarshal(body, &acknowledgement); err != nil {
		return err
	}

	if !acknowledgement.Acknowledged {
		return errors.New("request was not acknowledged")
	}

	return nil
}

// handleRequest executes the provided request and does all of the error processing. If a successful HTTP status code was received,
// it returns the clean request body.
func (client *Client) handleRequest(req *http.Request) ([]byte, error) {
	if client.token.AccessToken != "" {
		// Add the authorization if applicable
		// i.e Authorization: bearer accesstokenhere
		req.Header.Add("Authorization", fmt.Sprintf("%s %s", client.token.TokenType, client.token.AccessToken))
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return body, err
	}

	switch resp.StatusCode {
	case http.StatusAccepted:
		fallthrough
	case http.StatusCreated:
		fallthrough
	case http.StatusOK:
		return body, err
	case http.StatusUnauthorized:
		var apiError Error
		if err := json.Unmarshal(body, &apiError); err != nil {
			return nil, err
		}
		return body, errors.New(apiError.Detail)
	case http.StatusUnprocessableEntity: // ValidationError
		var apiErrors ValidationError
		if err := json.Unmarshal(body, &apiErrors); err != nil {
			return nil, err
		}

		var errMsg strings.Builder
		for _, errEntry := range apiErrors.Detail {
			errMsg.WriteString(
				fmt.Sprintf("\n- Message: %s\n  Type: %s\n  Location: %s", errEntry.Msg, errEntry.Type, errEntry.Loc),
			)
		}
		return body, errors.New(errMsg.String())
	default:
		return body, errors.New(fmt.Sprintf("Received unexpected status code: %d", resp.StatusCode))
	}
}

// Fetch all diversions for your account
func (client *Client) GetDiversions() (Diversions, error) {
	endpoint := client.baseURL + "/diversions"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Diversions{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return Diversions{}, err
	}

	var receivedDiversions Diversions
	if err := json.Unmarshal(body, &receivedDiversions); err != nil {
		return Diversions{}, err
	}

	return receivedDiversions, nil
}

// Fetch a single diversion
func (client *Client) GetDiversion(network string, prefixLength int) (Diversion, error) {
	endpoint := fmt.Sprintf("%s/diversions/%s/%d", client.baseURL, network, prefixLength)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Diversion{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return Diversion{}, err
	}

	var receivedDiversion Diversion
	if err := json.Unmarshal(body, &receivedDiversion); err != nil {
		return Diversion{}, err
	}

	return receivedDiversion, nil
}

// Delete a network diversion
func (client *Client) DeleteDiversion(network string, prefixLength int) error {
	return client.deleteResource(fmt.Sprintf("/diversions/%s/%d", network, prefixLength))
}

// Fetch all rules for your account
func (client *Client) GetRules() (Rules, error) {
	endpoint := client.baseURL + "/rules"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Rules{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return Rules{}, err
	}

	var receivedRules Rules
	if err := json.Unmarshal(body, &receivedRules); err != nil {
		return Rules{}, err
	}

	return receivedRules, nil
}

// Fetch all rules matching a specific destination for your account
func (client *Client) GetRulesWithDestination(destination string) (Rules, error) {
	endpoint := client.baseURL + "/rules?destination=" + destination
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Rules{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return Rules{}, err
	}

	var receivedRules Rules
	if err := json.Unmarshal(body, &receivedRules); err != nil {
		return Rules{}, err
	}

	return receivedRules, nil
}

// Create a new firewall rule, and return the new rule made
func (client *Client) CreateRule(newRule Rule) (Rule, error) {
	endpoint := client.baseURL + "/rules"

	jsonBody, err := json.Marshal(newRule)
	if err != nil {
		return Rule{}, err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return Rule{}, err
	}

	body, err := client.handleRequest(req)
	if err != nil {
		return Rule{}, err
	}

	var createdRule Rule
	if err := json.Unmarshal(body, &createdRule); err != nil {
		return Rule{}, err
	}

	return createdRule, nil
}

// Retrieve a rule with the specified ID
func (client *Client) GetRule(ruleID string) (Rule, error) {
	endpoint := fmt.Sprintf("%s/rules/%s", client.baseURL, ruleID)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Rule{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return Rule{}, err
	}

	var receivedRule Rule
	if err := json.Unmarshal(body, &receivedRule); err != nil {
		return Rule{}, err
	}

	return receivedRule, nil
}

// Delete a rule. If deletion fails, an error is returned
func (client *Client) DeleteRule(ruleID string) error {
	return client.deleteResource(fmt.Sprintf("/rules/%s", ruleID))
}

// Fetch all rate limiters for your account
func (client *Client) GetRateLimiters() (RateLimiters, error) {
	endpoint := client.baseURL + "/rate_limiters"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return RateLimiters{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return RateLimiters{}, err
	}

	var receivedRateLimiters RateLimiters
	if err := json.Unmarshal(body, &receivedRateLimiters); err != nil {
		return RateLimiters{}, err
	}

	return receivedRateLimiters, nil
}

// Update an existing rate limiter
func (client *Client) UpdateRateLimiter(rateLimiterID string, updatedRateLimiter RateLimiter) (RateLimiter, error) {
	endpoint := fmt.Sprintf("%s/rate_limiters/%s", client.baseURL, rateLimiterID)

	jsonBody, err := json.Marshal(updatedRateLimiter)
	if err != nil {
		return RateLimiter{}, err
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return RateLimiter{}, err
	}

	body, err := client.handleRequest(req)
	if err != nil {
		return RateLimiter{}, err
	}

	var newRateLimiter RateLimiter
	if err := json.Unmarshal(body, &newRateLimiter); err != nil {
		return RateLimiter{}, err
	}

	return newRateLimiter, nil
}

// Get a rate limiter by its ID
func (client *Client) GetRateLimiter(rateLimiterID string) (RateLimiter, error) {
	endpoint := fmt.Sprintf("%s/rate_limiters/%s", client.baseURL, rateLimiterID)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return RateLimiter{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return RateLimiter{}, err
	}

	var receivedRateLimiter RateLimiter
	if err := json.Unmarshal(body, &receivedRateLimiter); err != nil {
		return RateLimiter{}, err
	}

	return receivedRateLimiter, nil
}

// Delete a rule. If deletion fails, an error is returned
func (client *Client) DeleteRateLimiter(rateLimiterID string) error {
	return client.deleteResource(fmt.Sprintf("/rate_limiters/%s", rateLimiterID))
}

// Fetch the attack history for all hosts under your account
func (client *Client) GetAttackHistory() (AttackHistory, error) {
	endpoint := client.baseURL + "/attack_history"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return AttackHistory{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return AttackHistory{}, err
	}

	var receivedAttackHistory AttackHistory
	if err := json.Unmarshal(body, &receivedAttackHistory); err != nil {
		return AttackHistory{}, err
	}

	return receivedAttackHistory, nil
}

// Fetch the announcement history for all hosts under your account
func (client *Client) GetAnnouncementHistory() (AnnouncementHistory, error) {
	endpoint := client.baseURL + "/attack_history"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return AnnouncementHistory{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return AnnouncementHistory{}, err
	}

	var receivedAnnouncementHistory AnnouncementHistory
	if err := json.Unmarshal(body, &receivedAnnouncementHistory); err != nil {
		return AnnouncementHistory{}, err
	}

	return receivedAnnouncementHistory, nil
}

// Retrieve all application filters
func (client *Client) GetFilters() (Filters, error) {
	endpoint := client.baseURL + "/filters"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Filters{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return Filters{}, err
	}

	var receivedFilters Filters
	if err := json.Unmarshal(body, &receivedFilters); err != nil {
		return Filters{}, err
	}

	return receivedFilters, nil
}

// Retrieve all application filters matching a specific destination
func (client *Client) GetFiltersWithDestination(destination string) (Filters, error) {
	endpoint := client.baseURL + "/filters?addr=" + destination
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Filters{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return Filters{}, err
	}

	var receivedFilters Filters
	if err := json.Unmarshal(body, &receivedFilters); err != nil {
		return Filters{}, err
	}

	return receivedFilters, nil
}

// Retrieve all application filters available to your account
func (client *Client) GetAvailableFilters() (Filters, error) {
	endpoint := client.baseURL + "/filters/available"
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return Filters{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return Filters{}, err
	}

	var receivedFilters Filters
	if err := json.Unmarshal(body, &receivedFilters); err != nil {
		return Filters{}, err
	}

	return receivedFilters, nil
}

// Create a new application filter
func (client *Client) CreateFilter(filterType string) (Filter, error) {
	endpoint := fmt.Sprintf("%s/filters/%s", client.baseURL, filterType)
	req, err := http.NewRequest(http.MethodPost, endpoint, nil)
	if err != nil {
		return Filter{}, err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return Filter{}, err
	}

	var createdFilter Filter
	if err := json.Unmarshal(body, &createdFilter); err != nil {
		return Filter{}, err
	}

	return createdFilter, nil
}

// Delete a REST API service
// This function should not be used externally. Consider making use of the resource-specific functions such as DeleteRule
func (client *Client) deleteResource(loc string) error {
	endpoint := fmt.Sprintf("%s%s", client.baseURL, loc)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	body, err := client.handleRequest(req)
	if err != nil {
		return err
	}

	var acknowledgement Acknowledgement
	if err := json.Unmarshal(body, &acknowledgement); err != nil {
		return err
	}

	if !acknowledgement.Acknowledged {
		return errors.New("request was not acknowledged")
	}

	return nil
}

// Delete a filter. If deletion fails, an error is returned
func (client *Client) DeleteFilter(filterType, filterID string) error {
	return client.deleteResource(fmt.Sprintf("/filters/%s/%s", filterType, filterID))
}

// Create a new Path API client and fetch an access token
func NewClient(tokenRequest AccessTokenRequest) (Client, error) {
	client := Client{
		token: Token{},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.path.net",
	}

	if err := client.GetToken(tokenRequest); err != nil {
		return Client{}, err
	}

	switch client.token.TokenType {
	case "bearer":
		client.token.TokenType = AuthorizationTokenBearer
	default:
		client.token.TokenType = AuthorizationTokenBearer
	}

	return client, nil
}

// Create a new Path API client and use an existing access token
func NewClientWithToken(token string) Client {
	client := Client{
		token: Token{AccessToken: token, TokenType: AuthorizationTokenBearer},
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		baseURL: "https://api.path.net",
	}
	return client
}
