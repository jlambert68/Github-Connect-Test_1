package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// requestDeviceCode starts GitHub device flow and returns user/device codes.
func (a *app) requestDeviceCode(ctx context.Context) (*githubDeviceCodeResponse, error) {
	form := url.Values{}
	form.Set("client_id", a.cfg.ClientID)
	form.Set("scope", a.cfg.OAuthScope)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/device/code", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	status, endpoint, body, err := a.doGitHubRequest(req)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("github device code endpoint failed: status=%d url=%s response=%s", status, endpoint, strings.TrimSpace(string(body)))
	}

	var codeResp githubDeviceCodeResponse
	if err := json.Unmarshal(body, &codeResp); err != nil {
		return nil, err
	}
	if codeResp.Error != "" {
		if codeResp.ErrorDescription != "" {
			return nil, fmt.Errorf("github device code error: %s (%s)", codeResp.Error, codeResp.ErrorDescription)
		}
		return nil, fmt.Errorf("github device code error: %s", codeResp.Error)
	}
	if codeResp.DeviceCode == "" || codeResp.UserCode == "" || codeResp.VerificationURI == "" {
		return nil, fmt.Errorf("incomplete device code response from github")
	}
	return &codeResp, nil
}

// pollDeviceToken checks if a device_code has been approved and exchanged for a token yet.
func (a *app) pollDeviceToken(ctx context.Context, deviceCode string) (*githubDeviceTokenResponse, error) {
	form := url.Values{}
	form.Set("client_id", a.cfg.ClientID)
	form.Set("device_code", deviceCode)
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	status, endpoint, body, err := a.doGitHubRequest(req)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("github token endpoint failed: status=%d url=%s response=%s", status, endpoint, strings.TrimSpace(string(body)))
	}

	var tokenResp githubDeviceTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, err
	}
	return &tokenResp, nil
}

// pollDeviceFlow runs in a goroutine and drives status transitions for one flow_id.
func (a *app) pollDeviceFlow(flowID string) {
	log.Printf("device flow started: flow_id=%s", flowID)
	for {
		// Snapshot current flow state under lock.
		a.mu.RLock()
		flow, ok := a.deviceFlows[flowID]
		if !ok {
			a.mu.RUnlock()
			return
		}
		status := flow.Status
		expiresAt := flow.ExpiresAt
		interval := flow.Interval
		deviceCode := flow.DeviceCode
		a.mu.RUnlock()

		if status != "pending" {
			log.Printf("device flow finished: flow_id=%s status=%s", flowID, status)
			return
		}
		if time.Now().After(expiresAt) {
			// Local timeout guard: stop polling when flow window has passed.
			a.updateFlow(flowID, func(f *deviceFlow) {
				f.Status = "expired"
				f.Error = "device code expired before authorization completed"
			})
			log.Printf("device flow expired locally: flow_id=%s", flowID)
			return
		}

		tokenResp, err := a.pollDeviceToken(context.Background(), deviceCode)
		if err != nil {
			a.updateFlow(flowID, func(f *deviceFlow) {
				f.Status = "error"
				f.Error = err.Error()
			})
			log.Printf("device flow poll error: flow_id=%s error=%v", flowID, err)
			return
		}

		if tokenResp.AccessToken != "" {
			// Success path: token is now available for frontend registration endpoint.
			a.updateFlow(flowID, func(f *deviceFlow) {
				f.Status = "approved"
				f.AccessToken = tokenResp.AccessToken
				f.Error = ""
			})
			log.Printf("device flow approved: flow_id=%s token_len=%d", flowID, len(tokenResp.AccessToken))
			return
		}

		switch tokenResp.Error {
		case "", "authorization_pending":
			// User still authorizing.
			log.Printf("device flow pending: flow_id=%s", flowID)
		case "slow_down":
			// GitHub asks client to reduce polling frequency.
			interval += 5 * time.Second
			if tokenResp.Interval > 0 {
				interval = time.Duration(tokenResp.Interval) * time.Second
			}
			a.updateFlow(flowID, func(f *deviceFlow) {
				f.Interval = interval
			})
			log.Printf("device flow slow_down: flow_id=%s new_interval=%s", flowID, interval)
		case "access_denied":
			// User explicitly denied device flow on GitHub page.
			a.updateFlow(flowID, func(f *deviceFlow) {
				f.Status = "denied"
				if tokenResp.ErrorDescription != "" {
					f.Error = tokenResp.ErrorDescription
				} else {
					f.Error = "github authorization denied by user"
				}
			})
			log.Printf("device flow denied: flow_id=%s", flowID)
			return
		case "expired_token", "token_expired":
			// Provider-side expiry.
			a.updateFlow(flowID, func(f *deviceFlow) {
				f.Status = "expired"
				if tokenResp.ErrorDescription != "" {
					f.Error = tokenResp.ErrorDescription
				} else {
					f.Error = "device code expired"
				}
			})
			log.Printf("device flow expired by provider: flow_id=%s", flowID)
			return
		default:
			// Any other provider error is terminal for this flow.
			a.updateFlow(flowID, func(f *deviceFlow) {
				f.Status = "error"
				if tokenResp.ErrorDescription != "" {
					f.Error = fmt.Sprintf("%s (%s)", tokenResp.Error, tokenResp.ErrorDescription)
				} else {
					f.Error = tokenResp.Error
				}
			})
			log.Printf("device flow unexpected response: flow_id=%s error=%s description=%s", flowID, tokenResp.Error, tokenResp.ErrorDescription)
			return
		}

		if interval < 1*time.Second {
			// Defensive lower bound to avoid tight polling loops.
			interval = 1 * time.Second
		}
		time.Sleep(interval)
	}
}

// updateFlow applies an in-place mutation to one stored flow under lock.
func (a *app) updateFlow(flowID string, updateFn func(*deviceFlow)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	flow, ok := a.deviceFlows[flowID]
	if !ok {
		return
	}
	updateFn(flow)
}

// listRepoAndPrint converts GitHub content payload into UI-friendly entries and logs details.
func (a *app) listRepoAndPrint(ctx context.Context, token, owner, repo, ref, contentPath string) ([]repoContentEntry, error) {
	items, err := a.fetchContentsDir(ctx, token, owner, repo, contentPath, ref)
	if err != nil {
		return nil, err
	}

	entries := make([]repoContentEntry, 0, len(items))
	log.Printf("repo content listing for %s/%s (ref=%s path=%q)", owner, repo, ref, contentPath)
	for _, item := range items {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			name = strings.TrimSpace(item.Path)
		}
		if name == "" {
			continue
		}
		switch item.Type {
		case "dir":
			entries = append(entries, repoContentEntry{Name: name, Type: "dir"})
			log.Printf("DIR  %s", name)
		case "file":
			entries = append(entries, repoContentEntry{Name: name, Type: "file"})
			log.Printf("FILE %s", name)
		default:
			entries = append(entries, repoContentEntry{Name: name, Type: item.Type})
			log.Printf("%s %s", strings.ToUpper(item.Type), name)
		}
	}

	// Keep folder-first sorted output to match expected navigation UX.
	sort.Slice(entries, func(i, j int) bool {
		// Sort folders first, then by name.
		if entries[i].Type != entries[j].Type {
			if entries[i].Type == "dir" {
				return true
			}
			if entries[j].Type == "dir" {
				return false
			}
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})

	log.Printf("done. entries=%d", len(entries))
	return entries, nil
}

// listUserRepos pages through GitHub /user/repos and returns normalized owner/repo/ref fields.
func (a *app) listUserRepos(ctx context.Context, token string) ([]map[string]string, error) {
	perPage := 100
	page := 1
	all := make([]githubUserRepo, 0, 128)

	for {
		// Fetch page-by-page to support users with many repos.
		endpoint := fmt.Sprintf("https://api.github.com/user/repos?per_page=%d&page=%d&type=all&sort=updated", perPage, page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

		status, triedURL, body, err := a.doGitHubRequest(req)
		if err != nil {
			return nil, err
		}
		if status >= 300 {
			return nil, fmt.Errorf("github user repos request failed: status=%d url=%s response=%s", status, triedURL, strings.TrimSpace(string(body)))
		}

		var batch []githubUserRepo
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, fmt.Errorf("failed to parse github user repos response for url=%s: %w", triedURL, err)
		}
		all = append(all, batch...)
		if len(batch) < perPage {
			// Last page reached.
			break
		}
		page++
		if page > 10 {
			// Defensive cap to avoid unbounded pagination.
			break
		}
	}

	sort.Slice(all, func(i, j int) bool {
		return strings.ToLower(all[i].FullName) < strings.ToLower(all[j].FullName)
	})

	out := make([]map[string]string, 0, len(all))
	for _, r := range all {
		owner := strings.TrimSpace(r.Owner.Login)
		repo := strings.TrimSpace(r.Name)
		if owner == "" || repo == "" {
			continue
		}
		ref := strings.TrimSpace(r.DefaultBranch)
		if ref == "" {
			ref = "main"
		}
		out = append(out, map[string]string{
			"owner":      owner,
			"repo":       repo,
			"full_name":  strings.TrimSpace(r.FullName),
			"defaultRef": ref,
		})
	}
	return out, nil
}

// fetchFileContent loads one file via GitHub contents API and decodes base64 when needed.
func (a *app) fetchFileContent(ctx context.Context, token, owner, repo, ref, filePath string) (string, error) {
	endpoint := fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/contents/%s?ref=%s",
		url.PathEscape(owner),
		url.PathEscape(repo),
		encodePathForURL(filePath),
		url.QueryEscape(ref),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	status, triedURL, body, err := a.doGitHubRequest(req)
	if err != nil {
		return "", err
	}
	if status >= 300 {
		return "", fmt.Errorf("github file content request failed: status=%d owner=%q repo=%q ref=%q path=%q url=%s response=%s", status, owner, repo, ref, filePath, triedURL, strings.TrimSpace(string(body)))
	}

	var fileResp githubFileContentResponse
	if err := json.Unmarshal(body, &fileResp); err != nil {
		return "", fmt.Errorf("failed to parse github file content response for url=%s: %w", triedURL, err)
	}
	if fileResp.Type != "file" {
		return "", fmt.Errorf("path %q is not a file (type=%q)", filePath, fileResp.Type)
	}

	encoded := strings.ReplaceAll(fileResp.Content, "\n", "")
	encoded = strings.ReplaceAll(encoded, "\r", "")
	if fileResp.Encoding == "base64" && encoded != "" {
		// Contents API usually returns base64 with wrapped lines.
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("failed to decode base64 file content: %w", err)
		}
		return string(decoded), nil
	}

	if fileResp.Content != "" {
		return fileResp.Content, nil
	}

	if fileResp.DownloadURL != "" {
		// For large/binary files GitHub may skip inline content.
		return "(No inline content returned by GitHub API. Download URL: " + fileResp.DownloadURL + ")", nil
	}
	return "(No file content returned by GitHub API.)", nil
}

// fetchAuthenticatedUser resolves the user bound to a bearer token.
func (a *app) fetchAuthenticatedUser(ctx context.Context, token string) (*githubAuthenticatedUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	status, triedURL, body, err := a.doGitHubRequest(req)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("github authenticated user request failed: status=%d url=%s response=%s", status, triedURL, strings.TrimSpace(string(body)))
	}

	var user githubAuthenticatedUser
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, fmt.Errorf("failed to parse github authenticated user response for url=%s: %w", triedURL, err)
	}
	return &user, nil
}

// fetchContentsDir calls GitHub contents API for a repo path and normalizes both array and single-item responses.
func (a *app) fetchContentsDir(ctx context.Context, token, owner, repo, dirPath, ref string) ([]githubContentItem, error) {
	endpoint := fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/contents",
		url.PathEscape(owner),
		url.PathEscape(repo),
	)
	if trimmed := strings.Trim(dirPath, "/"); trimmed != "" {
		endpoint += "/" + encodePathForURL(trimmed)
	}
	endpoint += "?ref=" + url.QueryEscape(ref)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	status, triedURL, body, err := a.doGitHubRequest(req)
	if err != nil {
		return nil, err
	}
	if status >= 300 {
		return nil, fmt.Errorf("github contents request failed: status=%d owner=%q repo=%q ref=%q path=%q url=%s response=%s", status, owner, repo, ref, dirPath, triedURL, strings.TrimSpace(string(body)))
	}

	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return []githubContentItem{}, nil
	}

	if strings.HasPrefix(trimmed, "[") {
		// Directory response (array).
		var items []githubContentItem
		if err := json.Unmarshal(body, &items); err != nil {
			return nil, fmt.Errorf("failed to parse github directory response for url=%s: %w", triedURL, err)
		}
		return items, nil
	}

	// File response instead of directory listing.
	var single githubContentItem
	if err := json.Unmarshal(body, &single); err != nil {
		return nil, fmt.Errorf("failed to parse github file response for url=%s: %w", triedURL, err)
	}
	if single.Path == "" {
		var ghErr githubErrorResponse
		if err := json.Unmarshal(body, &ghErr); err == nil && ghErr.Message != "" {
			return nil, fmt.Errorf("github contents error for path=%q ref=%q url=%s: %s", dirPath, ref, triedURL, ghErr.Message)
		}
	}
	return []githubContentItem{single}, nil
}

// doGitHubRequest is a shared wrapper that logs request/response metadata and body preview.
func (a *app) doGitHubRequest(req *http.Request) (int, string, []byte, error) {
	start := time.Now()
	urlStr := req.URL.String()
	log.Printf("[github] --> %s %s", req.Method, urlStr)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		log.Printf("[github] xx> %s %s failed after %s: %v", req.Method, urlStr, time.Since(start), err)
		return 0, urlStr, nil, err
	}
	defer resp.Body.Close()

	body, readErr := io.ReadAll(resp.Body)
	duration := time.Since(start)
	if readErr != nil {
		log.Printf("[github] <x- %s %s status=%d duration=%s read_error=%v", req.Method, urlStr, resp.StatusCode, duration, readErr)
		return resp.StatusCode, urlStr, nil, readErr
	}

	log.Printf("[github] <-- %s %s status=%d duration=%s bytes=%d preview=%q", req.Method, urlStr, resp.StatusCode, duration, len(body), previewBody(body, 320))
	return resp.StatusCode, urlStr, body, nil
}
