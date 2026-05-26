package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// kl 1329

type config struct {
	// ServerAddr is the HTTP listen address for the backend, e.g. ":8080".
	ServerAddr string
	// ClientID is the GitHub OAuth App client id used by device flow.
	ClientID string
	// RepoOwner/RepoName/RepoRef are optional defaults for repo-listing endpoints.
	RepoOwner string
	RepoName  string
	RepoRef   string
	// OAuthScope is requested when starting device flow (typically "repo").
	OAuthScope string
	// AuthTokenEncryptionKey is the raw secret used to derive an AES key.
	AuthTokenEncryptionKey string
	// AuthTokenSQLiteFilePath is where encrypted token rows are stored.
	AuthTokenSQLiteFilePath string
}

type sessionIdentity struct {
	// UserID is the stable GitHub numeric id represented as a string.
	UserID string
	// UserLogin is the GitHub username/login (case-insensitive for checks).
	UserLogin string
	// UserName is the display name from GitHub profile (may be empty).
	UserName string
}

type app struct {
	cfg config

	// mu protects all mutable maps below.
	mu sync.RWMutex
	// sessionUser maps backend session id -> logical GitHub identity.
	sessionUser map[string]sessionIdentity
	// encryptedTokenCache stores encrypted token payloads by user id.
	encryptedTokenCache map[string]string // userId -> encrypted token
	// tokenHashCache stores sha256(lower(login)+token) by login.
	tokenHashCache map[string]string // userLogin -> token hash
	// deviceFlows tracks in-flight device login flows by random flow id.
	deviceFlows map[string]*deviceFlow
	// httpClient is reused for all outbound GitHub calls.
	httpClient *http.Client
	// db is the SQLite connection used for persisted encrypted tokens.
	db *sql.DB
	// encryptionKey is a 32-byte AES key derived from AUTH_TOKEN_ENCRYPTION_KEY.
	encryptionKey []byte
}

type deviceFlow struct {
	// ID is backend-generated and used by frontend polling.
	ID string
	// SessionID binds the flow to exactly one backend browser session.
	SessionID string
	// DeviceCode/UserCode/VerificationURI* are returned by GitHub device endpoint.
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	// ExpiresAt/Interval drive backend polling behavior.
	ExpiresAt time.Time
	Interval  time.Duration
	// Status transitions: pending -> approved|denied|expired|error.
	Status string
	// AccessToken is only set on approved status.
	AccessToken string
	// Error contains details for denied/expired/error states.
	Error string
}

type githubDeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Error                   string `json:"error"`
	ErrorDescription        string `json:"error_description"`
}

type githubDeviceTokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	Interval         int    `json:"interval"`
}

type githubContentItem struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Type string `json:"type"`
}

type githubErrorResponse struct {
	Message string `json:"message"`
}

type githubRepoOwner struct {
	Login string `json:"login"`
}

type githubUserRepo struct {
	Name          string          `json:"name"`
	FullName      string          `json:"full_name"`
	Owner         githubRepoOwner `json:"owner"`
	DefaultBranch string          `json:"default_branch"`
}

type repoContentEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type githubFileContentResponse struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	Size        int    `json:"size"`
	Encoding    string `json:"encoding"`
	Content     string `json:"content"`
	DownloadURL string `json:"download_url"`
}

type githubAuthenticatedUser struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
}

func main() {
	// 1) Load and validate runtime configuration.
	cfg := loadConfig()
	if err := cfg.validate(); err != nil {
		log.Fatalf("configuration error: %v", err)
	}

	// 2) Open SQLite used for encrypted token persistence.
	db, err := openSQLiteDB(cfg.AuthTokenSQLiteFilePath)
	if err != nil {
		log.Fatalf("database init error: %v", err)
	}
	defer db.Close()

	// 3) Derive fixed-length AES key from provided env secret.
	encKey := deriveEncryptionKey(cfg.AuthTokenEncryptionKey)

	// 4) Build app state and in-memory caches.
	a := &app{
		cfg:                 cfg,
		sessionUser:         make(map[string]sessionIdentity),
		encryptedTokenCache: make(map[string]string),
		tokenHashCache:      make(map[string]string),
		deviceFlows:         make(map[string]*deviceFlow),
		db:                  db,
		encryptionKey:       encKey,
		httpClient: &http.Client{
			Timeout: 20 * time.Second,
		},
	}

	// 5) Register all HTTP routes (UI + auth + repo browsing).
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("GET /api/auth/status", a.handleAuthStatus)
	mux.HandleFunc("GET /api/user/repos", a.handleUserRepos)
	mux.HandleFunc("POST /api/token/clear-memory", a.handleClearTokenMemory)
	mux.HandleFunc("POST /api/token/clear-all", a.handleClearTokenMemoryAndDB)
	mux.HandleFunc("POST /auth/github/device/open-browser", a.handleOpenGitHubDeviceBrowser)
	mux.HandleFunc("POST /auth/github/device/start", a.handleGitHubDeviceStart)
	mux.HandleFunc("GET /auth/github/device/status", a.handleGitHubDeviceStatus)
	mux.HandleFunc("POST /api/token/register", a.handleRegisterToken)
	mux.HandleFunc("POST /api/list-repo", a.handleListRepo)
	mux.HandleFunc("POST /api/file-content", a.handleFileContent)

	// 6) Configure HTTP server timeouts and request logging middleware.
	server := &http.Server{
		Addr:         cfg.ServerAddr,
		Handler:      logRequests(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	appURL := serverURLFromAddr(cfg.ServerAddr)
	log.Printf("github auth flow: device flow (no client secret required)")
	log.Printf("sqlite token db file: %s", cfg.AuthTokenSQLiteFilePath)

	// 7) Best effort: open the UI in a regular browser window/tab.
	go func() {
		time.Sleep(800 * time.Millisecond)
		if err := openRegularBrowser(appURL); err != nil {
			log.Printf("could not open browser: %v", err)
			log.Printf("open %s manually", appURL)
		}
	}()

	log.Printf("server started at %s", appURL)
	// 8) Start serving requests.
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}

func loadConfig() config {
	// Read required/optional env values with explicit defaults where applicable.
	return config{
		ServerAddr:              getEnv("SERVER_ADDR", ":8080"),
		ClientID:                os.Getenv("GITHUB_CLIENT_ID"),
		RepoOwner:               os.Getenv("GITHUB_REPO_OWNER"),
		RepoName:                os.Getenv("GITHUB_REPO_NAME"),
		RepoRef:                 getEnv("GITHUB_REPO_REF", "main"),
		OAuthScope:              getEnv("GITHUB_OAUTH_SCOPE", "repo"),
		AuthTokenEncryptionKey:  os.Getenv("AUTH_TOKEN_ENCRYPTION_KEY"),
		AuthTokenSQLiteFilePath: getEnv("AUTH_TOKEN_SQLITE_FILE", "auth_tokens.db"),
	}
}

func (c config) validate() error {
	var missing []string
	if c.ClientID == "" {
		missing = append(missing, "GITHUB_CLIENT_ID")
	}
	if strings.TrimSpace(c.AuthTokenEncryptionKey) == "" {
		missing = append(missing, "AUTH_TOKEN_ENCRYPTION_KEY")
	}
	if len(missing) > 0 {
		// Fail fast so startup never proceeds with invalid auth configuration.
		return fmt.Errorf("missing required env vars: %s", strings.Join(missing, ", "))
	}
	return nil
}

const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GitHub Repo File Lister</title>
  <style>
    :root { color-scheme: light; }
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      background: #f5f7fb;
      color: #111827;
    }
    .wrap {
      max-width: 980px;
      margin: 56px auto;
      padding: 0 20px;
    }
    h1 { margin: 0 0 14px; font-size: 30px; }
    p { margin: 0 0 16px; line-height: 1.5; }
    button {
      border: 0;
      border-radius: 8px;
      padding: 10px 16px;
      font-size: 15px;
      background: #2563eb;
      color: #fff;
      cursor: pointer;
    }
    button:disabled { opacity: 0.6; cursor: default; }
    pre {
      margin-top: 18px;
      padding: 12px;
      border-radius: 8px;
      background: #0f172a;
      color: #e2e8f0;
      font-size: 13px;
      overflow-x: auto;
      min-height: 80px;
    }
    .row { display: flex; gap: 10px; flex-wrap: wrap; }
    .action-row { margin-top: 8px; }
    .clear-row { margin-top: 8px; }
    .push-right { margin-left: auto; }
    .secondary { background: #334155; }
    .info-box {
      margin-top: 14px;
    }
    .lists {
      margin-top: 16px;
      display: grid;
      gap: 14px;
      grid-template-columns: 1fr 1fr;
    }
    .list-label {
      margin: 0 0 6px;
      font-size: 13px;
      color: #334155;
    }
    .section-head {
      display: flex;
      align-items: baseline;
      gap: 10px;
      flex-wrap: wrap;
    }
    select {
      width: 100%;
      min-height: 320px;
      border-radius: 8px;
      border: 1px solid #cbd5e1;
      background: #ffffff;
      color: #111827;
      padding: 8px;
      font-size: 14px;
      box-sizing: border-box;
    }
    .content-wrap {
      margin-top: 14px;
    }
    .content-actions {
      margin-top: 8px;
    }
    .selected-wrap {
      margin-top: 14px;
    }
    .modal-overlay {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.55);
      display: none;
      align-items: flex-start;
      justify-content: center;
      overflow: auto;
      padding: 24px 12px;
      z-index: 50;
    }
    .modal-overlay.open { display: flex; }
    .modal-panel {
      width: min(1040px, 100%);
      background: #f5f7fb;
      border-radius: 10px;
      box-shadow: 0 30px 80px rgba(2, 6, 23, 0.35);
    }
    .base-wrap {
      max-width: 980px;
      margin: 56px auto;
      padding: 0 20px;
    }
    .modal-wrap {
      max-width: none;
      margin: 0;
      padding: 18px 20px 22px;
    }
    textarea {
      width: 100%;
      min-height: 240px;
      border-radius: 8px;
      border: 1px solid #cbd5e1;
      background: #ffffff;
      color: #111827;
      padding: 10px;
      font-size: 13px;
      line-height: 1.4;
      box-sizing: border-box;
      resize: vertical;
      overflow-x: auto;
      white-space: pre;
      word-break: normal;
      overflow-wrap: normal;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    }
    @media (max-width: 900px) {
      .lists { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <main class="base-wrap">
    <h1>Selected Files</h1>
    <div class="selected-wrap">
      <p class="list-label">Selected Files</p>
      <select id="selectedFilesListBase" size="10"></select>
    </div>
    <div class="row content-actions">
      <button id="openModal">Import</button>
      <button class="secondary push-right" id="checkUpdatesBase" disabled>Check for updates</button>
      <button class="secondary" id="applyUpdatesBase" disabled>Update</button>
      <button class="secondary" id="sortSelectedBase">Sort</button>
    </div>
  </main>

  <div class="modal-overlay" id="appModal" aria-hidden="true">
    <div class="modal-panel">
      <main class="wrap modal-wrap">
        <h1>GitHub Device Flow + Repo Listing</h1>
        <p>Log in, load your repositories, then click one repository to view its files and folders.</p>
        <div class="row">
          <button id="login">Log in to GitHub</button>
          <button class="secondary" id="checkAuth">Check GitHub Login</button>
          <button class="secondary" id="loadRepos">Load My Repos</button>
          <button class="secondary" id="listRepo">Load Selected Repo</button>
        </div>
        <div class="row action-row">
          <button class="secondary" id="importTop">Import</button>
          <button class="secondary" id="cancelTop">Cancel</button>
        </div>
        <div class="row clear-row">
          <button class="secondary" id="clearMemToken">Clear Token Memory Cache</button>
          <button class="secondary" id="clearAllToken">Clear Token Memory + DB</button>
        </div>
        <p class="list-label" id="loggedInUser">Logged in user: -</p>
        <pre class="info-box" id="out">Waiting for action...</pre>
        <div class="lists">
          <div>
            <p class="list-label">Repositories</p>
            <select id="repoList" size="14"></select>
          </div>
          <div>
            <p class="list-label section-head"><span>Files and Folders</span><span id="entryPath">Path: /</span></p>
            <select id="entryList" size="14"></select>
          </div>
        </div>
        <div class="selected-wrap">
          <p class="list-label">Selected Files (Double-click file to select/deselect)</p>
          <select id="selectedFilesListModal" size="6"></select>
        </div>
        <div class="row content-actions">
          <button class="secondary" id="importBottom">Import</button>
          <button class="secondary" id="cancelBottom">Cancel</button>
          <button class="secondary push-right" id="checkUpdatesModal" disabled>Check for updates</button>
          <button class="secondary" id="applyUpdatesModal" disabled>Update</button>
          <button class="secondary" id="sortSelectedModal">Sort</button>
        </div>
        <div class="content-wrap">
          <p class="list-label" id="fileFullPath">Full Path: -</p>
          <textarea id="fileContent" readonly wrap="off"></textarea>
        </div>
      </main>
    </div>
  </div>
  <script>
    const out = document.getElementById('out');
    const loginButton = document.getElementById('login');
    const repoList = document.getElementById('repoList');
    const entryList = document.getElementById('entryList');
    const entryPathLabel = document.getElementById('entryPath');
    const selectedFilesListBase = document.getElementById('selectedFilesListBase');
    const selectedFilesListModal = document.getElementById('selectedFilesListModal');
    const fileFullPath = document.getElementById('fileFullPath');
    const fileContent = document.getElementById('fileContent');
    const loggedInUserLabel = document.getElementById('loggedInUser');
    const appModal = document.getElementById('appModal');
    const openModalButton = document.getElementById('openModal');
    const checkUpdatesBaseButton = document.getElementById('checkUpdatesBase');
    const checkUpdatesModalButton = document.getElementById('checkUpdatesModal');
    const applyUpdatesBaseButton = document.getElementById('applyUpdatesBase');
    const applyUpdatesModalButton = document.getElementById('applyUpdatesModal');
    const sortSelectedBaseButton = document.getElementById('sortSelectedBase');
    const sortSelectedModalButton = document.getElementById('sortSelectedModal');
    const setOut = (msg) => { out.textContent = msg; };
    let pollingTimer = null;
    const browseState = { owner: '', repo: '', ref: 'main', path: '' };
    const selectedFiles = new Map();
    const newVersionSuffix = ' (New version exists)';

    function clearSelect(el) {
      while (el.options.length > 0) {
        el.remove(0);
      }
    }

    function fillSelect(el, values) {
      clearSelect(el);
      for (const item of values) {
        const opt = document.createElement('option');
        opt.value = item.value;
        opt.textContent = item.label;
        if (item.owner) opt.dataset.owner = item.owner;
        if (item.repo) opt.dataset.repo = item.repo;
        if (item.ref) opt.dataset.ref = item.ref;
        if (item.path !== undefined) opt.dataset.path = item.path;
        if (item.type) opt.dataset.type = item.type;
        el.appendChild(opt);
      }
    }

    function clearFileContent() {
      fileFullPath.textContent = 'Full Path: -';
      fileContent.value = '';
    }

    function allSelectedLists() {
      return [selectedFilesListBase, selectedFilesListModal];
    }

    function selectedKeysFromLists() {
      return {
        base: selectedFilesListBase.value || '',
        modal: selectedFilesListModal.value || ''
      };
    }

    function openModal() {
      appModal.classList.add('open');
      appModal.setAttribute('aria-hidden', 'false');
    }

    function closeModal() {
      appModal.classList.remove('open');
      appModal.setAttribute('aria-hidden', 'true');
    }

    function setUpdateButtonsEnabled(enabled) {
      checkUpdatesBaseButton.disabled = !enabled;
      checkUpdatesModalButton.disabled = !enabled;
      applyUpdatesBaseButton.disabled = !enabled;
      applyUpdatesModalButton.disabled = !enabled;
    }

    function clearSelectedFiles() {
      selectedFiles.clear();
      fillSelect(selectedFilesListBase, []);
      fillSelect(selectedFilesListModal, []);
    }

    function renderSelectedFiles(preservedKeys) {
      const selectedKeys = preservedKeys || selectedKeysFromLists();
      const items = Array.from(selectedFiles.values())
        .map((item) => ({ value: item.key, label: item.label }));
      fillSelect(selectedFilesListBase, items);
      fillSelect(selectedFilesListModal, items);
      if (selectedKeys.base && selectedFiles.has(selectedKeys.base)) {
        selectedFilesListBase.value = selectedKeys.base;
      }
      if (selectedKeys.modal && selectedFiles.has(selectedKeys.modal)) {
        selectedFilesListModal.value = selectedKeys.modal;
      }
    }

    function makeSelectedKey(owner, repo, ref, pathValue) {
      return (owner || '') + '|' + (repo || '') + '|' + (ref || 'main') + '|' + (pathValue || '');
    }

    async function fetchFileContentData(owner, repo, ref, pathValue) {
      const res = await fetch('/api/file-content', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ owner, repo, ref, path: pathValue })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error((data && data.error) ? data.error : 'Failed to load file content');
      }
      return data;
    }

    function labelWithUpdateState(item) {
      return item.updateAvailable ? (item.baseLabel + newVersionSuffix) : item.baseLabel;
    }

    async function addSelectedFile(owner, repo, ref, pathValue) {
      const key = makeSelectedKey(owner, repo, ref, pathValue);
      if (selectedFiles.has(key)) {
        setOut('Already selected: ' + pathValue);
        return;
      }
      const selectedBefore = selectedKeysFromLists();
      let baselineContent = '';
      try {
        const data = await fetchFileContentData(owner, repo, ref, pathValue);
        baselineContent = typeof data.content === 'string' ? data.content : '';
      } catch (err) {
        setOut('Could not select file: ' + err.message);
        return;
      }
      const baseLabel = owner + '/' + repo + '/' + pathValue;
      selectedFiles.set(key, {
        key: key,
        owner: owner,
        repo: repo,
        ref: ref || 'main',
        path: pathValue,
        baseLabel: baseLabel,
        label: baseLabel,
        baselineContent: baselineContent,
        updateAvailable: false
      });
      renderSelectedFiles({
        base: selectedBefore.base || key,
        modal: selectedBefore.modal || key
      });
      setOut('Selected file: ' + pathValue);
    }

    function removeSelectedFileByKey(key) {
      if (!selectedFiles.has(key)) return;
      const item = selectedFiles.get(key);
      selectedFiles.delete(key);
      renderSelectedFiles();
      if (item && item.label) {
        setOut('Deselected file: ' + item.label);
      } else {
        setOut('Deselected file.');
      }
    }

    function sortSelectedFiles() {
      const previous = selectedKeysFromLists();
      const sortedItems = Array.from(selectedFiles.values())
        .sort((a, b) => a.label.localeCompare(b.label));
      selectedFiles.clear();
      for (const item of sortedItems) {
        selectedFiles.set(item.key, item);
      }
      renderSelectedFiles(previous);
      setOut('Selected files sorted.');
    }

    async function checkSelectedFilesForUpdates() {
      const selectedBefore = selectedKeysFromLists();
      const values = Array.from(selectedFiles.values());
      if (values.length === 0) {
        setOut('No selected files to check.');
        return;
      }
      let changedCount = 0;
      for (const item of values) {
        try {
          const data = await fetchFileContentData(item.owner, item.repo, item.ref || 'main', item.path);
          const latestContent = typeof data.content === 'string' ? data.content : '';
          const hasUpdate = latestContent !== (item.baselineContent || '');
          if (hasUpdate !== !!item.updateAvailable) {
            changedCount++;
          }
          item.updateAvailable = hasUpdate;
          item.label = labelWithUpdateState(item);
        } catch (err) {
          setOut('Check failed for ' + item.baseLabel + ': ' + err.message);
          return;
        }
      }
      renderSelectedFiles(selectedBefore);
      if (changedCount === 0) {
        setOut('Check complete. No update state changes.');
      } else {
        setOut('Check complete. Update flags changed for ' + changedCount + ' file(s).');
      }
    }

    async function applySelectedFileUpdates() {
      const selectedBefore = selectedKeysFromLists();
      const values = Array.from(selectedFiles.values());
      if (values.length === 0) {
        setOut('No selected files to update.');
        return;
      }
      let updatedCount = 0;
      for (const item of values) {
        if (!item.updateAvailable) continue;
        try {
          const data = await fetchFileContentData(item.owner, item.repo, item.ref || 'main', item.path);
          const latestContent = typeof data.content === 'string' ? data.content : '';
          item.baselineContent = latestContent;
          item.updateAvailable = false;
          item.label = labelWithUpdateState(item);
          updatedCount++;

          if (selectedBefore.base === item.key || selectedBefore.modal === item.key) {
            fileFullPath.textContent = 'Full Path: ' + (data.full_path || (item.owner + '/' + item.repo + '/' + item.path));
            fileContent.value = latestContent;
          }
        } catch (err) {
          setOut('Update failed for ' + item.baseLabel + ': ' + err.message);
          return;
        }
      }
      renderSelectedFiles(selectedBefore);
      setOut('Update complete. Updated ' + updatedCount + ' file(s).');
    }

    function parseSelectedKey(key) {
      const parts = (key || '').split('|');
      if (parts.length < 4) return null;
      return {
        owner: parts[0] || '',
        repo: parts[1] || '',
        ref: parts[2] || 'main',
        path: parts.slice(3).join('|')
      };
    }

    function showSelectedFileSnapshot(item) {
      if (!item) return;
      fileFullPath.textContent = 'Full Path: ' + (item.baseLabel || (item.owner + '/' + item.repo + '/' + item.path));
      fileContent.value = typeof item.baselineContent === 'string' ? item.baselineContent : '';
      if (item.updateAvailable) {
        setOut('Showing selected snapshot for ' + item.path + '. A newer GitHub version exists.');
      } else {
        setOut('Showing selected snapshot for ' + item.path + '.');
      }
    }

    function setLoggedInUserLabel(data) {
      if (!data || !data.logged_in) {
        loggedInUserLabel.textContent = 'Logged in user: -';
        return;
      }
      const login = data.user_login || '';
      const userId = data.user_id || '';
      const name = data.user_name || '';
      if (login && userId) {
        loggedInUserLabel.textContent = 'Logged in user: ' + login + ' (id: ' + userId + ')' + (name ? ' - ' + name : '');
        return;
      }
      if (login) {
        loggedInUserLabel.textContent = 'Logged in user: ' + login + (name ? ' - ' + name : '');
        return;
      }
      loggedInUserLabel.textContent = 'Logged in user: authenticated (user lookup unavailable)';
    }

    async function sha256Hex(input) {
      const data = new TextEncoder().encode(input);
      const digest = await crypto.subtle.digest('SHA-256', data);
      const bytes = new Uint8Array(digest);
      let hex = '';
      for (const b of bytes) {
        hex += b.toString(16).padStart(2, '0');
      }
      return hex;
    }

    async function resolveUserLoginFromToken(token) {
      const res = await fetch('https://api.github.com/user', {
        headers: {
          'Accept': 'application/vnd.github+json',
          'Authorization': 'Bearer ' + token
        }
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error((data && data.message) ? data.message : 'Failed to resolve GitHub user from token');
      }
      if (!data || !data.login) {
        throw new Error('GitHub user response did not include login');
      }
      return data.login;
    }

    async function registerToken(token) {
      const userLogin = await resolveUserLoginFromToken(token);
      const tokenHash = await sha256Hex(userLogin + token);
      const res = await fetch('/api/token/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          access_token: token,
          token_hash: tokenHash
        })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to register token');
      }
      return data;
    }

    function parentPathOf(pathValue) {
      if (!pathValue) return '';
      const idx = pathValue.lastIndexOf('/');
      return idx < 0 ? '' : pathValue.slice(0, idx);
    }

    async function loadRepoEntries(owner, repo, ref, pathValue) {
      browseState.owner = owner || '';
      browseState.repo = repo || '';
      browseState.ref = ref || 'main';
      browseState.path = pathValue || '';
      clearSelect(entryList);
      clearFileContent();
      entryPathLabel.textContent = 'Path: /' + (browseState.path || '');
      setOut('Loading files/folders for ' + owner + '/' + repo + '...');
      try {
        const res = await fetch('/api/list-repo', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ owner, repo, ref, path: browseState.path })
        });
        const data = await res.json();
        if (!res.ok) {
          setOut(JSON.stringify(data, null, 2));
          return;
        }
        const entries = Array.isArray(data.entries) ? data.entries : [];
        const listItems = [];
        const currentPath = data.path || '';
        browseState.path = currentPath;
        entryPathLabel.textContent = 'Path: /' + (currentPath || '');

        if (currentPath !== '') {
          listItems.push({
            value: '.',
            label: '.',
            type: 'up',
            path: parentPathOf(currentPath)
          });
        }

        for (const entry of entries) {
          const name = entry && entry.name ? entry.name : '';
          const type = entry && entry.type ? entry.type : 'file';
          if (!name) continue;
          const nextPath = currentPath ? (currentPath + '/' + name) : name;
          listItems.push({
            value: name,
            label: type === 'dir' ? (name + '/') : name,
            type: type,
            path: nextPath
          });
        }

        fillSelect(entryList, listItems);
        if (entries.length === 0) {
          setOut('No files or folders found.');
          return;
        }
        setOut('Loaded ' + entries.length + ' entries from ' + owner + '/' + repo + '.');
      } catch (err) {
        setOut('Failed to load repo entries: ' + err.message);
      }
    }

    async function loadFileContent(owner, repo, ref, pathValue) {
      setOut('Loading file content for ' + pathValue + '...');
      try {
        const data = await fetchFileContentData(owner, repo, ref, pathValue);
        fileFullPath.textContent = 'Full Path: ' + (data.full_path || (owner + '/' + repo + '/' + pathValue));
        fileContent.value = typeof data.content === 'string' ? data.content : '';
        setOut('Loaded file content.');
      } catch (err) {
        setOut('Failed to load file content: ' + err.message);
      }
    }

    async function loadUserRepos() {
      setOut('Loading repositories...');
      try {
        const res = await fetch('/api/user/repos');
        const data = await res.json();
        if (!res.ok) {
          setOut(JSON.stringify(data, null, 2));
          return;
        }
        const repos = Array.isArray(data.repos) ? data.repos : [];
        if (repos.length === 0) {
          clearSelect(repoList);
          clearSelect(entryList);
          clearSelectedFiles();
          clearFileContent();
          entryPathLabel.textContent = 'Path: /';
          setOut('No repositories found for this user.');
          return;
        }
        fillSelect(repoList, repos.map((r) => ({
          value: r.full_name || (r.owner + '/' + r.repo),
          label: r.full_name || (r.owner + '/' + r.repo),
          owner: r.owner,
          repo: r.repo,
          ref: r.defaultRef || 'main'
        })));
        repoList.selectedIndex = 0;
        const first = repoList.options[0];
        await loadRepoEntries(first.dataset.owner, first.dataset.repo, first.dataset.ref || 'main', '');
      } catch (err) {
        setOut('Failed to load repositories: ' + err.message);
      }
    }

    async function refreshAuthStatus() {
      try {
        const res = await fetch('/api/auth/status');
        const data = await res.json();
        if (!res.ok) {
          return;
        }
        setLoggedInUserLabel(data);
        if (data.logged_in) {
          loginButton.disabled = true;
          setUpdateButtonsEnabled(true);
          setOut('Session already authenticated.');
          await loadUserRepos();
        } else {
          loginButton.disabled = false;
          setUpdateButtonsEnabled(false);
          clearSelect(repoList);
          clearSelect(entryList);
          clearSelectedFiles();
          entryPathLabel.textContent = 'Path: /';
          clearFileContent();
        }
      } catch (_) {}
    }

    async function pollStatus(flowId) {
      const res = await fetch('/auth/github/device/status?flow_id=' + encodeURIComponent(flowId));
      const data = await res.json();
      if (!res.ok) {
        setOut('Status error: ' + JSON.stringify(data, null, 2));
        return;
      }

      if (data.status === 'approved' && data.access_token) {
        try {
          await registerToken(data.access_token);
          loginButton.disabled = true;
          setOut('GitHub login approved.\nToken received in frontend and registered to backend.');
          await refreshAuthStatus();
          await loadUserRepos();
        } catch (err) {
          setOut('Token register failed: ' + err.message);
        }
        if (pollingTimer) {
          clearInterval(pollingTimer);
          pollingTimer = null;
        }
        return;
      }

      if (data.status === 'denied' || data.status === 'expired' || data.status === 'error') {
        setOut('Device flow ended with status "' + data.status + '".\n' + (data.error || ''));
        if (pollingTimer) {
          clearInterval(pollingTimer);
          pollingTimer = null;
        }
        return;
      }

      setOut(
        'Waiting for GitHub authorization...\n\n' +
        '1) Open: ' + data.verification_uri + '\n' +
        '2) Enter code: ' + data.user_code + '\n\n' +
        'Status: ' + data.status
      );
    }

    document.getElementById('login').addEventListener('click', async () => {
      if (pollingTimer) {
        clearInterval(pollingTimer);
        pollingTimer = null;
      }
      let usedRegularBrowser = false;
      try {
        const openRes = await fetch('/auth/github/device/open-browser', { method: 'POST' });
        const openData = await openRes.json();
        usedRegularBrowser = openRes.ok && !!openData.opened;
      } catch (_) {}

      let authTab = null;
      if (!usedRegularBrowser) {
        const uniqueTarget = 'github_device_' + Date.now() + '_' + Math.random().toString(36).slice(2);
        authTab = window.open('https://github.com/login/device', uniqueTarget, 'noopener,noreferrer');
      }
      try {
        const res = await fetch('/auth/github/device/start', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) {
          if (authTab && !authTab.closed) {
            authTab.close();
          }
          setOut(JSON.stringify(data, null, 2));
          return;
        }
        if (data.status === 'already_authenticated') {
          if (authTab && !authTab.closed) {
            authTab.close();
          }
          loginButton.disabled = true;
          setOut('Already logged in for this session.');
          await refreshAuthStatus();
          await loadUserRepos();
          return;
        }

        setOut(
          'Start device login:\n\n' +
          '1) Open: ' + data.verification_uri + '\n' +
          '2) Enter code: ' + data.user_code + '\n\n' +
          'Polling status...'
        );

        await pollStatus(data.flow_id);
        pollingTimer = setInterval(() => pollStatus(data.flow_id), 3000);
      } catch (err) {
        setOut('Start login failed: ' + err.message);
      }
    });

    repoList.addEventListener('change', async () => {
      const selected = repoList.selectedOptions[0];
      if (!selected) {
        clearSelect(entryList);
        entryPathLabel.textContent = 'Path: /';
        return;
      }
      await loadRepoEntries(selected.dataset.owner, selected.dataset.repo, selected.dataset.ref || 'main', '');
    });

    entryList.addEventListener('change', async () => {
      const selected = entryList.selectedOptions[0];
      if (!selected) return;
      const type = selected.dataset.type || '';
      if (type === 'dir' || type === 'up') {
        await loadRepoEntries(
          browseState.owner,
          browseState.repo,
          browseState.ref || 'main',
          selected.dataset.path || ''
        );
        return;
      }
      if (type === 'file') {
        await loadFileContent(
          browseState.owner,
          browseState.repo,
          browseState.ref || 'main',
          selected.dataset.path || ''
        );
      }
    });

    entryList.addEventListener('dblclick', async () => {
      const selected = entryList.selectedOptions[0];
      if (!selected) return;
      const type = selected.dataset.type || '';
      if (type !== 'file') return;
      await addSelectedFile(
        browseState.owner,
        browseState.repo,
        browseState.ref || 'main',
        selected.dataset.path || ''
      );
    });

    // Only modal selected-files list supports dblclick removal.
    selectedFilesListModal.addEventListener('dblclick', () => {
      const selected = selectedFilesListModal.selectedOptions[0];
      if (!selected) return;
      removeSelectedFileByKey(selected.value || '');
    });

    async function onSelectedFileListChange(sourceList, targetList) {
      const selected = sourceList.selectedOptions[0];
      if (!selected) return;
      const key = selected.value || '';
      if (targetList && key) {
        targetList.value = key;
      }
      const item = selectedFiles.get(key);
      if (item) {
        showSelectedFileSnapshot(item);
        return;
      }
      const parsed = parseSelectedKey(key);
      if (!parsed || !parsed.owner || !parsed.repo || !parsed.path) {
        setOut('Selected file entry is invalid.');
        return;
      }
      // Fallback only for legacy entries that might not exist in selectedFiles map.
      await loadFileContent(parsed.owner, parsed.repo, parsed.ref || 'main', parsed.path);
    }

    selectedFilesListBase.addEventListener('change', async () => {
      await onSelectedFileListChange(selectedFilesListBase, selectedFilesListModal);
    });
    selectedFilesListModal.addEventListener('change', async () => {
      await onSelectedFileListChange(selectedFilesListModal, selectedFilesListBase);
    });

    sortSelectedBaseButton.addEventListener('click', () => {
      sortSelectedFiles();
    });
    sortSelectedModalButton.addEventListener('click', () => {
      sortSelectedFiles();
    });

    checkUpdatesBaseButton.addEventListener('click', async () => {
      await checkSelectedFilesForUpdates();
    });
    checkUpdatesModalButton.addEventListener('click', async () => {
      await checkSelectedFilesForUpdates();
    });

    applyUpdatesBaseButton.addEventListener('click', async () => {
      await applySelectedFileUpdates();
    });
    applyUpdatesModalButton.addEventListener('click', async () => {
      await applySelectedFileUpdates();
    });

    openModalButton.addEventListener('click', openModal);
    document.getElementById('importTop').addEventListener('click', openModal);
    document.getElementById('importBottom').addEventListener('click', openModal);
    document.getElementById('cancelTop').addEventListener('click', closeModal);
    document.getElementById('cancelBottom').addEventListener('click', closeModal);

    document.getElementById('loadRepos').addEventListener('click', loadUserRepos);

    document.getElementById('listRepo').addEventListener('click', async () => {
      const selected = repoList.selectedOptions[0];
      if (!selected) {
        setOut('Select a repository first.');
        return;
      }
      await loadRepoEntries(selected.dataset.owner, selected.dataset.repo, selected.dataset.ref || 'main', '');
    });

    document.getElementById('checkAuth').addEventListener('click', async () => {
      try {
        const res = await fetch('/api/auth/status');
        const data = await res.json();
        if (!res.ok) {
          setOut(JSON.stringify(data, null, 2));
          return;
        }
        setLoggedInUserLabel(data);
        if (data.logged_in) {
          setOut('GitHub login status: LOGGED IN');
        } else {
          setOut('GitHub login status: NOT LOGGED IN\nUse "Log in to GitHub" first.');
        }
      } catch (err) {
        setOut('Auth status request failed: ' + err.message);
      }
    });

    document.getElementById('clearMemToken').addEventListener('click', async () => {
      try {
        const res = await fetch('/api/token/clear-memory', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) {
          setOut(JSON.stringify(data, null, 2));
          return;
        }
        setOut('Cleared encrypted token from memory cache for current user.');
        await refreshAuthStatus();
      } catch (err) {
        setOut('Clear memory cache failed: ' + err.message);
      }
    });

    document.getElementById('clearAllToken').addEventListener('click', async () => {
      try {
        const res = await fetch('/api/token/clear-all', { method: 'POST' });
        const data = await res.json();
        if (!res.ok) {
          setOut(JSON.stringify(data, null, 2));
          return;
        }
        clearSelect(repoList);
        clearSelect(entryList);
        clearSelectedFiles();
        clearFileContent();
        entryPathLabel.textContent = 'Path: /';
        setOut('Cleared encrypted token from memory cache and SQLite DB for current user.');
        await refreshAuthStatus();
      } catch (err) {
        setOut('Clear memory+db failed: ' + err.message);
      }
    });

    refreshAuthStatus();
  </script>
</body>
</html>`
