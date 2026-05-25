# GitHub Repo File Lister (Go + GitHub Device Flow)

This app starts a Go backend, opens the UI in an incognito/private browser window, uses GitHub OAuth Device Flow (no client secret), and lets the UI load your repositories in one listbox. Clicking a repository loads its files/folders into a second listbox.

## What you need

1. A GitHub OAuth App (`Settings -> Developer settings -> OAuth Apps -> New OAuth App`)
2. In that OAuth app, enable **Device Flow**
3. Environment variables:
   - `GITHUB_CLIENT_ID`
   - `AUTH_TOKEN_ENCRYPTION_KEY`
4. Optional environment variables:
   - `GITHUB_REPO_OWNER` (fallback only when no repo is selected from UI)
   - `GITHUB_REPO_NAME` (fallback only when no repo is selected from UI)
   - `GITHUB_REPO_REF` (default: `main`)
   - `GITHUB_OAUTH_SCOPE` (default: `repo`)
   - `AUTH_TOKEN_SQLITE_FILE` (default: `auth_tokens.db`)
   - `SERVER_ADDR` (default: `:8080`)
5. A local browser installed with private mode support (Chrome/Chromium/Edge/Firefox)

## Run

```bash
export GITHUB_CLIENT_ID="your_client_id"
export AUTH_TOKEN_ENCRYPTION_KEY="your_secret_key"
export GITHUB_REPO_REF="main"
export GITHUB_OAUTH_SCOPE="repo"

go run .
```

## SQL Schema

- Token table schema is available at: `sql/create_auth_tokens.sql`

## Endpoints

- `GET /` UI with:
  - `Log in to GitHub`
  - `Load My Repos`
  - `Load Selected Repo`
  - `Clear Token Memory Cache`
  - `Clear Token Memory + DB`
- `GET /api/auth/status` returns whether session already has a token
- `GET /api/user/repos` returns repos available to the logged-in user token
- `POST /api/token/clear-memory` clears encrypted token cache in memory for current user
- `POST /api/token/clear-all` clears encrypted token from memory and SQLite for current user
- `POST /auth/github/device/open-browser` opens `https://github.com/login/device` in regular browser (non-incognito), useful for reusing existing GitHub login
- `POST /auth/github/device/start` starts device flow and returns device/user codes
- `GET /auth/github/device/status?flow_id=...` returns device flow status and token when approved
- `POST /api/token/register` receives token from frontend, resolves user, encrypts token, stores encrypted token in SQLite and encrypted in-memory cache keyed by `userId`
- `POST /api/list-repo` returns JSON with `entries` (file/folder names). Optional body:
  - `owner`
  - `repo`
  - `ref`
  - `path`
- `POST /api/file-content` returns file content for a selected file path

## Behavior

- On startup, backend tries to open `http://localhost:8080` in incognito/private mode.
- After successful login:
  - frontend gets `verification_uri` + `user_code`
  - user authorizes in GitHub device page
  - backend polls GitHub token endpoint
  - frontend polls backend status
  - frontend receives token in status response
  - frontend resolves `userlogin`, computes `sha256(userlogin + token)`, and sends both token and hash to backend (`/api/token/register`)
  - token is encrypted and stored in SQLite file (default `auth_tokens.db`)
  - encrypted token is cached in memory map keyed by `userId`
  - hash is stored in the same SQLite row and cached in memory map keyed by `userlogin`
- when token is needed by backend:
  - check encrypted in-memory cache by `userId`
  - if missing in memory, load encrypted token from SQLite and cache it in memory
  - decrypt token
  - verify `sha256(userlogin + decryptedToken)` matches stored hash before any outgoing GitHub call
  - use token only if hash verification passes
- when a repository is selected, backend calls GitHub contents API and fills files/folders listbox
- clicking a folder in files/folders listbox loads that folder content
- when inside a subfolder, a `.` entry is shown at the top to navigate up one level
- current content path is shown above the files/folders listbox
- clicking a file loads content in the resizable content area below listboxes
- full path (`owner/repo/path`) is shown above file content area

## Troubleshooting

- If `POST /auth/github/device/start` returns `{"error":"github device code endpoint status 404: {\"error\":\"Not Found\"}"}`, verify that Device Flow is enabled in the GitHub OAuth app settings.
