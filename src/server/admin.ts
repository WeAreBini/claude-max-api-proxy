/**
 * Admin setup UI and diagnostics endpoints.
 *
 * Implements a direct OAuth PKCE flow against Claude.ai so that
 * headless hosts (Railway, Docker, etc.) can authenticate without
 * needing a local browser or PTY. The proxy builds the authorization
 * URL, the operator opens it in *any* browser, pastes the resulting
 * auth code back, and the proxy exchanges it for tokens and writes
 * them where the CLI expects them.
 */

import crypto from "crypto";
import os from "os";
import path from "path";
import fs from "fs/promises";
import type { Request, Response } from "express";
import {
  getClaudeAuthStatus,
  verifyClaude,
} from "../subprocess/manager.js";

/* ------------------------------------------------------------------ */
/*  OAuth constants (extracted from Claude Code CLI v2.1.72 source)    */
/* ------------------------------------------------------------------ */

const OAUTH_CLIENT_ID =
  process.env.CLAUDE_CODE_OAUTH_CLIENT_ID || "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const OAUTH_AUTHORIZE_URL = "https://claude.ai/oauth/authorize";
const OAUTH_TOKEN_URL = "https://platform.claude.com/v1/oauth/token";
const OAUTH_MANUAL_REDIRECT_URL = "https://platform.claude.com/oauth/code/callback";
const OAUTH_SCOPES = [
  "user:inference",
  "user:profile",
  "org:create_api_key",
  "user:sessions:claude_code",
  "user:mcp_servers",
];

/* ------------------------------------------------------------------ */
/*  PKCE helpers                                                       */
/* ------------------------------------------------------------------ */

function generateCodeVerifier(): string {
  return crypto.randomBytes(32).toString("base64url");
}

function computeCodeChallenge(verifier: string): string {
  return crypto.createHash("sha256").update(verifier).digest("base64url");
}

/* ------------------------------------------------------------------ */
/*  Credential file helpers                                            */
/* ------------------------------------------------------------------ */

function getClaudeConfigDir(): string {
  return (process.env.CLAUDE_CONFIG_DIR ?? path.join(os.homedir(), ".claude"));
}

function getCredentialsPath(): string {
  return path.join(getClaudeConfigDir(), ".credentials.json");
}

interface StoredCredentials {
  claudeAiOauth?: {
    accessToken: string;
    refreshToken: string | null;
    expiresAt: number;
    scopes: string[];
    subscriptionType: string | null;
    rateLimitTier: string | null;
  };
  [key: string]: unknown;
}

async function readStoredCredentials(): Promise<StoredCredentials | null> {
  try {
    const raw = await fs.readFile(getCredentialsPath(), "utf8");
    return JSON.parse(raw) as StoredCredentials;
  } catch {
    return null;
  }
}

async function writeStoredCredentials(creds: StoredCredentials): Promise<void> {
  const dir = getClaudeConfigDir();
  await fs.mkdir(dir, { recursive: true });
  const filePath = getCredentialsPath();
  await fs.writeFile(filePath, JSON.stringify(creds), { encoding: "utf8", mode: 0o600 });
}

/* ------------------------------------------------------------------ */
/*  Token exchange                                                     */
/* ------------------------------------------------------------------ */

interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  token_type?: string;
}

async function exchangeCodeForTokens(
  authCode: string,
  codeVerifier: string,
  state: string,
): Promise<TokenResponse> {
  const body = {
    grant_type: "authorization_code",
    code: authCode,
    redirect_uri: OAUTH_MANUAL_REDIRECT_URL,
    client_id: OAUTH_CLIENT_ID,
    code_verifier: codeVerifier,
    state,
  };

  console.log(`[oauth] Token exchange POST ${OAUTH_TOKEN_URL}`);
  console.log(`[oauth]   client_id: ${body.client_id}`);
  console.log(`[oauth]   redirect_uri: ${body.redirect_uri}`);
  console.log(`[oauth]   code length: ${body.code.length}`);
  console.log(`[oauth]   code_verifier length: ${body.code_verifier.length}`);
  console.log(`[oauth]   state length: ${body.state.length}`);

  const res = await fetch(OAUTH_TOKEN_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  });

  console.log(`[oauth] Token endpoint responded: ${res.status}`);

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    console.log(`[oauth] Error body: ${text}`);
    if (res.status === 401) {
      throw new Error("Authentication failed: invalid or expired authorization code.");
    }
    throw new Error(`Token exchange failed (${res.status}): ${text}`);
  }

  const data = (await res.json()) as Record<string, unknown>;
  if (!data.access_token) {
    throw new Error(`Token response missing access_token: ${JSON.stringify(data)}`);
  }
  return data as unknown as TokenResponse;
}

/* ------------------------------------------------------------------ */
/*  Auth-code extraction (accepts raw code, callback URL, or query)    */
/* ------------------------------------------------------------------ */

const AUTH_CODE_PATTERN = /(?:^|[?&#])code=([^&#\s]+)/i;

function extractAuthCode(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) throw new Error("Auth code is required");

  // If pasted as a URL, extract the code query parameter.
  if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
    try {
      const codeFromUrl = new URL(trimmed).searchParams.get("code")?.trim();
      if (codeFromUrl) return splitCodeFromState(codeFromUrl);
    } catch { /* fall through */ }
  }

  const match = trimmed.match(AUTH_CODE_PATTERN);
  if (match?.[1]) return splitCodeFromState(decodeURIComponent(match[1]).trim());

  return splitCodeFromState(trimmed);
}

/**
 * The callback page shows the value as CODE#STATE.
 * The CLI splits on '#' and only uses the code portion.
 * Strip the state suffix so we send only the auth code.
 */
function splitCodeFromState(value: string): string {
  const idx = value.indexOf("#");
  return idx >= 0 ? value.slice(0, idx) : value;
}

/* ------------------------------------------------------------------ */
/*  OAuth session (in-memory state for a single login attempt)         */
/* ------------------------------------------------------------------ */

type LoginPhase =
  | "idle"
  | "waiting_for_code"
  | "exchanging"
  | "succeeded"
  | "failed";

interface LoginSnapshot {
  readonly phase: LoginPhase;
  readonly authUrl: string | null;
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
  readonly error: string | null;
  readonly logs: readonly string[];
}

interface ConfigDirectorySummary {
  readonly path: string;
  readonly exists: boolean;
  readonly entries: readonly string[];
}

const MAX_LOG_LINES = 80;

class OAuthLoginSession {
  private phase: LoginPhase = "idle";
  private codeVerifier: string | null = null;
  private state: string | null = null;
  private authUrl: string | null = null;
  private startedAt: string | null = null;
  private finishedAt: string | null = null;
  private error: string | null = null;
  private logs: string[] = [];

  getSnapshot(): LoginSnapshot {
    return {
      phase: this.phase,
      authUrl: this.authUrl,
      startedAt: this.startedAt,
      finishedAt: this.finishedAt,
      error: this.error,
      logs: [...this.logs],
    };
  }

  /** Generate PKCE pair and build the Claude.ai authorization URL. */
  start(): LoginSnapshot {
    this.reset();
    this.codeVerifier = generateCodeVerifier();
    this.state = crypto.randomBytes(16).toString("hex");
    const challenge = computeCodeChallenge(this.codeVerifier);

    const url = new URL(OAUTH_AUTHORIZE_URL);
    url.searchParams.set("code", "true");
    url.searchParams.set("client_id", OAUTH_CLIENT_ID);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("redirect_uri", OAUTH_MANUAL_REDIRECT_URL);
    url.searchParams.set("scope", OAUTH_SCOPES.join(" "));
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");
    url.searchParams.set("state", this.state);

    this.authUrl = url.toString();
    this.phase = "waiting_for_code";
    this.startedAt = new Date().toISOString();
    this.log("[oauth] Generated PKCE pair and authorization URL");
    return this.getSnapshot();
  }

  /** Exchange an authorization code for tokens and write credentials. */
  async submit(rawCode: string): Promise<LoginSnapshot> {
    if (this.phase !== "waiting_for_code") {
      throw new Error(
        this.phase === "exchanging"
          ? "Token exchange already in progress."
          : "Start a new login first.",
      );
    }
    if (!this.codeVerifier || !this.state) {
      throw new Error("No active PKCE session — start a new login.");
    }

    const code = extractAuthCode(rawCode);
    const redacted = code.length > 12
      ? `${code.slice(0, 6)}…${code.slice(-4)} (${code.length} chars)`
      : `(${code.length} chars)`;
    this.log(`[oauth] Raw input length: ${rawCode.trim().length}, extracted code: ${redacted}`);
    if (rawCode.trim() !== code) {
      this.log(`[oauth] Input was transformed (URL/param extraction applied)`);
    }
    this.phase = "exchanging";
    this.error = null;
    this.log("[oauth] Exchanging authorization code for tokens (this can take up to 30 seconds)…");

    try {
      const tokens = await exchangeCodeForTokens(code, this.codeVerifier, this.state);
      this.log("[oauth] Token exchange succeeded");

      const expiresIn = tokens.expires_in ?? 3600;
      const scopes = tokens.scope?.split(" ").filter(Boolean) ?? [...OAUTH_SCOPES];
      const existing = await readStoredCredentials();
      const creds: StoredCredentials = existing ?? {};
      creds.claudeAiOauth = {
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token ?? null,
        expiresAt: Date.now() + expiresIn * 1000,
        scopes,
        subscriptionType: null,
        rateLimitTier: null,
      };
      await writeStoredCredentials(creds);
      this.log(`[oauth] Credentials written to ${getCredentialsPath()}`);

      this.phase = "succeeded";
      this.finishedAt = new Date().toISOString();
      this.log("[oauth] Login complete");
      return this.getSnapshot();
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.phase = "failed";
      this.error = message;
      this.finishedAt = new Date().toISOString();
      this.log(`[oauth] ${message}`);
      return this.getSnapshot();
    }
  }

  cancel(): LoginSnapshot {
    if (this.phase === "waiting_for_code" || this.phase === "failed") {
      this.log("[oauth] Login cancelled");
      this.reset();
    }
    return this.getSnapshot();
  }

  /** If auth is already valid (e.g. via env var), upgrade phase. */
  reconcile(loggedIn: boolean): void {
    if (loggedIn && this.phase !== "succeeded") {
      this.phase = "succeeded";
      this.finishedAt ??= new Date().toISOString();
      this.log("[oauth] Already authenticated (detected via CLI status)");
    }
  }

  private reset(): void {
    this.phase = "idle";
    this.codeVerifier = null;
    this.state = null;
    this.authUrl = null;
    this.startedAt = null;
    this.finishedAt = null;
    this.error = null;
    this.logs = [];
  }

  private log(msg: string): void {
    this.logs.push(msg);
    if (this.logs.length > MAX_LOG_LINES) {
      this.logs = this.logs.slice(-MAX_LOG_LINES);
    }
  }
}

const loginSession = new OAuthLoginSession();

/* ------------------------------------------------------------------ */
/*  Admin auth & status helpers                                        */
/* ------------------------------------------------------------------ */

function getAdminTokenFromRequest(req: Request): string | null {
  const bearerToken = req.header("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
  const headerToken = req.header("x-admin-token");
  const queryToken = typeof req.query.token === "string" ? req.query.token : null;
  return bearerToken ?? headerToken ?? queryToken;
}

function isAdminAuthorized(req: Request): boolean {
  const configuredToken = process.env.ADMIN_TOKEN;
  if (!configuredToken) return true;
  return getAdminTokenFromRequest(req) === configuredToken;
}

function requireAdmin(req: Request, res: Response): boolean {
  if (isAdminAuthorized(req)) return true;
  res.status(401).json({
    error: { message: "Unauthorized", type: "authentication_error", code: "admin_token_required" },
  });
  return false;
}

async function getConfigDirectorySummary(): Promise<ConfigDirectorySummary> {
  const configDir = getClaudeConfigDir();
  try {
    const entries = await fs.readdir(configDir);
    return { path: configDir, exists: true, entries: entries.sort() };
  } catch {
    return { path: configDir, exists: false, entries: [] };
  }
}

async function buildSetupStatus(req: Request) {
  const [cliStatus, authStatus, configDirectory] = await Promise.all([
    verifyClaude(),
    getClaudeAuthStatus(),
    getConfigDirectorySummary(),
  ]);

  loginSession.reconcile(authStatus.loggedIn);

  const runtimeHostHeader = req.get("host") || "127.0.0.1:3456";
  const hostParts = runtimeHostHeader.split(":");
  const runtimePort = hostParts.length > 1 ? hostParts[hostParts.length - 1] : process.env.PORT || "3456";
  const runtimeHost = hostParts.length > 1 ? hostParts.slice(0, -1).join(":") || "127.0.0.1" : runtimeHostHeader;

  return {
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    runtime: {
      nodeVersion: process.version,
      platform: process.platform,
      host: runtimeHost,
      port: runtimePort,
      adminTokenConfigured: Boolean(process.env.ADMIN_TOKEN),
      dangerousSkipPermissions: process.env.CLAUDE_DANGEROUSLY_SKIP_PERMISSIONS === "true",
      corsAllowOrigin: process.env.CORS_ALLOW_ORIGIN || "*",
    },
    claudeCli: cliStatus,
    auth: authStatus,
    configDirectory,
    credentialsFile: getCredentialsPath(),
    envTokens: {
      oauthTokenConfigured: Boolean(process.env.CLAUDE_CODE_OAUTH_TOKEN),
      oauthFdConfigured: Boolean(process.env.CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR),
      anthropicApiKeyConfigured: Boolean(process.env.ANTHROPIC_API_KEY),
    },
    loginFlow: loginSession.getSnapshot(),
  };
}

function renderSetupPage(req: Request): string {
  const token = typeof req.query.token === "string" ? req.query.token : "";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Claude Max Proxy Setup</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f3efe6;
      --panel: rgba(255, 252, 246, 0.94);
      --panel-strong: #fffdf7;
      --line: #d8cfbf;
      --text: #1f1a14;
      --muted: #6b6258;
      --accent: #0c7a6b;
      --accent-strong: #085f54;
      --accent-soft: #dff3ee;
      --good: #176b45;
      --bad: #a5382a;
      --warn: #946200;
      --shadow: 0 18px 36px rgba(63, 44, 15, 0.08);
      --code: #1d3a4a;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh;
      font-family: "IBM Plex Sans", "Avenir Next", "Segoe UI", sans-serif;
      background: radial-gradient(circle at top left, rgba(12,122,107,0.08), transparent 28%),
                  linear-gradient(180deg, #f8f4ec 0%, var(--bg) 100%);
      color: var(--text);
    }
    main { max-width: 920px; margin: 0 auto; padding: 24px 16px 48px; }
    .hero, .panel {
      border: 1px solid var(--line);
      background: linear-gradient(180deg, var(--panel) 0%, var(--panel-strong) 100%);
      border-radius: 22px; box-shadow: var(--shadow); backdrop-filter: blur(8px);
    }
    .hero { padding: 24px; margin-bottom: 16px; }
    h1 { margin: 0; font-size: clamp(2rem,5vw,3.25rem); line-height: 0.95; letter-spacing: -0.04em; }
    h2 { margin: 0 0 14px; font-size: 1.1rem; letter-spacing: -0.02em; }
    p, li, dd, dt, summary, label { line-height: 1.55; }
    p { margin: 0; }
    .eyebrow { display: inline-block; margin-bottom: 10px; font-size: 0.8rem; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--muted); }
    .lead { margin-top: 10px; max-width: 60ch; color: var(--muted); }
    .banner { display: none; margin-top: 18px; padding: 14px 16px; border-radius: 16px; border: 1px solid transparent; font-weight: 600; }
    .banner.visible { display: block; }
    .banner.good { color: var(--good); border-color: rgba(23,107,69,0.18); background: rgba(23,107,69,0.08); }
    .banner.warn { color: var(--warn); border-color: rgba(148,98,0,0.18); background: rgba(255,216,140,0.22); }
    .banner.bad  { color: var(--bad);  border-color: rgba(165,56,42,0.18); background: rgba(165,56,42,0.08); }
    .chip-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 10px; margin-top: 18px; }
    .chip { padding: 14px; border: 1px solid var(--line); border-radius: 16px; background: rgba(255,255,255,0.55); }
    .good { color: var(--good); } .bad { color: var(--bad); } .warn { color: var(--warn); }
    .chip-label { display: block; margin-bottom: 6px; color: var(--muted); font-size: 0.84rem; }
    .chip strong { font-size: 1rem; }
    .panel { padding: 20px; margin-bottom: 16px; }
    .actions, .input-row, .url-actions, .row { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
    .steps { list-style: none; padding: 0; margin: 0; display: grid; gap: 14px; }
    .step { padding: 16px; border: 1px solid var(--line); border-radius: 18px; background: rgba(255,255,255,0.5); }
    .step-head { display: flex; gap: 12px; align-items: flex-start; justify-content: space-between; margin-bottom: 10px; }
    .step-number { display: inline-flex; align-items: center; justify-content: center; width: 30px; height: 30px; border-radius: 999px; background: var(--accent-soft); color: var(--accent-strong); font-weight: 700; flex: none; }
    .step-title { font-weight: 700; font-size: 1.05rem; }
    .step-status { padding: 4px 10px; border-radius: 999px; background: #efe6d8; color: var(--muted); font-size: 0.85rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; }
    .step-status.good { background: rgba(23,107,69,0.1); color: var(--good); }
    .step-status.warn { background: rgba(255,216,140,0.35); color: var(--warn); }
    .step-copy { display: grid; gap: 8px; color: var(--muted); }
    button { border: 1px solid transparent; border-radius: 14px; padding: 12px 16px; font: inherit; font-weight: 700; background: var(--accent); color: #f7f4ec; cursor: pointer; transition: transform 160ms ease, box-shadow 160ms ease; box-shadow: 0 8px 18px rgba(12,122,107,0.16); }
    button.secondary { background: transparent; color: var(--text); border-color: var(--line); box-shadow: none; }
    button:hover:not(:disabled), button:focus-visible:not(:disabled) { transform: translateY(-1px); box-shadow: 0 12px 22px rgba(12,122,107,0.18); }
    button:disabled { opacity: 0.45; cursor: not-allowed; }
    button:focus-visible, input:focus-visible, a:focus-visible, summary:focus-visible { outline: 3px solid rgba(12,122,107,0.32); outline-offset: 2px; }
    label { display: block; margin-bottom: 8px; color: var(--muted); font-size: 0.95rem; }
    input[type="text"] { flex: 1 1 320px; min-width: 0; border: 1px solid var(--line); border-radius: 14px; padding: 14px 16px; font: inherit; background: rgba(255,255,255,0.82); color: var(--text); }
    code, pre { font-family: "IBM Plex Mono", SFMono-Regular, Menlo, Monaco, Consolas, monospace; color: var(--code); }
    code { padding: 0.1em 0.35em; border-radius: 0.4em; background: rgba(12,122,107,0.08); }
    pre { margin: 14px 0 0; padding: 16px; border-radius: 14px; border: 1px solid var(--line); background: #fffdf8; white-space: pre-wrap; word-break: break-word; max-height: 280px; overflow: auto; }
    .url-box { display: grid; gap: 10px; padding: 16px; background: rgba(223,243,238,0.6); border-radius: 14px; border: 1px solid rgba(12,122,107,0.14); }
    .url-box.hidden { display: none; }
    .link-box { display: block; padding: 12px 14px; border-radius: 12px; border: 1px solid var(--line); background: rgba(255,255,255,0.85); word-break: break-all; }
    .hint, .muted { color: var(--muted); font-size: 0.95rem; }
    dl { margin: 0; }
    .kv, .state-list { display: grid; grid-template-columns: minmax(140px,180px) 1fr; gap: 8px 12px; font-size: 0.97rem; }
    .kv dt, .state-list dt { color: var(--muted); }
    summary { cursor: pointer; font-weight: 700; }
    details[open] summary { margin-bottom: 14px; }
    @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important; scroll-behavior: auto !important; } }
    @media (max-width: 640px) { .chip-row, .kv, .state-list { grid-template-columns: 1fr; } .hero, .panel, .step { border-radius: 18px; } .step-head { flex-direction: column; } }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="eyebrow">Claude Max Proxy</div>
      <h1>Setup</h1>
      <p class="lead">Authenticate this server with your Claude Max account. The login uses the same OAuth flow Claude Code CLI uses, but runs entirely through this page so it works on headless hosts like Railway.</p>
      <div id="statusBanner" class="banner" role="status" aria-live="polite"></div>
      <div id="summaryChips" class="chip-row" aria-live="polite"></div>
    </section>

    <section class="panel" aria-labelledby="setup-steps-title">
      <h2 id="setup-steps-title">Login steps</h2>
      <ol class="steps">
        <li class="step">
          <div class="step-head">
            <div class="row">
              <span class="step-number">1</span>
              <div>
                <div class="step-title">Generate login link</div>
                <div class="step-copy">Creates a one-time sign-in URL tied to this server.</div>
              </div>
            </div>
            <span id="stepStartStatus" class="step-status">Idle</span>
          </div>
          <div class="actions">
            <button id="startButton">Generate Login Link</button>
            <button id="cancelButton" class="secondary">Reset</button>
          </div>
        </li>
        <li class="step">
          <div class="step-head">
            <div class="row">
              <span class="step-number">2</span>
              <div>
                <div class="step-title">Sign in on Claude.ai</div>
                <div class="step-copy">Open the link below in any browser (your phone, laptop, etc.), sign in with your Claude Max account, and copy the code shown after sign-in.</div>
              </div>
            </div>
            <span id="stepLinkStatus" class="step-status">Waiting</span>
          </div>
          <div id="authUrlBox" class="url-box hidden" aria-live="polite">
            <a id="authUrlLink" class="link-box" href="#" target="_blank" rel="noreferrer"></a>
            <div class="url-actions">
              <button id="copyAuthLinkButton" class="secondary">Copy Link</button>
            </div>
          </div>
          <p id="authUrlEmptyState" class="hint">Click "Generate Login Link" first.</p>
        </li>
        <li class="step">
          <div class="step-head">
            <div class="row">
              <span class="step-number">3</span>
              <div>
                <div class="step-title">Paste the auth code</div>
                <div class="step-copy">After signing in, Claude shows a code (or redirects to a URL containing the code). Paste it below. The server exchanges it for tokens and writes credentials so the CLI can use them.</div>
              </div>
            </div>
            <span id="stepSubmitStatus" class="step-status">Waiting</span>
          </div>
          <label for="authCode">Auth code or callback URL</label>
          <div class="input-row">
            <input id="authCode" type="text" placeholder="Paste the code or the full callback URL here" autocomplete="off" />
            <button id="submitCodeButton">Submit Code</button>
          </div>
          <p class="hint">Pasting the full callback URL also works — the code is extracted automatically.</p>
        </li>
      </ol>
    </section>

    <section class="panel" aria-labelledby="state-title">
      <h2 id="state-title">Current state</h2>
      <dl id="currentState" class="state-list"></dl>
    </section>

    <details class="panel">
      <summary>Diagnostics</summary>
      <p class="muted">After login, point your OpenAI-compatible client at <code>/v1</code> on this server.</p>
      <dl id="details" class="kv" style="margin-top: 14px;"></dl>
      <pre id="logOutput">Waiting for status...</pre>
    </details>
  </main>

  <script>
    const token = ${JSON.stringify(token)};
    const statusUrl = token ? '/api/setup/status?token=' + encodeURIComponent(token) : '/api/setup/status';
    let lastStatus = null;
    let isBusy = false;

    const byId = (id) => document.getElementById(id);
    const esc = (v) => String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    const apiUrl = (p) => token ? p + '?token=' + encodeURIComponent(token) : p;

    function setBanner(msg, tone) { const b = byId('statusBanner'); b.textContent = msg; b.className = 'banner visible ' + tone; }
    function clearBanner() { const b = byId('statusBanner'); b.textContent = ''; b.className = 'banner'; }

    function setBusy(next) {
      isBusy = next;
      const s = lastStatus;
      const phase = s?.loginFlow?.phase || 'idle';
      const loggedIn = !!s?.auth?.loggedIn;
      byId('startButton').disabled   = next || phase === 'waiting_for_code' || phase === 'exchanging' || loggedIn;
      byId('cancelButton').disabled   = next || (phase !== 'waiting_for_code' && phase !== 'failed');
      byId('submitCodeButton').disabled = next || phase !== 'waiting_for_code';
      byId('copyAuthLinkButton').disabled = next || !s?.loginFlow?.authUrl;
    }

    async function callApi(path, method = 'GET', body) {
      const r = await fetch(apiUrl(path), {
        method,
        headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Admin-Token': token } : {}) },
        body: body ? JSON.stringify(body) : undefined,
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d?.error?.message || 'Request failed ' + r.status);
      return d;
    }

    function renderSummary(s) {
      const a = s.auth;
      const chips = [
        { l: 'CLI', v: s.claudeCli.ok ? 'Installed' : 'Missing', c: s.claudeCli.ok ? 'good' : 'bad' },
        { l: 'Auth', v: a.loggedIn ? 'Logged in' : 'Not logged in', c: a.loggedIn ? 'good' : 'warn' },
        { l: 'Account', v: a.email || '-', c: a.loggedIn ? 'good' : '' },
        { l: 'Subscription', v: a.subscriptionType || '-', c: a.loggedIn ? 'good' : '' },
      ];
      byId('summaryChips').innerHTML = chips.map(i =>
        '<div class="chip"><span class="chip-label">' + esc(i.l) + '</span><strong' + (i.c ? ' class="' + i.c + '"' : '') + '>' + esc(i.v) + '</strong></div>'
      ).join('');
    }

    function renderDetails(s) {
      const rows = [
        ['Host', s.runtime.host + ':' + s.runtime.port],
        ['CLI version', s.claudeCli.version || '-'],
        ['Auth method', s.auth.authMethod || '-'],
        ['API provider', s.auth.apiProvider || '-'],
        ['Config dir', s.configDirectory.path + (s.configDirectory.exists ? '' : ' (missing)')],
        ['Credentials file', s.credentialsFile || '-'],
        ['Admin token', s.runtime.adminTokenConfigured ? 'yes' : 'no'],
        ['OAuth env token', String(s.envTokens.oauthTokenConfigured)],
        ['Anthropic API key', String(s.envTokens.anthropicApiKeyConfigured)],
      ];
      byId('details').innerHTML = rows.map(([k, v]) => '<dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd>').join('');
    }

    function updateStep(id, label, tone) {
      const el = byId(id);
      el.textContent = label;
      el.className = tone ? 'step-status ' + tone : 'step-status';
    }

    function renderState(s) {
      const lf = s.loginFlow;
      const entries = [
        ['Phase', lf.phase],
        ['Logged in', s.auth.loggedIn ? 'yes' : 'no'],
        ['Started', lf.startedAt || '-'],
        ['Finished', lf.finishedAt || '-'],
      ];
      if (s.auth.email) entries.push(['Account', s.auth.email]);
      if (lf.error) entries.push(['Error', lf.error]);
      byId('currentState').innerHTML = entries.map(([k,v]) => '<dt>' + esc(k) + '</dt><dd>' + esc(v) + '</dd>').join('');
    }

    function renderFlow(s) {
      lastStatus = s;
      const lf = s.loginFlow;
      const urlBox = byId('authUrlBox');
      const urlLink = byId('authUrlLink');
      const empty = byId('authUrlEmptyState');

      if (lf.authUrl) {
        urlBox.classList.remove('hidden'); empty.style.display = 'none';
        urlLink.href = lf.authUrl; urlLink.textContent = lf.authUrl;
      } else {
        urlBox.classList.add('hidden'); empty.style.display = 'block';
        urlLink.href = '#'; urlLink.textContent = '';
      }
      byId('logOutput').textContent = lf.logs.join('\\n') || 'No log output yet.';

      updateStep('stepStartStatus',
        s.auth.loggedIn ? 'Done' : lf.authUrl ? 'Ready' : 'Idle',
        s.auth.loggedIn ? 'good' : lf.authUrl ? 'good' : '');
      updateStep('stepLinkStatus',
        s.auth.loggedIn ? 'Done' : lf.authUrl ? 'Open link' : 'Waiting',
        s.auth.loggedIn || lf.authUrl ? 'good' : '');
      updateStep('stepSubmitStatus',
        s.auth.loggedIn ? 'Done'
          : lf.phase === 'exchanging' ? 'Exchanging'
          : lf.phase === 'waiting_for_code' ? 'Ready'
          : 'Waiting',
        s.auth.loggedIn ? 'good' : lf.phase === 'exchanging' ? 'warn' : lf.phase === 'waiting_for_code' ? 'warn' : '');

      if (s.auth.loggedIn) {
        setBanner('Authenticated! Point your OpenAI client at /v1 on this server.', 'good');
      } else if (lf.phase === 'exchanging') {
        setBanner('Exchanging auth code for tokens...', 'warn');
      } else if (lf.phase === 'waiting_for_code' && lf.authUrl) {
        setBanner('Open the login link in any browser, sign in, and paste the code below.', 'warn');
      } else if (lf.phase === 'failed') {
        setBanner(lf.error || 'Login failed. Click "Generate Login Link" to try again.', 'bad');
      } else { clearBanner(); }

      setBusy(isBusy);
    }

    async function refreshStatus() {
      const r = await fetch(statusUrl, { headers: token ? { 'X-Admin-Token': token } : {} });
      const s = await r.json();
      if (!r.ok) throw new Error(s?.error?.message || 'Failed to load');
      renderSummary(s); renderState(s); renderDetails(s); renderFlow(s);
    }

    async function run(action, msg) {
      try { setBusy(true); clearBanner(); await action(); await refreshStatus(); if (msg) setBanner(msg, 'good'); }
      catch (e) { const m = e instanceof Error ? e.message : 'Failed'; setBanner(m, 'bad'); }
      finally { setBusy(false); }
    }

    byId('startButton').addEventListener('click', () => run(
      () => callApi('/api/setup/auth/start', 'POST'),
      'Login link generated. Open it in any browser to sign in.'
    ));

    byId('cancelButton').addEventListener('click', () => run(
      () => callApi('/api/setup/auth/cancel', 'POST'), 'Login reset.'
    ));

    byId('submitCodeButton').addEventListener('click', () => {
      const code = byId('authCode').value.trim();
      if (!code) { setBanner('Paste the auth code first.', 'bad'); return; }
      run(async () => {
        await callApi('/api/setup/auth/submit', 'POST', { code });
        byId('authCode').value = '';
      }, 'Credentials saved! Verifying...');
    });

    byId('authCode').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); byId('submitCodeButton').click(); } });

    byId('copyAuthLinkButton').addEventListener('click', async () => {
      if (!lastStatus?.loginFlow?.authUrl) { setBanner('Generate a login link first.', 'bad'); return; }
      try { await navigator.clipboard.writeText(lastStatus.loginFlow.authUrl); setBanner('Link copied!', 'good'); }
      catch { setBanner('Copy failed — select and copy manually.', 'warn'); }
    });

    refreshStatus().catch(e => { byId('logOutput').textContent = e.message; setBanner(e.message, 'bad'); });
    setInterval(() => { refreshStatus().catch(() => {}); }, 3000);
  </script>
</body>
</html>`;
}

export async function handleSetupStatus(req: Request, res: Response): Promise<void> {
  if (!requireAdmin(req, res)) {
    return;
  }

  res.json(await buildSetupStatus(req));
}

export function handleSetupPage(req: Request, res: Response): void {
  if (!isAdminAuthorized(req)) {
    res.status(401).type("text/plain").send("Unauthorized. Provide ADMIN_TOKEN as a query parameter.");
    return;
  }

  res.type("html").send(renderSetupPage(req));
}

export function handleStartAuth(req: Request, res: Response): void {
  if (!requireAdmin(req, res)) {
    return;
  }

  res.json(loginSession.start());
}

export async function handleSubmitAuthCode(req: Request, res: Response): Promise<void> {
  if (!requireAdmin(req, res)) {
    return;
  }

  const code = typeof req.body?.code === "string" ? req.body.code : "";
  try {
    const result = await loginSession.submit(code);
    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to submit auth code";
    res.status(400).json({
      error: {
        message,
        type: "invalid_request_error",
        code: "invalid_auth_code",
      },
    });
  }
}

export function handleCancelAuth(req: Request, res: Response): void {
  if (!requireAdmin(req, res)) {
    return;
  }

  res.json(loginSession.cancel());
}