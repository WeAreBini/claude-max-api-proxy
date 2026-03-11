/**
 * Admin setup UI and diagnostics endpoints.
 *
 * Provides a minimal browser-based setup flow for Claude CLI login on headless hosts,
 * plus runtime diagnostics useful for Railway and similar platforms.
 */

import { spawn, type ChildProcess } from "child_process";
import os from "os";
import path from "path";
import fs from "fs/promises";
import type { Request, Response } from "express";
import { getClaudeAuthStatus, verifyClaude } from "../subprocess/manager.js";

type LoginPhase =
  | "idle"
  | "starting"
  | "waiting_for_code"
  | "submitting_code"
  | "succeeded"
  | "failed"
  | "cancelled";

interface LoginSnapshot {
  readonly phase: LoginPhase;
  readonly active: boolean;
  readonly startedAt: string | null;
  readonly finishedAt: string | null;
  readonly authUrl: string | null;
  readonly lastExitCode: number | null;
  readonly error: string | null;
  readonly logs: readonly string[];
}

interface ConfigDirectorySummary {
  readonly path: string;
  readonly exists: boolean;
  readonly entries: readonly string[];
}

const MAX_LOG_LINES = 120;
const AUTH_URL_PATTERN = /(https:\/\/claude\.ai\/oauth\/authorize\?\S+)/;

class ClaudeLoginSession {
  private process: ChildProcess | null = null;
  private stdoutBuffer = "";
  private stderrBuffer = "";
  private logs: string[] = [];
  private phase: LoginPhase = "idle";
  private authUrl: string | null = null;
  private error: string | null = null;
  private startedAt: string | null = null;
  private finishedAt: string | null = null;
  private lastExitCode: number | null = null;

  getSnapshot(): LoginSnapshot {
    return {
      phase: this.phase,
      active: this.process !== null && this.process.exitCode === null,
      startedAt: this.startedAt,
      finishedAt: this.finishedAt,
      authUrl: this.authUrl,
      lastExitCode: this.lastExitCode,
      error: this.error,
      logs: [...this.logs],
    };
  }

  start(): LoginSnapshot {
    if (this.process && this.process.exitCode === null) {
      return this.getSnapshot();
    }

    this.reset();
    this.phase = "starting";
    this.startedAt = new Date().toISOString();

    this.process = spawn("claude", ["auth", "login"], {
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });

    this.process.stdout?.on("data", (chunk: Buffer) => {
      this.stdoutBuffer += chunk.toString();
      this.consumeBuffer("stdout");
    });

    this.process.stderr?.on("data", (chunk: Buffer) => {
      this.stderrBuffer += chunk.toString();
      this.consumeBuffer("stderr");
    });

    this.process.on("error", (error: Error) => {
      this.error = error.message;
      this.phase = "failed";
      this.appendLog(`[process] ${error.message}`);
    });

    this.process.on("close", (code: number | null) => {
      this.lastExitCode = code;
      this.finishedAt = new Date().toISOString();

      if (this.phase !== "cancelled") {
        if (code === 0) {
          this.phase = "succeeded";
          this.appendLog("[process] Claude login completed successfully");
        } else {
          this.phase = "failed";
          if (!this.error) {
            this.error = `Claude login exited with code ${code}`;
          }
          this.appendLog(`[process] Claude login exited with code ${code}`);
        }
      }

      this.process = null;
    });

    return this.getSnapshot();
  }

  submitCode(code: string): LoginSnapshot {
    const trimmedCode = code.trim();
    if (!trimmedCode) {
      throw new Error("Auth code is required");
    }

    if (!this.process || this.process.exitCode !== null) {
      throw new Error("No active Claude login session");
    }

    this.phase = "submitting_code";
    this.appendLog("[input] Submitted auth code from setup UI");
    this.process.stdin?.write(`${trimmedCode}\n`);
    return this.getSnapshot();
  }

  cancel(): LoginSnapshot {
    if (this.process && this.process.exitCode === null) {
      this.phase = "cancelled";
      this.finishedAt = new Date().toISOString();
      this.appendLog("[process] Claude login cancelled from setup UI");
      this.process.kill("SIGTERM");
    }

    return this.getSnapshot();
  }

  private reset(): void {
    this.stdoutBuffer = "";
    this.stderrBuffer = "";
    this.logs = [];
    this.phase = "idle";
    this.authUrl = null;
    this.error = null;
    this.startedAt = null;
    this.finishedAt = null;
    this.lastExitCode = null;
  }

  private consumeBuffer(stream: "stdout" | "stderr"): void {
    const buffer = stream === "stdout" ? this.stdoutBuffer : this.stderrBuffer;
    const lines = buffer.split(/\r?\n/);
    const remainder = lines.pop() ?? "";

    for (const line of lines) {
      this.handleLine(line.trim());
    }

    if (stream === "stdout") {
      this.stdoutBuffer = remainder;
    } else {
      this.stderrBuffer = remainder;
    }

    const combinedBuffer = `${this.stdoutBuffer} ${this.stderrBuffer}`.trim();
    this.captureAuthUrl(combinedBuffer);
  }

  private handleLine(line: string): void {
    if (!line) {
      return;
    }

    this.appendLog(line);
    this.captureAuthUrl(line);
  }

  private captureAuthUrl(value: string): void {
    if (this.authUrl) {
      return;
    }

    const match = value.match(AUTH_URL_PATTERN);
    if (!match?.[1]) {
      return;
    }

    this.authUrl = match[1];
    if (this.phase === "starting") {
      this.phase = "waiting_for_code";
    }
    this.appendLog("[process] Captured Claude login URL");
  }

  private appendLog(message: string): void {
    this.logs.push(message);
    if (this.logs.length > MAX_LOG_LINES) {
      this.logs = this.logs.slice(-MAX_LOG_LINES);
    }
  }
}

const loginSession = new ClaudeLoginSession();

function getAdminTokenFromRequest(req: Request): string | null {
  const bearerToken = req.header("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
  const headerToken = req.header("x-admin-token");
  const queryToken = typeof req.query.token === "string" ? req.query.token : null;
  return bearerToken ?? headerToken ?? queryToken;
}

function isAdminAuthorized(req: Request): boolean {
  const configuredToken = process.env.ADMIN_TOKEN;
  if (!configuredToken) {
    return true;
  }

  return getAdminTokenFromRequest(req) === configuredToken;
}

function requireAdmin(req: Request, res: Response): boolean {
  if (isAdminAuthorized(req)) {
    return true;
  }

  res.status(401).json({
    error: {
      message: "Unauthorized",
      type: "authentication_error",
      code: "admin_token_required",
    },
  });
  return false;
}

async function getConfigDirectorySummary(): Promise<ConfigDirectorySummary> {
  const homeDirectory = process.env.HOME || os.homedir();
  const configDirectoryPath = path.join(homeDirectory, ".config", "claude");

  try {
    const entries = await fs.readdir(configDirectoryPath);
    return {
      path: configDirectoryPath,
      exists: true,
      entries: entries.sort(),
    };
  } catch {
    return {
      path: configDirectoryPath,
      exists: false,
      entries: [],
    };
  }
}

async function buildSetupStatus(req: Request) {
  const [cliStatus, authStatus, configDirectory] = await Promise.all([
    verifyClaude(),
    getClaudeAuthStatus(),
    getConfigDirectorySummary(),
  ]);

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
      --bg: #07111f;
      --bg-accent: #132742;
      --panel: rgba(10, 19, 34, 0.82);
      --panel-strong: rgba(14, 28, 48, 0.94);
      --panel-soft: rgba(18, 35, 59, 0.72);
      --text: #ecf3ff;
      --muted: #9db0ce;
      --line: rgba(140, 173, 222, 0.22);
      --accent: #59d0ff;
      --accent-strong: #8af7d3;
      --accent-soft: rgba(89, 208, 255, 0.16);
      --good: #8af7d3;
      --bad: #ff8b8b;
      --warn: #ffd37a;
      --shadow: 0 24px 70px rgba(0, 0, 0, 0.35);
      --code: #dce8ff;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Space Grotesk", "Avenir Next", "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at 15% 15%, rgba(89, 208, 255, 0.24), transparent 22%),
        radial-gradient(circle at 85% 18%, rgba(138, 247, 211, 0.14), transparent 20%),
        radial-gradient(circle at 50% 100%, rgba(68, 91, 255, 0.22), transparent 28%),
        linear-gradient(180deg, var(--bg) 0%, #030812 100%);
      color: var(--text);
    }
    .shell {
      max-width: 1240px;
      margin: 0 auto;
      padding: 32px 20px 56px;
    }
    .hero {
      display: grid;
      grid-template-columns: minmax(0, 1.55fr) minmax(260px, 0.85fr);
      gap: 20px;
      margin-bottom: 24px;
      padding: 28px;
      border: 1px solid var(--line);
      background:
        linear-gradient(145deg, rgba(10, 19, 34, 0.96), rgba(13, 29, 49, 0.86)),
        linear-gradient(120deg, rgba(89, 208, 255, 0.1), transparent 40%);
      border-radius: 28px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }
    h1 {
      margin: 0;
      font-size: clamp(2.2rem, 6vw, 4.5rem);
      line-height: 0.9;
      letter-spacing: -0.06em;
    }
    h2 {
      margin: 0;
      font-size: 1rem;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      color: var(--muted);
    }
    p { margin: 0; line-height: 1.6; }
    .subtle { color: var(--muted); }
    .hero-copy {
      display: grid;
      gap: 14px;
      align-content: start;
    }
    .eyebrow {
      display: inline-flex;
      align-items: center;
      width: fit-content;
      gap: 8px;
      padding: 8px 12px;
      border: 1px solid rgba(138, 247, 211, 0.28);
      border-radius: 999px;
      color: var(--accent-strong);
      background: rgba(138, 247, 211, 0.07);
      font-size: 0.82rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .hero-side {
      display: grid;
      gap: 14px;
      align-content: end;
    }
    .hero-note {
      padding: 18px;
      border: 1px solid var(--line);
      border-radius: 20px;
      background: rgba(255, 255, 255, 0.04);
      backdrop-filter: blur(12px);
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }
    .card, .panel {
      border: 1px solid var(--line);
      border-radius: 24px;
      background: linear-gradient(180deg, var(--panel) 0%, var(--panel-strong) 100%);
      padding: 20px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(16px);
    }
    .card {
      position: relative;
      overflow: hidden;
    }
    .card::after {
      content: "";
      position: absolute;
      inset: auto -18% -42% auto;
      width: 130px;
      height: 130px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(89, 208, 255, 0.18), transparent 70%);
      pointer-events: none;
    }
    .metric {
      font-size: clamp(1.8rem, 4vw, 2.6rem);
      line-height: 0.95;
      margin: 10px 0 8px;
      letter-spacing: -0.04em;
    }
    .good { color: var(--good); }
    .bad { color: var(--bad); }
    .warn { color: var(--warn); }
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
    }
    .button-row {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 18px;
    }
    button {
      border: 1px solid transparent;
      border-radius: 999px;
      padding: 12px 18px;
      font: inherit;
      font-weight: 700;
      letter-spacing: 0.01em;
      background: linear-gradient(135deg, var(--accent), #3478ff);
      color: #03111d;
      cursor: pointer;
      transition: transform 160ms ease, box-shadow 160ms ease, border-color 160ms ease, background 160ms ease;
      box-shadow: 0 10px 24px rgba(52, 120, 255, 0.22);
    }
    button.secondary {
      background: rgba(255, 255, 255, 0.06);
      color: var(--text);
      border-color: var(--line);
      box-shadow: none;
    }
    button.ghost {
      background: transparent;
      color: var(--accent);
      border-color: rgba(89, 208, 255, 0.35);
      box-shadow: none;
    }
    button:hover:not(:disabled), button:focus-visible:not(:disabled) {
      transform: translateY(-1px);
      box-shadow: 0 14px 30px rgba(52, 120, 255, 0.28);
    }
    button.secondary:hover:not(:disabled),
    button.secondary:focus-visible:not(:disabled),
    button.ghost:hover:not(:disabled),
    button.ghost:focus-visible:not(:disabled) {
      box-shadow: 0 0 0 4px rgba(89, 208, 255, 0.12);
    }
    button:disabled { opacity: 0.45; cursor: not-allowed; }
    button:focus-visible,
    input:focus-visible,
    a:focus-visible {
      outline: 3px solid rgba(138, 247, 211, 0.55);
      outline-offset: 2px;
    }
    label {
      display: block;
      margin-bottom: 8px;
      color: var(--muted);
      font-size: 0.95rem;
    }
    input[type="text"] {
      width: min(540px, 100%);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 14px 16px;
      font: inherit;
      background: rgba(255, 255, 255, 0.05);
      color: var(--text);
    }
    code, pre {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--code);
    }
    pre {
      margin: 0;
      padding: 16px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: rgba(3, 10, 20, 0.78);
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 360px;
      overflow: auto;
    }
    .stack {
      display: grid;
      gap: 16px;
    }
    .layout {
      display: grid;
      grid-template-columns: minmax(0, 1.15fr) minmax(320px, 0.85fr);
      gap: 16px;
    }
    .url-box {
      display: none;
      padding: 16px;
      background: linear-gradient(135deg, rgba(89, 208, 255, 0.12), rgba(138, 247, 211, 0.08));
      border-radius: 18px;
      border: 1px solid rgba(89, 208, 255, 0.22);
    }
    .url-box.visible { display: block; }
    .status-banner {
      display: none;
      margin-bottom: 18px;
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid transparent;
      background: rgba(255, 255, 255, 0.04);
    }
    .status-banner.visible { display: block; }
    .status-banner.good {
      border-color: rgba(138, 247, 211, 0.24);
      background: rgba(138, 247, 211, 0.09);
      color: var(--good);
    }
    .status-banner.warn {
      border-color: rgba(255, 211, 122, 0.28);
      background: rgba(255, 211, 122, 0.09);
      color: var(--warn);
    }
    .status-banner.bad {
      border-color: rgba(255, 139, 139, 0.28);
      background: rgba(255, 139, 139, 0.09);
      color: var(--bad);
    }
    .kv {
      display: grid;
      grid-template-columns: 180px 1fr;
      gap: 8px 12px;
      font-size: 0.97rem;
    }
    .kv div:nth-child(odd) { color: var(--muted); }
    .input-row {
      display: grid;
      gap: 10px;
    }
    .flow-meta {
      display: grid;
      gap: 10px;
      margin-top: 18px;
      padding-top: 18px;
      border-top: 1px solid var(--line);
    }
    .tiny {
      font-size: 0.88rem;
      color: var(--muted);
    }
    a { color: var(--accent); }
    .pulse {
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }
    .pulse::before {
      content: "";
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: currentColor;
      box-shadow: 0 0 0 0 currentColor;
      animation: pulse 1.8s infinite;
    }
    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 rgba(138, 247, 211, 0.55); }
      70% { box-shadow: 0 0 0 10px rgba(138, 247, 211, 0); }
      100% { box-shadow: 0 0 0 0 rgba(138, 247, 211, 0); }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation: none !important;
        transition: none !important;
        scroll-behavior: auto !important;
      }
    }
    @media (max-width: 980px) {
      .hero,
      .layout {
        grid-template-columns: 1fr;
      }
    }
    @media (max-width: 640px) {
      .kv { grid-template-columns: 1fr; }
      .shell { padding-left: 14px; padding-right: 14px; }
      .hero, .card, .panel { border-radius: 20px; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <div class="hero-copy">
        <div class="eyebrow">Railway Setup Console</div>
        <h1>Claude Max Proxy Control Room</h1>
        <p>This page starts Claude login from the running server, exposes the OAuth URL for browser sign-in, accepts the returned auth code, and shows whether the proxy is genuinely ready for OpenClaw or Paperclip traffic.</p>
      </div>
      <div class="hero-side">
        <div class="hero-note">
          <p><strong>How it works:</strong> start login, open the generated Claude URL, copy the auth code back here, then wait for the auth state to flip to logged in.</p>
        </div>
        <div class="hero-note subtle">
          If <code>ADMIN_TOKEN</code> is configured, keep this page URL private because the token query parameter grants access to admin actions.
        </div>
      </div>
    </section>

    <section class="grid" id="cards"></section>

    <section class="layout">
      <div class="stack">
        <div class="panel">
          <div id="statusBanner" class="status-banner" role="status" aria-live="polite"></div>
        <h2>Setup Flow</h2>
          <div class="button-row">
            <button id="startButton">Start Claude Login</button>
            <button id="cancelButton" class="secondary">Cancel Login</button>
            <button id="refreshButton" class="secondary">Refresh Status</button>
          </div>
          <div id="authUrlBox" class="url-box" aria-live="polite">
            <p style="margin-bottom: 8px;"><strong>Open this Claude URL in your browser:</strong></p>
            <p style="margin-bottom: 12px;"><a id="authUrlLink" href="#" target="_blank" rel="noreferrer"></a></p>
            <div class="row">
              <button id="openAuthLinkButton" class="ghost">Open Link</button>
              <button id="copyAuthLinkButton" class="secondary">Copy Link</button>
            </div>
          </div>
          <div class="input-row" style="margin-top: 16px;">
            <label for="authCode">Claude auth code</label>
            <div class="row">
              <input id="authCode" type="text" placeholder="Paste the Claude auth code here" autocomplete="off" aria-describedby="authCodeHint" />
              <button id="submitCodeButton">Submit Code</button>
            </div>
            <div id="authCodeHint" class="tiny">After signing in with the Claude URL above, paste the returned code here and submit it to the server-side login process.</div>
          </div>
          <div class="flow-meta tiny" id="flowMeta"></div>
        </div>

        <div class="panel">
          <h2>Process Log</h2>
          <pre id="logOutput">Waiting for status...</pre>
        </div>
      </div>

      <div class="stack">
        <div class="panel">
          <h2>Live Diagnostics</h2>
          <div class="kv" id="details"></div>
        </div>

        <div class="panel">
          <h2>Connection Notes</h2>
          <div class="stack tiny">
            <p>Use your Railway public domain with <code>/v1</code> as the OpenAI-compatible base URL once auth shows logged in.</p>
            <p>Paperclip and OpenClaw should point at the same host after setup is complete.</p>
            <p>If auth gets stuck, cancel the login flow, start it again, and use the latest generated Claude URL rather than a cached older one.</p>
          </div>
        </div>
      </div>
    </section>
  </div>

  <script>
    const token = ${JSON.stringify(token)};
    const statusUrl = token ? '/api/setup/status?token=' + encodeURIComponent(token) : '/api/setup/status';
    let lastStatus = null;
    let isBusy = false;

    function byId(id) {
      return document.getElementById(id);
    }

    function escapeHtml(value) {
      return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function apiUrl(path) {
      return token ? path + '?token=' + encodeURIComponent(token) : path;
    }

    function setBanner(message, tone) {
      const banner = byId('statusBanner');
      banner.textContent = message;
      banner.className = 'status-banner visible ' + tone;
    }

    function clearBanner() {
      const banner = byId('statusBanner');
      banner.textContent = '';
      banner.className = 'status-banner';
    }

    function setBusy(nextBusy) {
      isBusy = nextBusy;
      const status = lastStatus;
      const active = Boolean(status && status.loginFlow && status.loginFlow.active);

      byId('startButton').disabled = nextBusy || active;
      byId('cancelButton').disabled = nextBusy || !active;
      byId('submitCodeButton').disabled = nextBusy || !active;
      byId('refreshButton').disabled = nextBusy;
      byId('copyAuthLinkButton').disabled = nextBusy || !(status && status.loginFlow && status.loginFlow.authUrl);
      byId('openAuthLinkButton').disabled = nextBusy || !(status && status.loginFlow && status.loginFlow.authUrl);
    }

    async function callApi(path, method = 'GET', body) {
      const response = await fetch(apiUrl(path), {
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'X-Admin-Token': token } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });

      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload?.error?.message || 'Request failed with ' + response.status);
      }

      return payload;
    }

    function renderCards(status) {
      const auth = status.auth;
      const loginFlow = status.loginFlow;
      const cli = status.claudeCli;

      const items = [
        {
          title: 'Claude CLI',
          metric: cli.ok ? 'Installed' : 'Missing',
          className: cli.ok ? 'good' : 'bad',
          detail: cli.version || cli.error || 'Unknown status',
        },
        {
          title: 'Auth Status',
          metric: auth.loggedIn ? 'Logged In' : 'Logged Out',
          className: auth.loggedIn ? 'good' : 'warn',
          detail: (auth.authMethod || 'unknown') + ' via ' + (auth.apiProvider || 'unknown'),
        },
        {
          title: 'Login Flow',
          metric: loginFlow.phase,
          className: loginFlow.phase === 'failed' ? 'bad' : loginFlow.phase === 'succeeded' ? 'good' : 'warn',
          detail: loginFlow.active ? 'process running' : 'no active login process',
        },
        {
          title: 'Runtime',
          metric: status.runtime.host + ':' + status.runtime.port,
          className: 'good',
          detail: 'uptime ' + status.uptimeSeconds + 's',
        },
      ];

      byId('cards').innerHTML = items.map((item) => {
        return '<div class="card">'
          + '<h2>' + escapeHtml(item.title) + '</h2>'
          + '<div class="metric ' + escapeHtml(item.className) + '">' + escapeHtml(item.metric) + '</div>'
          + '<p class="subtle">' + escapeHtml(item.detail) + '</p>'
          + '</div>';
      }).join('');
    }

    function renderDetails(status) {
      const details = [
        ['Config dir', status.configDirectory.path + (status.configDirectory.exists ? '' : ' (missing)')],
        ['Config entries', status.configDirectory.entries.join(', ') || 'none'],
        ['Admin token', status.runtime.adminTokenConfigured ? 'configured' : 'not configured'],
        ['Dangerous skip perms', String(status.runtime.dangerousSkipPermissions)],
        ['CORS allow origin', status.runtime.corsAllowOrigin],
        ['OAuth env token', String(status.envTokens.oauthTokenConfigured)],
        ['OAuth FD token', String(status.envTokens.oauthFdConfigured)],
        ['Anthropic API key', String(status.envTokens.anthropicApiKeyConfigured)],
        ['Auth method', status.auth.authMethod || 'unknown'],
        ['CLI version', status.claudeCli.version || 'unknown'],
      ];

      byId('details').innerHTML = details.map(([key, value]) => {
        return '<div>' + escapeHtml(key) + '</div><div>' + escapeHtml(value) + '</div>';
      }).join('');
    }

    function renderLoginFlow(status) {
      lastStatus = status;
      const loginFlow = status.loginFlow;
      const urlBox = byId('authUrlBox');
      const urlLink = byId('authUrlLink');
      const logOutput = byId('logOutput');
      const flowMeta = byId('flowMeta');

      const flowLines = [
        'Phase: ' + loginFlow.phase,
        'Active process: ' + String(loginFlow.active),
        'Started: ' + (loginFlow.startedAt || 'not started'),
        'Finished: ' + (loginFlow.finishedAt || 'not finished'),
        'Last exit code: ' + (loginFlow.lastExitCode === null ? 'none' : String(loginFlow.lastExitCode)),
      ];

      if (loginFlow.error) {
        flowLines.push('Last error: ' + loginFlow.error);
      }

      flowMeta.innerHTML = flowLines.map((line) => '<div>' + escapeHtml(line) + '</div>').join('');

      if (loginFlow.authUrl) {
        urlBox.classList.add('visible');
        urlLink.href = loginFlow.authUrl;
        urlLink.textContent = loginFlow.authUrl;
      } else {
        urlBox.classList.remove('visible');
        urlLink.href = '#';
        urlLink.textContent = '';
      }

      logOutput.textContent = loginFlow.logs.join('\\n') || 'No login process output yet.';

      if (status.auth.loggedIn) {
        setBanner('Claude CLI is authenticated. Your proxy is ready for OpenAI-compatible client traffic.', 'good');
      } else if (loginFlow.phase === 'waiting_for_code' && loginFlow.authUrl) {
        setBanner('Claude login is waiting for the auth code. Open the URL, finish sign-in, and paste the returned code here.', 'warn');
      } else if (loginFlow.phase === 'failed') {
        setBanner(loginFlow.error || 'Claude login failed. Start a fresh login attempt and use the newest generated URL.', 'bad');
      } else if (loginFlow.phase === 'starting' || loginFlow.phase === 'submitting_code') {
        setBanner('Claude login is in progress. Wait for the next prompt or the logged-in state.', 'warn');
      } else if (loginFlow.phase === 'cancelled') {
        setBanner('Claude login was cancelled. Start a new login attempt when you are ready.', 'warn');
      } else {
        clearBanner();
      }

      setBusy(isBusy);
    }

    async function refreshStatus() {
      const response = await fetch(statusUrl, {
        headers: token ? { 'X-Admin-Token': token } : {},
      });
      const status = await response.json();
      if (!response.ok) {
        throw new Error(status?.error?.message || 'Failed to load status');
      }

      renderCards(status);
      renderDetails(status);
      renderLoginFlow(status);
    }

    async function runAction(action, successMessage) {
      try {
        setBusy(true);
        clearBanner();
        await action();
        await refreshStatus();
        if (successMessage) {
          setBanner(successMessage, 'good');
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Request failed';
        setBanner(message, 'bad');
        byId('logOutput').textContent = message;
      } finally {
        setBusy(false);
      }
    }

    byId('startButton').addEventListener('click', async () => {
      await runAction(async () => {
        await callApi('/api/setup/auth/start', 'POST');
      });
    });

    byId('cancelButton').addEventListener('click', async () => {
      await runAction(async () => {
        await callApi('/api/setup/auth/cancel', 'POST');
      }, 'Claude login cancelled.');
    });

    byId('refreshButton').addEventListener('click', async () => {
      await runAction(async () => {
        await refreshStatus();
      });
    });

    byId('submitCodeButton').addEventListener('click', async () => {
      const code = byId('authCode').value.trim();
      if (!code) {
        setBanner('Paste the Claude auth code before submitting.', 'bad');
        return;
      }
      await runAction(async () => {
        await callApi('/api/setup/auth/submit', 'POST', { code: code });
        byId('authCode').value = '';
      }, 'Auth code submitted to Claude login process.');
    });

    byId('authCode').addEventListener('keydown', async (event) => {
      if (event.key !== 'Enter') {
        return;
      }
      event.preventDefault();
      byId('submitCodeButton').click();
    });

    byId('openAuthLinkButton').addEventListener('click', () => {
      if (!lastStatus || !lastStatus.loginFlow || !lastStatus.loginFlow.authUrl) {
        setBanner('No Claude login URL is available yet. Start a login first.', 'bad');
        return;
      }
      window.open(lastStatus.loginFlow.authUrl, '_blank', 'noopener,noreferrer');
    });

    byId('copyAuthLinkButton').addEventListener('click', async () => {
      if (!lastStatus || !lastStatus.loginFlow || !lastStatus.loginFlow.authUrl) {
        setBanner('No Claude login URL is available yet. Start a login first.', 'bad');
        return;
      }

      try {
        await navigator.clipboard.writeText(lastStatus.loginFlow.authUrl);
        setBanner('Claude login URL copied to clipboard.', 'good');
      } catch {
        setBanner('Clipboard write failed. Copy the Claude URL manually.', 'warn');
      }
    });

    refreshStatus().catch((error) => {
      const message = error instanceof Error ? error.message : 'Failed to load status';
      byId('logOutput').textContent = message;
      setBanner(message, 'bad');
    });

    setInterval(() => {
      refreshStatus().catch((error) => {
        const message = error instanceof Error ? error.message : 'Failed to load status';
        byId('logOutput').textContent = message;
        setBanner(message, 'bad');
      });
    }, 4000);
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

export function handleSubmitAuthCode(req: Request, res: Response): void {
  if (!requireAdmin(req, res)) {
    return;
  }

  const code = typeof req.body?.code === "string" ? req.body.code : "";
  try {
    res.json(loginSession.submitCode(code));
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