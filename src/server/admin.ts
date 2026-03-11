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

async function buildSetupStatus() {
  const [cliStatus, authStatus, configDirectory] = await Promise.all([
    verifyClaude(),
    getClaudeAuthStatus(),
    getConfigDirectorySummary(),
  ]);

  return {
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    runtime: {
      nodeVersion: process.version,
      platform: process.platform,
      host: process.env.HOST || "127.0.0.1",
      port: process.env.PORT || "3456",
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
      --bg: #f3efe6;
      --panel: #fffaf0;
      --panel-strong: #fff3d6;
      --text: #1e1b18;
      --muted: #6d655d;
      --line: #d7c8ad;
      --accent: #a84d1b;
      --accent-soft: #f2c38b;
      --good: #2f6a3a;
      --bad: #8b2e1e;
      --warn: #8a5a0a;
      --code: #211d1a;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      background:
        radial-gradient(circle at top left, rgba(242,195,139,0.45), transparent 30%),
        linear-gradient(180deg, #f7f1e5 0%, var(--bg) 100%);
      color: var(--text);
    }
    .shell {
      max-width: 1120px;
      margin: 0 auto;
      padding: 32px 20px 48px;
    }
    .hero {
      display: grid;
      gap: 16px;
      margin-bottom: 24px;
      padding: 28px;
      border: 1px solid var(--line);
      background: linear-gradient(140deg, var(--panel) 0%, var(--panel-strong) 100%);
      border-radius: 20px;
      box-shadow: 0 18px 48px rgba(84, 57, 27, 0.08);
    }
    h1 {
      margin: 0;
      font-size: clamp(2rem, 5vw, 3.4rem);
      line-height: 0.95;
      letter-spacing: -0.04em;
    }
    p { margin: 0; line-height: 1.5; }
    .subtle { color: var(--muted); }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }
    .card, .panel {
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255, 250, 240, 0.92);
      padding: 18px;
      box-shadow: 0 12px 30px rgba(84, 57, 27, 0.05);
    }
    .card h2, .panel h2 {
      margin: 0 0 12px;
      font-size: 1rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }
    .metric {
      font-size: 1.8rem;
      line-height: 1;
      margin-bottom: 8px;
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
    button {
      border: 0;
      border-radius: 999px;
      padding: 11px 16px;
      font: inherit;
      background: var(--accent);
      color: #fff8f0;
      cursor: pointer;
    }
    button.secondary {
      background: #dfc09a;
      color: var(--text);
    }
    button:disabled { opacity: 0.45; cursor: not-allowed; }
    input[type="text"] {
      width: min(540px, 100%);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 12px 14px;
      font: inherit;
      background: #fffdf8;
      color: var(--text);
    }
    code, pre {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--code);
    }
    pre {
      margin: 0;
      padding: 16px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: #f7f1e6;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 320px;
      overflow: auto;
    }
    .stack {
      display: grid;
      gap: 16px;
    }
    .url-box {
      display: none;
      border-left: 4px solid var(--accent);
      padding: 14px 16px;
      background: rgba(242, 195, 139, 0.18);
      border-radius: 12px;
    }
    .url-box.visible { display: block; }
    .kv {
      display: grid;
      grid-template-columns: 160px 1fr;
      gap: 8px 12px;
      font-size: 0.97rem;
    }
    .kv div:nth-child(odd) { color: var(--muted); }
    a { color: var(--accent); }
    @media (max-width: 640px) {
      .kv { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="shell">
    <section class="hero">
      <h1>Claude Max Proxy Setup</h1>
      <p>This page lets you start Claude login from the server itself, open the auth URL in your browser, paste the returned code, and monitor whether the proxy is actually ready.</p>
      <p class="subtle">If <code>ADMIN_TOKEN</code> is configured, keep this page URL private because it contains the token query parameter needed for API calls.</p>
    </section>

    <section class="grid" id="cards"></section>

    <section class="stack">
      <div class="panel">
        <h2>Setup Flow</h2>
        <div class="row" style="margin-bottom: 14px;">
          <button id="startButton">Start Claude Login</button>
          <button id="cancelButton" class="secondary">Cancel Login</button>
          <button id="refreshButton" class="secondary">Refresh Status</button>
        </div>
        <div id="authUrlBox" class="url-box">
          <p style="margin-bottom: 8px;"><strong>Open this URL in your browser:</strong></p>
          <p><a id="authUrlLink" href="#" target="_blank" rel="noreferrer"></a></p>
        </div>
        <div class="row" style="margin-top: 14px;">
          <input id="authCode" type="text" placeholder="Paste the Claude auth code here" autocomplete="off" />
          <button id="submitCodeButton">Submit Code</button>
        </div>
      </div>

      <div class="panel">
        <h2>Live Diagnostics</h2>
        <div class="kv" id="details"></div>
      </div>

      <div class="panel">
        <h2>Process Log</h2>
        <pre id="logOutput">Waiting for status…</pre>
      </div>
    </section>
  </div>

  <script>
    const token = ${JSON.stringify(token)};
    const statusUrl = token ? '/api/setup/status?token=' + encodeURIComponent(token) : '/api/setup/status';

    function apiUrl(path) {
      return token ? path + '?token=' + encodeURIComponent(token) : path;
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

      document.getElementById('cards').innerHTML = items.map((item) => {
        return '<div class="card">'
          + '<h2>' + item.title + '</h2>'
          + '<div class="metric ' + item.className + '">' + item.metric + '</div>'
          + '<p class="subtle">' + item.detail + '</p>'
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

      document.getElementById('details').innerHTML = details.map(([key, value]) => {
        return '<div>' + key + '</div><div>' + value + '</div>';
      }).join('');
    }

    function renderLoginFlow(status) {
      const loginFlow = status.loginFlow;
      const urlBox = document.getElementById('authUrlBox');
      const urlLink = document.getElementById('authUrlLink');
      const logOutput = document.getElementById('logOutput');
      const startButton = document.getElementById('startButton');
      const cancelButton = document.getElementById('cancelButton');
      const submitCodeButton = document.getElementById('submitCodeButton');

      if (loginFlow.authUrl) {
        urlBox.classList.add('visible');
        urlLink.href = loginFlow.authUrl;
        urlLink.textContent = loginFlow.authUrl;
      } else {
        urlBox.classList.remove('visible');
        urlLink.href = '#';
        urlLink.textContent = '';
      }

      logOutput.textContent = loginFlow.logs.join('\n') || 'No login process output yet.';
      startButton.disabled = loginFlow.active;
      cancelButton.disabled = !loginFlow.active;
      submitCodeButton.disabled = !loginFlow.active;
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

    document.getElementById('startButton').addEventListener('click', async () => {
      await callApi('/api/setup/auth/start', 'POST');
      await refreshStatus();
    });

    document.getElementById('cancelButton').addEventListener('click', async () => {
      await callApi('/api/setup/auth/cancel', 'POST');
      await refreshStatus();
    });

    document.getElementById('refreshButton').addEventListener('click', async () => {
      await refreshStatus();
    });

    document.getElementById('submitCodeButton').addEventListener('click', async () => {
      const code = document.getElementById('authCode').value.trim();
      if (!code) {
        alert('Auth code is required');
        return;
      }
      await callApi('/api/setup/auth/submit', 'POST', { code });
      document.getElementById('authCode').value = '';
      await refreshStatus();
    });

    refreshStatus().catch((error) => {
      document.getElementById('logOutput').textContent = error.message;
    });

    setInterval(() => {
      refreshStatus().catch((error) => {
        document.getElementById('logOutput').textContent = error.message;
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

  res.json(await buildSetupStatus());
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