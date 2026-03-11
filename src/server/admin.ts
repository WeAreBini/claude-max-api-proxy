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
import {
  getClaudeAuthStatus,
  verifyClaude,
  type ClaudeAuthStatus,
} from "../subprocess/manager.js";

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

interface NormalizedAuthCode {
  readonly code: string;
  readonly source: "raw" | "query_string" | "callback_url";
}

interface SpawnCommand {
  readonly command: string;
  readonly args: readonly string[];
}

const MAX_LOG_LINES = 120;
const AUTH_URL_PATTERN = /(https:\/\/claude\.ai\/oauth\/authorize\?\S+)/;
const AUTH_CODE_PATTERN = /(?:^|[?&#])code=([^&#\s]+)/i;

function getClaudeLoginSpawnCommand(): SpawnCommand {
  if (process.platform === "darwin") {
    return {
      command: "script",
      args: ["-q", "/dev/null", "claude", "auth", "login"],
    };
  }

  if (process.platform === "linux") {
    return {
      command: "script",
      args: ["-q", "-c", "claude auth login", "/dev/null"],
    };
  }

  return {
    command: "claude",
    args: ["auth", "login"],
  };
}

function normalizeAuthCode(input: string): NormalizedAuthCode {
  const trimmedInput = input.trim();
  if (!trimmedInput) {
    throw new Error("Auth code is required");
  }

  if (trimmedInput.startsWith("http://") || trimmedInput.startsWith("https://")) {
    try {
      const parsedUrl = new URL(trimmedInput);
      const codeFromUrl = parsedUrl.searchParams.get("code")?.trim();
      if (codeFromUrl) {
        return {
          code: codeFromUrl,
          source: "callback_url",
        };
      }
    } catch {
      // Fall through to the regex-based parsing below.
    }
  }

  const codeMatch = trimmedInput.match(AUTH_CODE_PATTERN);
  if (codeMatch?.[1]) {
    return {
      code: decodeURIComponent(codeMatch[1]).trim(),
      source: "query_string",
    };
  }

  return {
    code: trimmedInput,
    source: "raw",
  };
}

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

    const loginCommand = getClaudeLoginSpawnCommand();

    this.process = spawn(loginCommand.command, [...loginCommand.args], {
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });

    if (loginCommand.command !== "claude") {
      this.appendLog(`[process] Started Claude login via ${loginCommand.command} PTY wrapper`);
    }

    this.process.stdout?.on("data", (chunk: Buffer) => {
      this.stdoutBuffer += chunk.toString();
      this.consumeBuffer("stdout");
    });

    this.process.stderr?.on("data", (chunk: Buffer) => {
      this.stderrBuffer += chunk.toString();
      this.consumeBuffer("stderr");
    });

    this.process.on("error", (error: Error) => {
      if (this.phase === "succeeded") {
        return;
      }

      this.error = error.message;
      this.phase = "failed";
      this.appendLog(`[process] ${error.message}`);
    });

    this.process.on("close", (code: number | null) => {
      this.lastExitCode = code;
      this.finishedAt = new Date().toISOString();

      if (this.phase === "succeeded" || this.phase === "cancelled") {
        this.process = null;
        return;
      }

      if (code === 0) {
        this.phase = "succeeded";
        this.error = null;
        this.appendLog("[process] Claude login completed successfully");
      } else {
        this.phase = "failed";
        if (!this.error) {
          this.error = `Claude login exited with code ${code}`;
        }
        this.appendLog(`[process] Claude login exited with code ${code}`);
      }

      this.process = null;
    });

    return this.getSnapshot();
  }

  submitCode(code: string): LoginSnapshot {
    if (!this.process || this.process.exitCode !== null) {
      throw new Error("No active Claude login session");
    }

    if (this.phase === "submitting_code") {
      throw new Error(
        "Auth code already submitted. Wait for Claude login to finish, or cancel and start again."
      );
    }

    const normalizedCode = normalizeAuthCode(code);

    this.phase = "submitting_code";
    this.error = null;
    this.appendLog(
      normalizedCode.source === "raw"
        ? "[input] Submitted auth code from setup UI"
        : "[input] Extracted auth code from callback URL submitted in setup UI"
    );
    this.process.stdin?.write(`${normalizedCode.code}\n`);
    this.appendLog("[process] Auth code forwarded to Claude login session");
    return this.getSnapshot();
  }

  reconcile(authStatus: ClaudeAuthStatus): void {
    const canReconcile =
      authStatus.loggedIn &&
      this.startedAt !== null &&
      this.phase !== "idle" &&
      this.phase !== "cancelled" &&
      this.phase !== "succeeded";

    if (!canReconcile) {
      return;
    }

    this.phase = "succeeded";
    this.error = null;
    this.finishedAt ??= new Date().toISOString();
    this.appendLog("[process] Claude auth detected via status check");

    if (this.process && this.process.exitCode === null) {
      this.process.kill("SIGTERM");
    }
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

  loginSession.reconcile(authStatus);

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
      margin: 0;
      min-height: 100vh;
      font-family: "IBM Plex Sans", "Avenir Next", "Segoe UI", sans-serif;
      background:
        radial-gradient(circle at top left, rgba(12, 122, 107, 0.08), transparent 28%),
        linear-gradient(180deg, #f8f4ec 0%, var(--bg) 100%);
      color: var(--text);
    }
    main {
      max-width: 920px;
      margin: 0 auto;
      padding: 24px 16px 48px;
    }
    .hero,
    .panel {
      border: 1px solid var(--line);
      background: linear-gradient(180deg, var(--panel) 0%, var(--panel-strong) 100%);
      border-radius: 22px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(8px);
    }
    .hero {
      padding: 24px;
      margin-bottom: 16px;
    }
    h1 {
      margin: 0;
      font-size: clamp(2rem, 5vw, 3.25rem);
      line-height: 0.95;
      letter-spacing: -0.04em;
    }
    h2 {
      margin: 0 0 14px;
      font-size: 1.1rem;
      letter-spacing: -0.02em;
    }
    p,
    li,
    dd,
    dt,
    summary,
    label {
      line-height: 1.55;
    }
    p { margin: 0; }
    .eyebrow {
      display: inline-block;
      margin-bottom: 10px;
      font-size: 0.8rem;
      font-weight: 700;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--muted);
    }
    .lead {
      margin-top: 10px;
      max-width: 60ch;
      color: var(--muted);
    }
    .banner {
      display: none;
      margin-top: 18px;
      padding: 14px 16px;
      border-radius: 16px;
      border: 1px solid transparent;
      font-weight: 600;
    }
    .banner.visible { display: block; }
    .banner.good {
      color: var(--good);
      border-color: rgba(23, 107, 69, 0.18);
      background: rgba(23, 107, 69, 0.08);
    }
    .banner.warn {
      color: var(--warn);
      border-color: rgba(148, 98, 0, 0.18);
      background: rgba(255, 216, 140, 0.22);
    }
    .banner.bad {
      color: var(--bad);
      border-color: rgba(165, 56, 42, 0.18);
      background: rgba(165, 56, 42, 0.08);
    }
    .chip-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 10px;
      margin-top: 18px;
    }
    .chip {
      padding: 14px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: rgba(255, 255, 255, 0.55);
    }
    .good { color: var(--good); }
    .bad { color: var(--bad); }
    .warn { color: var(--warn); }
    .chip-label {
      display: block;
      margin-bottom: 6px;
      color: var(--muted);
      font-size: 0.84rem;
    }
    .chip strong {
      font-size: 1rem;
    }
    .panel {
      padding: 20px;
      margin-bottom: 16px;
    }
    .actions,
    .input-row,
    .url-actions,
    .row {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }
    .steps {
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 14px;
    }
    .step {
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: rgba(255, 255, 255, 0.5);
    }
    .step-head {
      display: flex;
      gap: 12px;
      align-items: flex-start;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .step-number {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 30px;
      height: 30px;
      border-radius: 999px;
      background: var(--accent-soft);
      color: var(--accent-strong);
      font-weight: 700;
      flex: none;
    }
    .step-title {
      font-weight: 700;
      font-size: 1.05rem;
    }
    .step-status {
      padding: 4px 10px;
      border-radius: 999px;
      background: #efe6d8;
      color: var(--muted);
      font-size: 0.85rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .step-status.good {
      background: rgba(23, 107, 69, 0.1);
      color: var(--good);
    }
    .step-status.warn {
      background: rgba(255, 216, 140, 0.35);
      color: var(--warn);
    }
    .step-copy {
      display: grid;
      gap: 8px;
      color: var(--muted);
    }
    button {
      border: 1px solid transparent;
      border-radius: 14px;
      padding: 12px 16px;
      font: inherit;
      font-weight: 700;
      background: var(--accent);
      color: #f7f4ec;
      cursor: pointer;
      transition: transform 160ms ease, box-shadow 160ms ease, background 160ms ease;
      box-shadow: 0 8px 18px rgba(12, 122, 107, 0.16);
    }
    button.secondary {
      background: transparent;
      color: var(--text);
      border-color: var(--line);
      box-shadow: none;
    }
    button:hover:not(:disabled), button:focus-visible:not(:disabled) {
      transform: translateY(-1px);
      box-shadow: 0 12px 22px rgba(12, 122, 107, 0.18);
    }
    button:disabled { opacity: 0.45; cursor: not-allowed; }
    button:focus-visible,
    input:focus-visible,
    a:focus-visible,
    summary:focus-visible {
      outline: 3px solid rgba(12, 122, 107, 0.32);
      outline-offset: 2px;
    }
    label {
      display: block;
      margin-bottom: 8px;
      color: var(--muted);
      font-size: 0.95rem;
    }
    input[type="text"] {
      flex: 1 1 320px;
      min-width: 0;
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px 16px;
      font: inherit;
      background: rgba(255, 255, 255, 0.82);
      color: var(--text);
    }
    code, pre {
      font-family: "IBM Plex Mono", SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      color: var(--code);
    }
    code {
      padding: 0.1em 0.35em;
      border-radius: 0.4em;
      background: rgba(12, 122, 107, 0.08);
    }
    pre {
      margin: 14px 0 0;
      padding: 16px;
      border-radius: 14px;
      border: 1px solid var(--line);
      background: #fffdf8;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 280px;
      overflow: auto;
    }
    .url-box {
      display: grid;
      gap: 10px;
      padding: 16px;
      background: rgba(223, 243, 238, 0.6);
      border-radius: 14px;
      border: 1px solid rgba(12, 122, 107, 0.14);
    }
    .url-box.hidden {
      display: none;
    }
    .link-box {
      display: block;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.85);
      word-break: break-all;
    }
    .hint,
    .muted {
      color: var(--muted);
      font-size: 0.95rem;
    }
    dl {
      margin: 0;
    }
    .kv,
    .state-list {
      display: grid;
      grid-template-columns: minmax(140px, 180px) 1fr;
      gap: 8px 12px;
      font-size: 0.97rem;
    }
    .kv dt,
    .state-list dt {
      color: var(--muted);
    }
    summary {
      cursor: pointer;
      font-weight: 700;
    }
    details[open] summary {
      margin-bottom: 14px;
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation: none !important;
        transition: none !important;
        scroll-behavior: auto !important;
      }
    }
    @media (max-width: 640px) {
      .chip-row,
      .kv,
      .state-list {
        grid-template-columns: 1fr;
      }
      .hero,
      .panel,
      .step {
        border-radius: 18px;
      }
      .step-head {
        flex-direction: column;
      }
    }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="eyebrow">Claude Max Proxy</div>
      <h1>Setup Claude login</h1>
      <p class="lead">Use this page to authenticate the server with Claude Code CLI. Start the login, let the browser complete sign-in, then wait for the status here to switch to logged in. Pasting a code is only a fallback now.</p>
      <div id="statusBanner" class="banner" role="status" aria-live="polite"></div>
      <div id="summaryChips" class="chip-row" aria-live="polite"></div>
    </section>

    <section class="panel" aria-labelledby="setup-steps-title">
      <h2 id="setup-steps-title">Browser-first login</h2>
      <ol class="steps">
        <li class="step">
          <div class="step-head">
            <div class="row">
              <span class="step-number">1</span>
              <div>
                <div class="step-title">Start a server-side Claude login</div>
                <div class="step-copy">This launches <code>claude auth login</code> inside the running proxy and prepares the browser sign-in flow.</div>
              </div>
            </div>
            <span id="stepStartStatus" class="step-status">Idle</span>
          </div>
          <div class="actions">
            <button id="startButton">Start Login</button>
            <button id="cancelButton" class="secondary">Cancel</button>
            <button id="refreshButton" class="secondary">Refresh</button>
          </div>
        </li>
        <li class="step">
          <div class="step-head">
            <div class="row">
              <span class="step-number">2</span>
              <div>
                <div class="step-title">Finish sign-in in the browser</div>
                <div class="step-copy">The page will try to open the newest Claude sign-in link automatically. If it cannot, use the button below.</div>
              </div>
            </div>
            <span id="stepLinkStatus" class="step-status">Waiting</span>
          </div>
          <div id="authUrlBox" class="url-box hidden" aria-live="polite">
            <a id="authUrlLink" class="link-box" href="#" target="_blank" rel="noreferrer"></a>
            <div class="url-actions">
              <button id="openAuthLinkButton">Open Link</button>
              <button id="copyAuthLinkButton" class="secondary">Copy Link</button>
            </div>
          </div>
          <p id="authUrlEmptyState" class="hint">The sign-in link appears here after you start the login.</p>
          <p class="hint" style="margin-top: 10px;">Most setups do not need a pasted auth code. Complete sign-in in the browser and then wait a few seconds for this page to detect the authenticated Claude CLI session.</p>
          <p class="hint" style="margin-top: 10px;">If Anthropic shows <code>Authorization failed</code>, <code>Internal server error</code>, or <code>upstream connect error ... overflow</code> after sign-in, copy the full browser address from that error page and paste it into the fallback field below. If the address contains <code>code=</code>, this setup page can still extract it.</p>
          <p class="hint" style="margin-top: 8px;">The <code>overflow</code> variant usually points to Anthropic-side cookies, a browser extension, or a proxy in front of <code>claude.ai</code>. Retry in a private window or another browser before starting a fresh login.</p>
        </li>
        <li class="step">
          <div class="step-head">
            <div class="row">
              <span class="step-number">3</span>
              <div>
                <div class="step-title">Optional fallback</div>
                <div class="step-copy">Only use this if browser sign-in finishes on an error page that still contains a Claude callback URL or raw auth code.</div>
              </div>
            </div>
            <span id="stepSubmitStatus" class="step-status">Optional</span>
          </div>
          <label for="authCode">Callback URL or Claude code</label>
          <div class="input-row">
            <input
              id="authCode"
              type="text"
              placeholder="Only paste this if browser sign-in did not complete by itself"
              autocomplete="off"
              aria-describedby="authCodeHint"
            />
            <button id="submitCodeButton" class="secondary">Submit Fallback</button>
          </div>
          <p id="authCodeHint" class="hint">If browser sign-in succeeds normally, leave this empty. If you do need it, pasting the full callback URL is preferred because it avoids truncated-code mistakes.</p>
        </li>
      </ol>
    </section>

    <section class="panel" aria-labelledby="state-title">
      <h2 id="state-title">Current state</h2>
      <dl id="currentState" class="state-list"></dl>
    </section>

    <details class="panel">
      <summary>Diagnostics</summary>
      <p class="muted">Use your public server URL with <code>/v1</code> as the OpenAI-compatible base URL after login succeeds. If <code>ADMIN_TOKEN</code> is configured, keep this page URL private.</p>
      <dl id="details" class="kv" style="margin-top: 14px;"></dl>
      <pre id="logOutput">Waiting for status...</pre>
    </details>
  </main>

  <script>
    const token = ${JSON.stringify(token)};
    const statusUrl = token ? '/api/setup/status?token=' + encodeURIComponent(token) : '/api/setup/status';
    let lastStatus = null;
    let isBusy = false;
    let pendingAuthPopup = null;

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
      banner.className = 'banner visible ' + tone;
    }

    function clearBanner() {
      const banner = byId('statusBanner');
      banner.textContent = '';
      banner.className = 'banner';
    }

    function setBusy(nextBusy) {
      isBusy = nextBusy;
      const status = lastStatus;
      const active = Boolean(status && status.loginFlow && status.loginFlow.active);
      const waitingForCode = Boolean(
        status &&
        status.loginFlow &&
        status.loginFlow.phase === 'waiting_for_code'
      );
      const isSubmitting = Boolean(
        status &&
        status.loginFlow &&
        status.loginFlow.phase === 'submitting_code'
      );
      const isLoggedIn = Boolean(status && status.auth && status.auth.loggedIn);

      byId('startButton').disabled = nextBusy || active || isLoggedIn;
      byId('cancelButton').disabled = nextBusy || !active;
      byId('submitCodeButton').disabled = nextBusy || !waitingForCode || isSubmitting;
      byId('refreshButton').disabled = nextBusy;
      byId('copyAuthLinkButton').disabled = nextBusy || !(status && status.loginFlow && status.loginFlow.authUrl);
      byId('openAuthLinkButton').disabled = nextBusy || !(status && status.loginFlow && status.loginFlow.authUrl);
    }

    function openPendingAuthPopup() {
      if (pendingAuthPopup && !pendingAuthPopup.closed) {
        return;
      }

      try {
        pendingAuthPopup = window.open('', 'claude-auth-login');
        if (pendingAuthPopup && pendingAuthPopup.document) {
          pendingAuthPopup.document.title = 'Claude sign-in';
          pendingAuthPopup.document.body.innerHTML = '<p style="font-family: sans-serif; padding: 24px;">Waiting for Claude sign-in URL...</p>';
        }
      } catch {
        pendingAuthPopup = null;
      }
    }

    function maybeNavigatePendingPopup(authUrl) {
      if (!authUrl || !pendingAuthPopup || pendingAuthPopup.closed) {
        return;
      }

      try {
        pendingAuthPopup.location.href = authUrl;
        pendingAuthPopup.focus();
      } catch {
        // Ignore popup navigation errors and keep manual buttons available.
      } finally {
        pendingAuthPopup = null;
      }
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

    function renderSummary(status) {
      const auth = status.auth;
      const chips = [
        {
          label: 'Claude CLI',
          value: status.claudeCli.ok ? 'Installed' : 'Missing',
          className: status.claudeCli.ok ? 'good' : 'bad',
        },
        {
          label: 'Auth',
          value: auth.loggedIn ? 'Logged in' : 'Not logged in',
          className: auth.loggedIn ? 'good' : 'warn',
        },
        {
          label: 'Account',
          value: auth.email || 'No account yet',
          className: auth.loggedIn ? 'good' : '',
        },
        {
          label: 'Subscription',
          value: auth.subscriptionType || 'Unknown',
          className: auth.loggedIn ? 'good' : '',
        },
      ];

      byId('summaryChips').innerHTML = chips.map((item) => {
        const valueClass = item.className ? ' class="' + escapeHtml(item.className) + '"' : '';
        return '<div class="chip">'
          + '<span class="chip-label">' + escapeHtml(item.label) + '</span>'
          + '<strong' + valueClass + '>' + escapeHtml(item.value) + '</strong>'
          + '</div>';
      }).join('');
    }

    function renderDetails(status) {
      const details = [
        ['Host', status.runtime.host + ':' + status.runtime.port],
        ['CLI version', status.claudeCli.version || 'unknown'],
        ['Auth method', status.auth.authMethod || 'unknown'],
        ['API provider', status.auth.apiProvider || 'unknown'],
        ['Config dir', status.configDirectory.path + (status.configDirectory.exists ? '' : ' (missing)')],
        ['Config entries', status.configDirectory.entries.join(', ') || 'none'],
        ['Admin token', status.runtime.adminTokenConfigured ? 'configured' : 'not configured'],
        ['CORS allow origin', status.runtime.corsAllowOrigin],
        ['Dangerous skip perms', String(status.runtime.dangerousSkipPermissions)],
        ['OAuth env token', String(status.envTokens.oauthTokenConfigured)],
        ['OAuth FD token', String(status.envTokens.oauthFdConfigured)],
        ['Anthropic API key', String(status.envTokens.anthropicApiKeyConfigured)],
      ];

      byId('details').innerHTML = details.map(([key, value]) => {
        return '<dt>' + escapeHtml(key) + '</dt><dd>' + escapeHtml(value) + '</dd>';
      }).join('');
    }

    function updateStepStatus(elementId, label, tone) {
      const element = byId(elementId);
      element.textContent = label;
      element.className = tone ? 'step-status ' + tone : 'step-status';
    }

    function renderCurrentState(status) {
      const loginFlow = status.loginFlow;
      const entries = [
        ['Login phase', loginFlow.phase],
        ['Claude logged in', status.auth.loggedIn ? 'yes' : 'no'],
        ['Active login process', loginFlow.active ? 'yes' : 'no'],
        ['Started', loginFlow.startedAt || 'not started'],
        ['Finished', loginFlow.finishedAt || 'not finished'],
      ];

      if (status.auth.email) {
        entries.push(['Logged-in account', status.auth.email]);
      }

      if (loginFlow.error) {
        entries.push(['Last error', loginFlow.error]);
      }

      byId('currentState').innerHTML = entries.map(([key, value]) => {
        return '<dt>' + escapeHtml(key) + '</dt><dd>' + escapeHtml(value) + '</dd>';
      }).join('');
    }

    function renderLoginFlow(status) {
      lastStatus = status;
      const loginFlow = status.loginFlow;
      const urlBox = byId('authUrlBox');
      const urlLink = byId('authUrlLink');
      const emptyState = byId('authUrlEmptyState');
      const logOutput = byId('logOutput');

      if (loginFlow.authUrl) {
        urlBox.classList.remove('hidden');
        emptyState.style.display = 'none';
        urlLink.href = loginFlow.authUrl;
        urlLink.textContent = loginFlow.authUrl;
        maybeNavigatePendingPopup(loginFlow.authUrl);
      } else {
        urlBox.classList.add('hidden');
        emptyState.style.display = 'block';
        urlLink.href = '#';
        urlLink.textContent = '';
      }

      logOutput.textContent = loginFlow.logs.join('\\n') || 'No login process output yet.';

      updateStepStatus(
        'stepStartStatus',
        status.auth.loggedIn ? 'Done' : loginFlow.active ? 'Running' : loginFlow.startedAt ? 'Started' : 'Idle',
        status.auth.loggedIn ? 'good' : loginFlow.active ? 'warn' : ''
      );
      updateStepStatus(
        'stepLinkStatus',
        loginFlow.authUrl ? 'Ready' : status.auth.loggedIn ? 'Done' : 'Waiting',
        status.auth.loggedIn || loginFlow.authUrl ? 'good' : ''
      );
      updateStepStatus(
        'stepSubmitStatus',
        status.auth.loggedIn
          ? 'Done'
          : loginFlow.phase === 'submitting_code'
            ? 'Checking'
            : loginFlow.phase === 'waiting_for_code'
              ? 'Fallback'
              : 'Optional',
        status.auth.loggedIn ? 'good' : loginFlow.phase === 'submitting_code' ? 'warn' : ''
      );

      if (status.auth.loggedIn) {
        setBanner('Claude CLI is authenticated. Point your OpenAI-compatible client at /v1 on this server.', 'good');
      } else if (loginFlow.phase === 'waiting_for_code' && loginFlow.authUrl) {
        setBanner('Claude login is waiting for the browser flow to finish. Complete sign-in in the browser and wait here. Only use the fallback field if the browser ends on an error page that still includes the callback URL or code.', 'warn');
      } else if (loginFlow.phase === 'submitting_code') {
        setBanner('Fallback value submitted. Waiting for Claude CLI to confirm the login.', 'warn');
      } else if (loginFlow.phase === 'failed') {
        setBanner(loginFlow.error || 'Claude login failed. Start again and complete the browser sign-in with the newest link.', 'bad');
      } else if (loginFlow.phase === 'starting') {
        setBanner('Starting Claude login. A browser tab should open as soon as the sign-in link is ready.', 'warn');
      } else if (loginFlow.phase === 'cancelled') {
        setBanner('Claude login was cancelled. Start a fresh login when you are ready.', 'warn');
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

      renderSummary(status);
      renderCurrentState(status);
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
      openPendingAuthPopup();
      await runAction(async () => {
        await callApi('/api/setup/auth/start', 'POST');
      }, 'Claude login started. Complete sign-in in the browser, then wait for this page to detect the session.');
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
        setBanner('Paste the Claude code or callback URL before submitting.', 'bad');
        return;
      }
      await runAction(async () => {
        await callApi('/api/setup/auth/submit', 'POST', { code: code });
        byId('authCode').value = '';
      }, 'Fallback value submitted. Waiting for Claude CLI to finish login.');
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
    }, 3000);
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