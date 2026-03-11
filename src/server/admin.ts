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
  <title>Claude Max Proxy — Setup</title>
  <style>
    :root {
      --bg: #0d1117;
      --bg2: #161b22;
      --bg3: #1c2128;
      --border: #30363d;
      --border-subtle: #21262d;
      --text: #e6edf3;
      --text-muted: #7d8590;
      --text-subtle: #484f58;
      --accent: #58a6ff;
      --accent-muted: rgba(88,166,255,0.15);
      --green: #3fb950;
      --green-muted: rgba(63,185,80,0.15);
      --red: #f85149;
      --red-muted: rgba(248,81,73,0.15);
      --yellow: #d29922;
      --yellow-muted: rgba(210,153,34,0.15);
      --purple: #bc8cff;
      --purple-muted: rgba(188,140,255,0.15);
      --radius: 8px;
      --radius-lg: 12px;
      --shadow: 0 1px 3px rgba(0,0,0,0.4), 0 4px 12px rgba(0,0,0,0.25);
    }
    *, *::before, *::after { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "Noto Sans", Helvetica, Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      background: var(--bg);
      color: var(--text);
    }
    /* ── Layout ── */
    .topbar {
      border-bottom: 1px solid var(--border);
      background: var(--bg2);
      padding: 0 24px;
      display: flex;
      align-items: center;
      gap: 12px;
      height: 56px;
      position: sticky;
      top: 0;
      z-index: 10;
    }
    .topbar-logo {
      display: flex;
      align-items: center;
      gap: 8px;
      font-weight: 600;
      font-size: 15px;
      color: var(--text);
      text-decoration: none;
    }
    .topbar-logo svg { opacity: 0.85; }
    .topbar-sep { width: 1px; height: 20px; background: var(--border); }
    .topbar-title { color: var(--text-muted); font-size: 13px; }
    .topbar-spacer { flex: 1; }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 8px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 500;
      border: 1px solid transparent;
    }
    .badge-green  { background: var(--green-muted);  border-color: rgba(63,185,80,0.3);   color: var(--green);  }
    .badge-red    { background: var(--red-muted);    border-color: rgba(248,81,73,0.3);   color: var(--red);    }
    .badge-yellow { background: var(--yellow-muted); border-color: rgba(210,153,34,0.3);  color: var(--yellow); }
    .badge-blue   { background: var(--accent-muted); border-color: rgba(88,166,255,0.3);  color: var(--accent); }
    .badge-purple { background: var(--purple-muted); border-color: rgba(188,140,255,0.3); color: var(--purple); }
    .badge .dot {
      width: 6px; height: 6px;
      border-radius: 50%;
      background: currentColor;
      flex-shrink: 0;
    }
    .badge .dot.pulse { animation: dot-pulse 2s ease infinite; }
    @keyframes dot-pulse {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.35; }
    }
    .container { max-width: 960px; margin: 0 auto; padding: 32px 24px 64px; }
    /* ── Page header ── */
    .page-header { margin-bottom: 24px; }
    .page-header h1 {
      margin: 0 0 6px;
      font-size: 22px;
      font-weight: 600;
      letter-spacing: -0.3px;
    }
    .page-header p { margin: 0; color: var(--text-muted); }
    /* ── Alert banner ── */
    .alert {
      display: none;
      align-items: flex-start;
      gap: 10px;
      padding: 12px 14px;
      border-radius: var(--radius);
      border: 1px solid transparent;
      margin-bottom: 20px;
      font-size: 13.5px;
      line-height: 1.45;
    }
    .alert.visible { display: flex; }
    .alert-icon { flex-shrink: 0; margin-top: 1px; }
    .alert.good   { background: var(--green-muted);  border-color: rgba(63,185,80,0.35);   color: #7ee787; }
    .alert.warn   { background: var(--yellow-muted); border-color: rgba(210,153,34,0.35);  color: #e3b341; }
    .alert.bad    { background: var(--red-muted);    border-color: rgba(248,81,73,0.35);   color: #ff7b72; }
    /* ── Status cards ── */
    .cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      padding: 16px;
    }
    .stat-card-label {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-muted);
      margin-bottom: 8px;
    }
    .stat-card-value {
      font-size: 18px;
      font-weight: 600;
      letter-spacing: -0.3px;
      margin-bottom: 4px;
    }
    .stat-card-detail { font-size: 12px; color: var(--text-muted); }
    .stat-card-value.good   { color: var(--green);  }
    .stat-card-value.bad    { color: var(--red);    }
    .stat-card-value.warn   { color: var(--yellow); }
    .stat-card-value.blue   { color: var(--accent); }
    /* ── Main layout ── */
    .main-grid {
      display: grid;
      grid-template-columns: 1fr 340px;
      gap: 16px;
      align-items: start;
    }
    /* ── Panel ── */
    .panel {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius-lg);
      overflow: hidden;
    }
    .panel-header {
      padding: 14px 16px;
      border-bottom: 1px solid var(--border-subtle);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }
    .panel-title {
      font-size: 13px;
      font-weight: 600;
      color: var(--text);
      margin: 0;
    }
    .panel-body { padding: 16px; }
    /* ── Steps ── */
    .steps { display: grid; gap: 0; }
    .step {
      display: grid;
      grid-template-columns: 36px 1fr;
      gap: 0 14px;
      position: relative;
    }
    .step:not(:last-child) .step-line::after {
      content: "";
      position: absolute;
      top: 36px;
      left: 17px;
      width: 2px;
      bottom: 0;
      background: var(--border);
    }
    .step-num-col {
      display: flex;
      flex-direction: column;
      align-items: center;
      position: relative;
    }
    .step-num {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      border: 2px solid var(--border);
      background: var(--bg3);
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 13px;
      font-weight: 600;
      color: var(--text-muted);
      flex-shrink: 0;
      position: relative;
      z-index: 1;
      transition: background 0.2s, border-color 0.2s, color 0.2s;
    }
    .step-connector {
      flex: 1;
      width: 2px;
      background: var(--border);
      margin: 4px 0;
      min-height: 16px;
    }
    .step-content {
      padding: 4px 0 20px;
    }
    .step-content-title {
      font-size: 13.5px;
      font-weight: 600;
      margin: 4px 0 6px;
    }
    .step-content-body { font-size: 13px; color: var(--text-muted); }
    /* Step states */
    .step.active   .step-num { border-color: var(--accent); background: var(--accent-muted); color: var(--accent); }
    .step.done     .step-num { border-color: var(--green);  background: var(--green-muted);  color: var(--green);  }
    .step.error    .step-num { border-color: var(--red);    background: var(--red-muted);    color: var(--red);    }
    .step.active   .step-content-title { color: var(--accent); }
    .step.done     .step-content-title { color: var(--green);  }
    .step.error    .step-content-title { color: var(--red);    }
    /* ── Buttons ── */
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 14px;
      border-radius: var(--radius);
      border: 1px solid transparent;
      font: inherit;
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.15s, border-color 0.15s, opacity 0.15s, box-shadow 0.15s;
      white-space: nowrap;
    }
    .btn-primary {
      background: #238636;
      border-color: rgba(240,246,252,0.1);
      color: #fff;
    }
    .btn-primary:hover:not(:disabled) { background: #2ea043; box-shadow: 0 0 0 3px rgba(46,160,67,0.3); }
    .btn-default {
      background: var(--bg3);
      border-color: var(--border);
      color: var(--text);
    }
    .btn-default:hover:not(:disabled) { background: #30363d; }
    .btn-accent {
      background: var(--accent-muted);
      border-color: rgba(88,166,255,0.35);
      color: var(--accent);
    }
    .btn-accent:hover:not(:disabled) { background: rgba(88,166,255,0.25); }
    .btn-danger {
      background: var(--red-muted);
      border-color: rgba(248,81,73,0.35);
      color: var(--red);
    }
    .btn-danger:hover:not(:disabled) { background: rgba(248,81,73,0.25); }
    .btn:disabled { opacity: 0.45; cursor: not-allowed; }
    .btn:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .btn-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    /* ── URL box ── */
    .url-reveal {
      display: none;
      margin-top: 12px;
    }
    .url-reveal.visible { display: block; }
    .url-box {
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 10px 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      color: var(--accent);
      word-break: break-all;
      line-height: 1.5;
      margin-bottom: 10px;
    }
    /* ── Input ── */
    .input-group { display: grid; gap: 6px; }
    .input-label { font-size: 12px; font-weight: 500; color: var(--text-muted); }
    .input-field {
      width: 100%;
      padding: 7px 11px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      font: inherit;
      font-size: 13px;
      color: var(--text);
      transition: border-color 0.15s, box-shadow 0.15s;
    }
    .input-field:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px var(--accent-muted);
    }
    .input-hint { font-size: 12px; color: var(--text-subtle); }
    /* ── Log output ── */
    .log-output {
      margin: 0;
      padding: 12px 14px;
      background: var(--bg);
      border-radius: var(--radius);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
      color: #8b949e;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 280px;
      overflow-y: auto;
      line-height: 1.6;
    }
    /* ── KV list ── */
    .kv-list { display: grid; gap: 1px; }
    .kv-row {
      display: grid;
      grid-template-columns: 148px 1fr;
      gap: 8px;
      padding: 7px 0;
      border-bottom: 1px solid var(--border-subtle);
      font-size: 12.5px;
    }
    .kv-row:last-child { border-bottom: none; }
    .kv-key { color: var(--text-muted); }
    .kv-val { color: var(--text); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11.5px; word-break: break-all; }
    /* ── Note list ── */
    .note-list { display: grid; gap: 10px; }
    .note-item { font-size: 12.5px; color: var(--text-muted); line-height: 1.55; padding-left: 14px; position: relative; }
    .note-item::before { content: "·"; position: absolute; left: 0; color: var(--text-subtle); }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.92em; background: rgba(110,118,129,0.15); padding: 2px 5px; border-radius: 4px; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
    /* ── Divider ── */
    .divider { border: none; border-top: 1px solid var(--border-subtle); margin: 14px 0; }
    /* ── Loading state ── */
    #loadingOverlay {
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--text-muted);
      font-size: 13px;
      padding: 8px 0 16px;
    }
    #loadingOverlay.hidden { display: none; }
    .spinner {
      width: 16px; height: 16px;
      border: 2px solid var(--border);
      border-top-color: var(--accent);
      border-radius: 50%;
      animation: spin 0.7s linear infinite;
      flex-shrink: 0;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    /* ── Responsive ── */
    @media (max-width: 760px) {
      .main-grid { grid-template-columns: 1fr; }
      .topbar { padding: 0 16px; }
      .container { padding: 24px 16px 48px; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation: none !important;
        transition: none !important;
      }
    }
  </style>
</head>
<body>

  <!-- Top bar -->
  <header class="topbar">
    <span class="topbar-logo">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20A14.5 14.5 0 0 0 12 2"/><path d="M2 12h20"/>
      </svg>
      Claude Max Proxy
    </span>
    <span class="topbar-sep"></span>
    <span class="topbar-title">Setup &amp; Authentication</span>
    <span class="topbar-spacer"></span>
    <span id="topbarAuthBadge" class="badge badge-yellow"><span class="dot"></span> Checking…</span>
  </header>

  <main class="container">

    <!-- Page header -->
    <div class="page-header">
      <h1>Server Setup</h1>
      <p>Authenticate the Claude CLI so the proxy can forward requests to your Claude Max subscription.</p>
    </div>

    <!-- Loading indicator -->
    <div id="loadingOverlay">
      <div class="spinner"></div>
      Loading status…
    </div>

    <!-- Alert banner -->
    <div id="alertBanner" class="alert" role="status" aria-live="polite">
      <span class="alert-icon" id="alertIcon"></span>
      <span id="alertText"></span>
    </div>

    <!-- Status cards -->
    <div class="cards" id="statusCards">
      <div class="stat-card">
        <div class="stat-card-label">Claude CLI</div>
        <div class="stat-card-value" id="cardCliValue">—</div>
        <div class="stat-card-detail" id="cardCliDetail"></div>
      </div>
      <div class="stat-card">
        <div class="stat-card-label">Auth Status</div>
        <div class="stat-card-value" id="cardAuthValue">—</div>
        <div class="stat-card-detail" id="cardAuthDetail"></div>
      </div>
      <div class="stat-card">
        <div class="stat-card-label">Login Flow</div>
        <div class="stat-card-value" id="cardPhaseValue">—</div>
        <div class="stat-card-detail" id="cardPhaseDetail"></div>
      </div>
      <div class="stat-card">
        <div class="stat-card-label">Runtime</div>
        <div class="stat-card-value blue" id="cardRuntimeValue">—</div>
        <div class="stat-card-detail" id="cardRuntimeDetail"></div>
      </div>
    </div>

    <!-- Main content -->
    <div class="main-grid">

      <!-- Left: Setup wizard -->
      <div style="display:grid;gap:16px;">
        <div class="panel">
          <div class="panel-header">
            <h2 class="panel-title">Authentication Steps</h2>
            <button class="btn btn-default" id="refreshButton" style="padding:4px 10px;font-size:12px;">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>
              Refresh
            </button>
          </div>
          <div class="panel-body">

            <div class="steps">

              <!-- Step 1 -->
              <div class="step" id="step1">
                <div class="step-num-col">
                  <div class="step-num" id="stepNum1">1</div>
                  <div class="step-connector"></div>
                </div>
                <div class="step-content">
                  <div class="step-content-title">Start Claude Login</div>
                  <div class="step-content-body" style="margin-bottom:10px;">
                    Click the button below to start the <code>claude auth login</code> process on the server. A unique OAuth URL will be generated.
                  </div>
                  <div class="btn-row">
                    <button class="btn btn-primary" id="startButton" disabled>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polygon points="5 3 19 12 5 21 5 3"/></svg>
                      Start Login
                    </button>
                    <button class="btn btn-danger" id="cancelButton" disabled>Cancel</button>
                  </div>
                </div>
              </div>

              <!-- Step 2 -->
              <div class="step" id="step2">
                <div class="step-num-col">
                  <div class="step-num" id="stepNum2">2</div>
                  <div class="step-connector"></div>
                </div>
                <div class="step-content">
                  <div class="step-content-title">Open the URL in your browser</div>
                  <div class="step-content-body">
                    After starting login, an OAuth URL will appear below. Open it in your browser, sign in with your Claude account, and copy the auth code shown at the end.
                  </div>
                  <div class="url-reveal" id="authUrlBox" aria-live="polite">
                    <div class="url-box" id="authUrlText"></div>
                    <div class="btn-row">
                      <button class="btn btn-accent" id="openAuthLinkButton" disabled>
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
                        Open URL
                      </button>
                      <button class="btn btn-default" id="copyAuthLinkButton" disabled>
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        Copy URL
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <!-- Step 3 -->
              <div class="step" id="step3">
                <div class="step-num-col">
                  <div class="step-num" id="stepNum3">3</div>
                  <div class="step-connector"></div>
                </div>
                <div class="step-content">
                  <div class="step-content-title">Paste and submit the auth code</div>
                  <div class="step-content-body" style="margin-bottom:10px;">
                    After signing in with Claude, you'll receive a one-time auth code. Paste it below and click Submit.
                  </div>
                  <div class="input-group" style="margin-bottom:10px;">
                    <label class="input-label" for="authCode">Auth code</label>
                    <input class="input-field" id="authCode" type="text" placeholder="Paste your auth code here…" autocomplete="off" aria-describedby="authCodeHint" />
                    <span class="input-hint" id="authCodeHint">The code will be sent to the server-side login process via stdin.</span>
                  </div>
                  <button class="btn btn-primary" id="submitCodeButton" disabled>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
                    Submit Code
                  </button>
                </div>
              </div>

              <!-- Step 4 -->
              <div class="step" id="step4">
                <div class="step-num-col">
                  <div class="step-num" id="stepNum4">4</div>
                </div>
                <div class="step-content">
                  <div class="step-content-title">Done — proxy is ready</div>
                  <div class="step-content-body" id="step4Body">
                    Once auth status shows <strong>Logged In</strong>, the proxy is ready. Point any OpenAI-compatible client at <code>/v1</code> on this host.
                  </div>
                </div>
              </div>

            </div>
          </div>
        </div>

        <!-- Process log -->
        <div class="panel">
          <div class="panel-header">
            <h2 class="panel-title">Process Log</h2>
          </div>
          <div class="panel-body" style="padding:0;">
            <pre class="log-output" id="logOutput">Waiting for status…</pre>
          </div>
        </div>
      </div>

      <!-- Right: Diagnostics + Notes -->
      <div style="display:grid;gap:16px;">
        <div class="panel">
          <div class="panel-header">
            <h2 class="panel-title">Live Diagnostics</h2>
          </div>
          <div class="panel-body" style="padding:8px 16px;">
            <div class="kv-list" id="details"></div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-header">
            <h2 class="panel-title">Connection Notes</h2>
          </div>
          <div class="panel-body">
            <div class="note-list">
              <div class="note-item">Once authenticated, use <code>/v1</code> as the OpenAI-compatible base URL.</div>
              <div class="note-item">If auth stalls, cancel the flow, start fresh, and use the newest generated URL.</div>
              <div class="note-item">If <code>ADMIN_TOKEN</code> is set, keep this page URL private — the token in the query string grants admin access.</div>
              <div class="note-item">The proxy supports streaming and non-streaming requests to Claude Opus 4, Sonnet 4, and Haiku 4.</div>
            </div>
          </div>
        </div>
      </div>
    </div>

  </main>

  <script>
    const token = ${JSON.stringify(token)};
    const statusUrl = token ? '/api/setup/status?token=' + encodeURIComponent(token) : '/api/setup/status';
    let lastStatus = null;
    let isBusy = false;
    let initialized = false;

    function byId(id) { return document.getElementById(id); }

    function esc(v) {
      return String(v)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function apiUrl(path) {
      return token ? path + '?token=' + encodeURIComponent(token) : path;
    }

    /* ── Alert banner ── */
    function setAlert(message, tone) {
      const banner = byId('alertBanner');
      const icons = {
        good: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
        warn: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
        bad:  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
      };
      byId('alertIcon').innerHTML = icons[tone] || '';
      byId('alertText').textContent = message;
      banner.className = 'alert visible ' + tone;
    }

    function clearAlert() {
      byId('alertBanner').className = 'alert';
    }

    /* ── Button state ── */
    function setButtonStates() {
      const status = lastStatus;
      const flow = status && status.loginFlow;
      const active = Boolean(flow && flow.active);
      const phase = flow ? flow.phase : 'idle';
      const hasUrl = Boolean(flow && flow.authUrl);
      const loggedIn = Boolean(status && status.auth && status.auth.loggedIn);

      // Submit is enabled when we have a code-waiting phase OR active session
      // This prevents the button from staying disabled if the process briefly
      // transitions between states while the user is pasting their code.
      const canSubmit = active || phase === 'waiting_for_code' || phase === 'submitting_code';

      byId('startButton').disabled        = isBusy || active || loggedIn;
      byId('cancelButton').disabled       = isBusy || !active;
      byId('submitCodeButton').disabled   = isBusy || !canSubmit;
      byId('refreshButton').disabled      = isBusy;
      byId('copyAuthLinkButton').disabled = isBusy || !hasUrl;
      byId('openAuthLinkButton').disabled = isBusy || !hasUrl;
    }

    /* ── Step highlights ── */
    function updateSteps(status) {
      const flow = status && status.loginFlow;
      const phase = flow ? flow.phase : 'idle';
      const loggedIn = Boolean(status && status.auth && status.auth.loggedIn);
      const hasUrl = Boolean(flow && flow.authUrl);

      const s1 = byId('step1'), s2 = byId('step2'), s3 = byId('step3'), s4 = byId('step4');
      const n1 = byId('stepNum1'), n2 = byId('stepNum2'), n3 = byId('stepNum3'), n4 = byId('stepNum4');

      // Reset
      [s1, s2, s3, s4].forEach((s) => s.className = 'step');

      if (loggedIn) {
        s1.className = 'step done'; n1.textContent = '✓';
        s2.className = 'step done'; n2.textContent = '✓';
        s3.className = 'step done'; n3.textContent = '✓';
        s4.className = 'step done'; n4.textContent = '✓';
      } else if (phase === 'submitting_code') {
        s1.className = 'step done'; n1.textContent = '✓';
        s2.className = 'step done'; n2.textContent = '✓';
        s3.className = 'step active';
      } else if (phase === 'waiting_for_code' && hasUrl) {
        s1.className = 'step done'; n1.textContent = '✓';
        s2.className = 'step active';
        s3.className = 'step active';
      } else if (phase === 'starting') {
        s1.className = 'step active';
      } else if (phase === 'failed') {
        s1.className = 'step error'; n1.textContent = '!';
      } else if (phase === 'cancelled') {
        // back to idle
      }
    }

    /* ── API call ── */
    async function callApi(path, method, body) {
      const response = await fetch(apiUrl(path), {
        method: method || 'GET',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'X-Admin-Token': token } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload && payload.error && payload.error.message ? payload.error.message : 'Request failed with status ' + response.status);
      }
      return payload;
    }

    /* ── Render status ── */
    function renderStatus(status) {
      lastStatus = status;

      // Top-bar badge
      const topBadge = byId('topbarAuthBadge');
      if (status.auth.loggedIn) {
        topBadge.className = 'badge badge-green';
        topBadge.innerHTML = '<span class="dot"></span> Authenticated';
      } else {
        topBadge.className = 'badge badge-yellow';
        topBadge.innerHTML = '<span class="dot pulse"></span> Not authenticated';
      }

      // Stat cards
      const cli = status.claudeCli;
      byId('cardCliValue').textContent = cli.ok ? 'Installed' : 'Missing';
      byId('cardCliValue').className = 'stat-card-value ' + (cli.ok ? 'good' : 'bad');
      byId('cardCliDetail').textContent = cli.version || cli.error || 'Unknown';

      const auth = status.auth;
      byId('cardAuthValue').textContent = auth.loggedIn ? 'Logged In' : 'Logged Out';
      byId('cardAuthValue').className = 'stat-card-value ' + (auth.loggedIn ? 'good' : 'warn');
      byId('cardAuthDetail').textContent = (auth.authMethod || 'unknown') + ' · ' + (auth.apiProvider || 'unknown');

      const flow = status.loginFlow;
      byId('cardPhaseValue').textContent = flow.phase;
      byId('cardPhaseValue').className = 'stat-card-value ' + (flow.phase === 'failed' ? 'bad' : flow.phase === 'succeeded' ? 'good' : flow.phase === 'idle' ? '' : 'blue');
      byId('cardPhaseDetail').textContent = flow.active ? 'process running' : 'no active process';

      byId('cardRuntimeValue').textContent = status.runtime.host + ':' + status.runtime.port;
      byId('cardRuntimeDetail').textContent = 'uptime ' + status.uptimeSeconds + 's · node ' + status.runtime.nodeVersion;

      // Auth URL box
      const urlBox = byId('authUrlBox');
      const urlText = byId('authUrlText');
      if (flow.authUrl) {
        urlBox.classList.add('visible');
        urlText.textContent = flow.authUrl;
      } else {
        urlBox.classList.remove('visible');
        urlText.textContent = '';
      }

      // Log output
      byId('logOutput').textContent = flow.logs.length ? flow.logs.join('\\n') : 'No process output yet.';

      // Diagnostics
      const pairs = [
        ['Config dir',    status.configDirectory.path + (status.configDirectory.exists ? '' : ' (missing)')],
        ['Config files',  status.configDirectory.entries.join(', ') || 'none'],
        ['Admin token',   status.runtime.adminTokenConfigured ? 'configured' : 'not set'],
        ['Skip perms',    String(status.runtime.dangerousSkipPermissions)],
        ['CORS origin',   status.runtime.corsAllowOrigin],
        ['OAuth token',   String(status.envTokens.oauthTokenConfigured)],
        ['OAuth FD',      String(status.envTokens.oauthFdConfigured)],
        ['Anthropic key', String(status.envTokens.anthropicApiKeyConfigured)],
        ['Auth method',   status.auth.authMethod || 'unknown'],
        ['CLI version',   status.claudeCli.version || 'unknown'],
      ];
      byId('details').innerHTML = pairs.map(([k, v]) =>
        '<div class="kv-row"><div class="kv-key">' + esc(k) + '</div><div class="kv-val">' + esc(v) + '</div></div>'
      ).join('');

      // Alert banner
      if (auth.loggedIn) {
        setAlert('Claude CLI is authenticated. Your proxy is ready for OpenAI-compatible client traffic.', 'good');
      } else if (flow.phase === 'waiting_for_code' && flow.authUrl) {
        setAlert('Open the URL in your browser, complete sign-in, then paste the auth code in Step 3.', 'warn');
      } else if (flow.phase === 'submitting_code') {
        setAlert('Submitting auth code… waiting for the login process to complete.', 'warn');
      } else if (flow.phase === 'starting') {
        setAlert('Starting Claude login process — a URL will appear shortly.', 'warn');
      } else if (flow.phase === 'failed') {
        setAlert(flow.error || 'Claude login failed. Cancel and start a fresh login attempt.', 'bad');
      } else if (flow.phase === 'cancelled') {
        setAlert('Login was cancelled. Click Start Login to try again.', 'warn');
      } else {
        clearAlert();
      }

      // Step highlights
      updateSteps(status);

      // Button states
      setButtonStates();
    }

    /* ── Refresh ── */
    async function refreshStatus() {
      const res = await fetch(statusUrl, {
        headers: token ? { 'X-Admin-Token': token } : {},
      });
      const status = await res.json();
      if (!res.ok) {
        throw new Error(status && status.error && status.error.message ? status.error.message : 'Failed to load status');
      }
      renderStatus(status);

      if (!initialized) {
        initialized = true;
        const overlay = byId('loadingOverlay');
        if (overlay) overlay.className = 'hidden';
      }
    }

    /* ── runAction helper ── */
    async function runAction(action, successMessage) {
      try {
        isBusy = true;
        setButtonStates();
        clearAlert();
        await action();
        await refreshStatus();
        if (successMessage) setAlert(successMessage, 'good');
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Request failed';
        setAlert(msg, 'bad');
        byId('logOutput').textContent = msg;
      } finally {
        isBusy = false;
        setButtonStates();
      }
    }

    /* ── Event listeners ── */
    byId('startButton').addEventListener('click', () =>
      runAction(() => callApi('/api/setup/auth/start', 'POST'))
    );

    byId('cancelButton').addEventListener('click', () =>
      runAction(() => callApi('/api/setup/auth/cancel', 'POST'), 'Login cancelled.')
    );

    byId('refreshButton').addEventListener('click', () =>
      runAction(() => refreshStatus())
    );

    byId('submitCodeButton').addEventListener('click', () => {
      const code = byId('authCode').value.trim();
      if (!code) {
        setAlert('Paste the auth code into the field above before submitting.', 'bad');
        const authCodeEl = byId('authCode');
        if (authCodeEl && !authCodeEl.disabled) authCodeEl.focus();
        return;
      }
      runAction(async () => {
        await callApi('/api/setup/auth/submit', 'POST', { code });
        byId('authCode').value = '';
      }, 'Auth code submitted — waiting for login to complete.');
    });

    byId('authCode').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); byId('submitCodeButton').click(); }
    });

    byId('openAuthLinkButton').addEventListener('click', () => {
      const url = lastStatus && lastStatus.loginFlow && lastStatus.loginFlow.authUrl;
      if (!url) { setAlert('No login URL yet — start the login first.', 'bad'); return; }
      window.open(url, '_blank', 'noopener,noreferrer');
    });

    byId('copyAuthLinkButton').addEventListener('click', async () => {
      const url = lastStatus && lastStatus.loginFlow && lastStatus.loginFlow.authUrl;
      if (!url) { setAlert('No login URL yet — start the login first.', 'bad'); return; }
      try {
        await navigator.clipboard.writeText(url);
        setAlert('URL copied to clipboard.', 'good');
      } catch {
        setAlert('Clipboard write failed. Copy the URL from the box manually.', 'warn');
      }
    });

    /* ── Init ── */
    refreshStatus().catch((err) => {
      initialized = true;
      const overlay = byId('loadingOverlay');
      if (overlay) overlay.className = 'hidden';
      const msg = err instanceof Error ? err.message : 'Failed to load status';
      setAlert(msg, 'bad');
      byId('logOutput').textContent = msg;
    });

    setInterval(() => {
      if (!isBusy) {
        refreshStatus().catch(() => { /* silent — don't overwrite user-visible state */ });
      }
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