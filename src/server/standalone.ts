#!/usr/bin/env node
/**
 * Standalone server for testing without Clawdbot
 *
 * Usage:
 *   npm run start
 *   # or
 *   node dist/server/standalone.js [port]
 */

import { startServer, stopServer } from "./index.js";
import { verifyClaude, verifyAuth } from "../subprocess/manager.js";

const DEFAULT_PORT = 3456;
const DEFAULT_HOST = "0.0.0.0";

interface StandaloneConfig {
  readonly port: number;
  readonly host: string;
}

function parsePort(value: string | undefined, fallback: number): number {
  if (!value) {
    return fallback;
  }

  const parsed = Number.parseInt(value, 10);
  if (Number.isNaN(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`Invalid port: ${value}`);
  }

  return parsed;
}

function parseArgs(argv: readonly string[]): StandaloneConfig {
  let port = parsePort(process.env.PORT, DEFAULT_PORT);
  let host = process.env.HOST || DEFAULT_HOST;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--help" || arg === "-h") {
      console.log("Usage: node dist/server/standalone.js [port] [--host HOST] [--port PORT]");
      process.exit(0);
    }

    if (arg === "--host") {
      const value = argv[index + 1];
      if (!value) {
        throw new Error("Missing value for --host");
      }
      host = value;
      index += 1;
      continue;
    }

    if (arg === "--port") {
      const value = argv[index + 1];
      if (!value) {
        throw new Error("Missing value for --port");
      }
      port = parsePort(value, port);
      index += 1;
      continue;
    }

    if (arg.startsWith("--host=")) {
      host = arg.slice("--host=".length);
      continue;
    }

    if (arg.startsWith("--port=")) {
      port = parsePort(arg.slice("--port=".length), port);
      continue;
    }

    if (!arg.startsWith("-")) {
      port = parsePort(arg, port);
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  if (!host.trim()) {
    throw new Error("Host cannot be empty");
  }

  return { port, host };
}

async function main(): Promise<void> {
  console.log("Claude Code CLI Provider - Standalone Server");
  console.log("============================================\n");

  let config: StandaloneConfig;
  try {
    config = parseArgs(process.argv.slice(2));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(message);
    process.exit(1);
  }
  const { port, host } = config;

  // Verify Claude CLI
  console.log("Checking Claude CLI...");
  const cliCheck = await verifyClaude();
  if (!cliCheck.ok) {
    console.error(`Error: ${cliCheck.error}`);
    process.exit(1);
  }
  console.log(`  Claude CLI: ${cliCheck.version || "OK"}`);

  // Verify authentication
  console.log("Checking authentication...");
  const authCheck = await verifyAuth();
  if (!authCheck.ok) {
    console.error(`Error: ${authCheck.error}`);
    console.error("Please run: claude auth login");
    process.exit(1);
  }
  console.log("  Authentication: OK\n");

  // Start server
  try {
    await startServer({ port, host });
    console.log("\nServer ready. Test with:");
    console.log(`  curl -X POST http://localhost:${port}/v1/chat/completions \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"model": "claude-sonnet-4", "messages": [{"role": "user", "content": "Hello!"}]}'`);
    console.log("\nPress Ctrl+C to stop.\n");
  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }

  // Handle graceful shutdown
  const shutdown = async () => {
    console.log("\nShutting down...");
    await stopServer();
    process.exit(0);
  };

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error("Unexpected error:", err);
  process.exit(1);
});
