/**
 * Express HTTP Server
 *
 * Provides OpenAI-compatible API endpoints that wrap Claude Code CLI
 */

import express, { Express, Request, Response, NextFunction } from "express";
import { createServer, Server } from "http";
import {
  handleCancelAuth,
  handleChatCompletions,
  handleHealth,
  handleModels,
  handleSetupPage,
  handleSetupStatus,
  handleStartAuth,
  handleSubmitAuthCode,
} from "./routes.js";

export interface ServerConfig {
  port: number;
  host?: string;
}

let serverInstance: Server | null = null;

/**
 * Create and configure the Express app
 */
function createApp(): Express {
  const app = express();
  const corsAllowOrigin = process.env.CORS_ALLOW_ORIGIN || "*";

  // Middleware
  app.use(express.json({ limit: "10mb" }));

  // Request logging (debug mode)
  app.use((req: Request, _res: Response, next: NextFunction) => {
    if (process.env.DEBUG) {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    }
    next();
  });

  // CORS headers for local development
  app.use((_req: Request, res: Response, next: NextFunction) => {
    res.setHeader("Access-Control-Allow-Origin", corsAllowOrigin);
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    next();
  });

  // Handle OPTIONS preflight
  app.options("*", (_req: Request, res: Response) => {
    res.sendStatus(200);
  });

  // Routes
  app.get("/", handleHealth);
  app.get("/health", handleHealth);
  app.get("/setup", handleSetupPage);
  app.get("/api/setup/status", handleSetupStatus);
  app.post("/api/setup/auth/start", handleStartAuth);
  app.post("/api/setup/auth/submit", handleSubmitAuthCode);
  app.post("/api/setup/auth/cancel", handleCancelAuth);
  app.get("/v1/models", handleModels);
  app.post("/v1/chat/completions", handleChatCompletions);

  // 404 handler
  app.use((_req: Request, res: Response) => {
    res.status(404).json({
      error: {
        message: "Not found",
        type: "invalid_request_error",
        code: "not_found",
      },
    });
  });

  // Error handler
  app.use((err: Error & { status?: number; type?: string }, _req: Request, res: Response, _next: NextFunction) => {
    console.error("[Server Error]:", err.message);

    const isJsonSyntaxError = err instanceof SyntaxError && err.type === "entity.parse.failed";
    if (isJsonSyntaxError) {
      res.status(400).json({
        error: {
          message: "Invalid JSON body",
          type: "invalid_request_error",
          code: "invalid_json",
        },
      });
      return;
    }

    res.status(500).json({
      error: {
        message: err.message,
        type: "server_error",
        code: null,
      },
    });
  });

  return app;
}

/**
 * Start the HTTP server
 */
export async function startServer(config: ServerConfig): Promise<Server> {
  const { port, host = "127.0.0.1" } = config;

  if (serverInstance) {
    console.log("[Server] Already running, returning existing instance");
    return serverInstance;
  }

  const app = createApp();

  return new Promise((resolve, reject) => {
    serverInstance = createServer(app);

    serverInstance.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        reject(new Error(`Port ${port} is already in use`));
      } else {
        reject(err);
      }
    });

    serverInstance.listen(port, host, () => {
      const displayHost = host === "0.0.0.0" ? "localhost" : host;
      console.log(`[Server] Claude Code CLI provider running at http://${displayHost}:${port}`);
      console.log(`[Server] OpenAI-compatible endpoint: http://${displayHost}:${port}/v1/chat/completions`);
      resolve(serverInstance!);
    });
  });
}

/**
 * Stop the HTTP server
 */
export async function stopServer(): Promise<void> {
  if (!serverInstance) {
    return;
  }

  return new Promise((resolve, reject) => {
    serverInstance!.close((err) => {
      if (err) {
        reject(err);
      } else {
        console.log("[Server] Stopped");
        serverInstance = null;
        resolve();
      }
    });
  });
}

/**
 * Get the current server instance
 */
export function getServer(): Server | null {
  return serverInstance;
}
