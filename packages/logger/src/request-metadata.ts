/**
 * Copyright (c) 2026 Plane hardened fork contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 */

import type { RequestHandler } from "express";

const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"]);

export type HttpRequestMetadata = {
  method: string;
  route: string;
  status_code: number | null;
  duration_ms: number;
  outcome: "completed" | "aborted";
};

export function createRequestLogger(write: (metadata: HttpRequestMetadata) => void): RequestHandler {
  return (request, response, next) => {
    const started = performance.now();
    let written = false;
    const record = (outcome: "completed" | "aborted") => {
      if (written) return;
      written = true;
      // Express assigns the matched route after this middleware runs. Read the
      // static pattern at completion, never originalUrl/url/params or headers.
      const pattern: unknown = request.route?.path;
      const route =
        typeof pattern === "string" &&
        pattern.startsWith("/") &&
        pattern.length <= 255 &&
        // eslint-disable-next-line no-control-regex -- Log route patterns only when they contain no control bytes.
        !/[\u0000-\u001f\u007f]/.test(pattern)
          ? pattern
          : "/[unresolved]";
      const status = response.statusCode;
      try {
        write({
          method: METHODS.has(request.method) ? request.method : "OTHER",
          route,
          status_code:
            outcome === "completed" && Number.isInteger(status) && status >= 100 && status <= 599 ? status : null,
          duration_ms: Math.max(0, Math.round(performance.now() - started)),
          outcome,
        });
      } catch {
        // A failed log sink must not crash the server after sending a response.
        // Its exception may contain request data and is deliberately discarded.
      }
    };
    response.once("finish", () => record("completed"));
    response.once("close", () => record("aborted"));
    next();
  };
}
