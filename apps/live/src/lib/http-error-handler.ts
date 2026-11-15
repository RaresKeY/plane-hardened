import type { ErrorRequestHandler } from "express";
import { logger } from "@plane/logger";

// Express's development fallback can echo parser input and exception stacks.
// Preserve useful HTTP categories without serializing the exception or request.
export const httpErrorHandler: ErrorRequestHandler = (error: unknown, _request, response, _next) => {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  const status = error && typeof error === "object" && "status" in error ? error.status : null;
  const statusCode = status === 400 || status === 413 ? status : 500;
  logger.error("SERVER: HTTP request failed", { status_code: statusCode });
  response.status(statusCode).json({
    message: statusCode === 400 ? "Bad request" : statusCode === 413 ? "Payload too large" : "Internal server error",
  });
};
