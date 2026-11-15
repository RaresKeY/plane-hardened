/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import type { AxiosError } from "axios";

/**
 * Application error class that sanitizes and standardizes errors across the app.
 * Extracts only essential information from AxiosError to prevent massive log bloat
 * and sensitive data leaks (cookies, tokens, etc).
 *
 * Usage:
 *   new AppError("Simple error message")
 *   new AppError("Custom error", { code: "MY_CODE", statusCode: 400 })
 *   new AppError(axiosError)  // Auto-extracts essential info
 *   new AppError(anyError)    // Works with any error type
 */
export class AppError extends Error {
  statusCode?: number;
  method?: string;
  code?: string;
  context?: Record<string, any>;

  constructor(messageOrError: string | unknown, data?: Partial<Omit<AppError, "name" | "message">>) {
    // Handle error objects - extract essential info
    const error = messageOrError;

    // Already AppError - return immediately for performance (no need to re-process)
    if (error instanceof AppError) {
      return error;
    }

    // Handle string message (simple case like regular Error)
    if (typeof messageOrError === "string") {
      super(messageOrError);
      this.name = "AppError";
      if (data) {
        if (typeof data.code === "string" && /^[A-Z_]{1,64}$/.test(data.code)) this.code = data.code;
        if (Number.isInteger(data.statusCode) && data.statusCode! >= 100 && data.statusCode! <= 599)
          this.statusCode = data.statusCode;
        const operation = data.context?.operation;
        if (typeof operation === "string" && /^[a-zA-Z]{1,64}$/.test(operation)) this.context = { operation };
      }
      return;
    }

    // AxiosError - extract ONLY essential info (no config, no headers, no cookies)
    if (error && typeof error === "object" && "isAxiosError" in error) {
      const axiosError = error as AxiosError;
      // Transport messages, response bodies and URLs can contain credentials or document content.
      super("API request failed");
      this.name = "AppError";
      const status = axiosError.response?.status;
      if (Number.isInteger(status) && status! >= 100 && status! <= 599) this.statusCode = status;
      this.code = axiosError.code === "ERR_CANCELED" ? "ABORT_ERROR" : "API_REQUEST_FAILED";
      return;
    }

    // DOMException (AbortError from cancelled requests)
    if (error instanceof DOMException && error.name === "AbortError") {
      super("Operation canceled");
      this.name = "AppError";
      this.code = "ABORT_ERROR";
      return;
    }

    // Standard Error objects
    if (error instanceof Error) {
      super("Operation failed");
      this.name = "AppError";
      this.code = "INTERNAL_ERROR";
      return;
    }

    // Unknown error types - safe fallback
    super("Unknown error occurred");
    this.name = "AppError";
  }
}
