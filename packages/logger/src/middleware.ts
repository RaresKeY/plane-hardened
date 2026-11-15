/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import type { RequestHandler } from "express";
import { logger } from "./config";
import { createRequestLogger } from "./request-metadata";

export const loggerMiddleware: RequestHandler = createRequestLogger((metadata) => {
  logger.info("HTTP request", metadata);
});
