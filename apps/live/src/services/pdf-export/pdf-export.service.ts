/**
 * Copyright (c) 2023-present Plane Software, Inc. and contributors
 * SPDX-License-Identifier: AGPL-3.0-only
 * See the LICENSE file for details.
 */

import { Effect } from "effect";
import sharp from "sharp";
import { env } from "@/env";
import {
  assetUrl,
  downloadAsset,
  imageAssetIds,
  ASSET_ID,
  MAX_DOCUMENT_IMAGES,
  MAX_IMAGE_BYTES,
} from "@/lib/pdf/image-policy";
import { getAllDocumentFormatsFromDocumentEditorBinaryData } from "@plane/editor/lib";
import type { PDFExportMetadata, TipTapDocument } from "@/lib/pdf";
import { renderPlaneDocToPdfBuffer } from "@/lib/pdf";
import { getPageService } from "@/services/page/handler";
import type { TDocumentTypes } from "@/types";
import {
  PdfContentFetchError,
  PdfGenerationError,
  PdfImageProcessingError,
  PdfTimeoutError,
} from "@/schema/pdf-export";
import { withTimeoutAndRetry, recoverWithDefault, tryAsync } from "./effect-utils";
import type { PdfExportInput, PdfExportResult, PageContent, MetadataResult } from "./types";

const IMAGE_CONCURRENCY = 4;
const IMAGE_TIMEOUT_MS = 8000;
const CONTENT_FETCH_TIMEOUT_MS = 7000;
const PDF_RENDER_TIMEOUT_MS = 15000;
const IMAGE_MAX_DIMENSION = 1200;

type TipTapNode = {
  type: string;
  attrs?: Record<string, unknown>;
  content?: TipTapNode[];
};

/**
 * PDF Export Service
 */
export class PdfExportService extends Effect.Service<PdfExportService>()("PdfExportService", {
  sync: () => ({
    /**
     * Determines document type
     */
    getDocumentType: (_input: PdfExportInput): TDocumentTypes => {
      return "project_page";
    },

    /**
     * Extracts image asset IDs from document content
     */
    extractImageAssetIds: (doc: TipTapNode): string[] => {
      return imageAssetIds(doc);
    },

    /**
     * Fetches page content (description binary) and parses it
     */
    fetchPageContent: (
      pageService: ReturnType<typeof getPageService>,
      pageId: string,
      requestId: string
    ): Effect.Effect<PageContent, PdfContentFetchError | PdfTimeoutError> =>
      Effect.gen(function* () {
        yield* Effect.logDebug("PDF_EXPORT: Fetching page content", { requestId, pageId });

        const descriptionBinary = yield* tryAsync(
          () => pageService.fetchDescriptionBinary(pageId),
          (cause) =>
            new PdfContentFetchError({
              message: "Failed to fetch page content",
              cause,
            })
        ).pipe(
          withTimeoutAndRetry("fetch page content", {
            timeoutMs: CONTENT_FETCH_TIMEOUT_MS,
            maxRetries: 3,
          })
        );

        if (!descriptionBinary) {
          return yield* Effect.fail(
            new PdfContentFetchError({
              message: "Page content not found",
            })
          );
        }

        const binaryData = new Uint8Array(descriptionBinary);
        const { contentJSON, titleHTML } = getAllDocumentFormatsFromDocumentEditorBinaryData(binaryData, true);

        return {
          contentJSON: contentJSON as TipTapDocument,
          titleHTML: titleHTML || null,
          descriptionBinary,
        };
      }),

    /**
     * Fetches user mentions for the page
     */
    fetchUserMentions: (
      pageService: ReturnType<typeof getPageService>,
      pageId: string,
      requestId: string
    ): Effect.Effect<MetadataResult> =>
      Effect.gen(function* () {
        yield* Effect.logDebug("PDF_EXPORT: Fetching user mentions", { requestId });

        const userMentionsRaw = yield* tryAsync(
          async () => {
            if (pageService.fetchUserMentions) {
              return await pageService.fetchUserMentions(pageId);
            }
            return [];
          },
          () => []
        ).pipe(recoverWithDefault([] as Array<{ id: string; display_name: string; avatar_url?: string }>));

        return {
          userMentions: userMentionsRaw.map((u) => ({
            id: u.id,
            display_name: u.display_name,
            avatar_url: u.avatar_url,
          })),
        };
      }),

    /**
     * Resolves and processes images for PDF embedding
     */
    processImages: (
      pageService: ReturnType<typeof getPageService>,
      workspaceSlug: string,
      projectId: string | undefined,
      assetIds: string[],
      requestId: string
    ): Effect.Effect<Record<string, string>> =>
      Effect.gen(function* () {
        if (assetIds.length === 0) {
          return {};
        }

        yield* Effect.logDebug("PDF_EXPORT: Processing images", {
          requestId,
          count: assetIds.length,
        });

        const processSingleImage = (assetId: string) =>
          tryAsync(
            async () => {
              const controller = new AbortController();
              const timer = setTimeout(() => controller.abort(), IMAGE_TIMEOUT_MS);
              try {
                const resolved = await pageService.resolveImageAssetUrl(
                  workspaceSlug,
                  assetId,
                  projectId,
                  controller.signal
                );
                if (!resolved) return null;
                const url = assetUrl(resolved, env.PDF_ASSET_ORIGINS);
                const body = await downloadAsset(url, controller.signal);
                const processed = await sharp(body, { limitInputPixels: 16000000, animated: false })
                  .timeout({ seconds: IMAGE_TIMEOUT_MS / 1000 })
                  .rotate()
                  .flatten({ background: { r: 255, g: 255, b: 255 } })
                  .resize(IMAGE_MAX_DIMENSION, IMAGE_MAX_DIMENSION, { fit: "inside", withoutEnlargement: true })
                  .jpeg({ quality: 85 })
                  .toBuffer();
                if (processed.length > MAX_IMAGE_BYTES) throw new Error("Processed PDF image exceeds limit");
                return [assetId, `data:image/jpeg;base64,${processed.toString("base64")}`] as const;
              } finally {
                clearTimeout(timer);
                controller.abort();
              }
            },
            () => new PdfImageProcessingError({ message: "PDF image processing failed", assetId })
          ).pipe(
            Effect.tapError(() => Effect.logWarning("PDF_EXPORT: Image processing failed", { requestId })),
            Effect.catchAll(() => Effect.succeed(null))
          );

        // Independently validate this boundary even when called outside the export pipeline.
        const entries = [...new Set(assetIds)].filter((id) => ASSET_ID.test(id)).slice(0, MAX_DOCUMENT_IMAGES);

        const pairs = yield* Effect.forEach(entries, processSingleImage, {
          concurrency: IMAGE_CONCURRENCY,
        });

        const filtered = pairs.filter((p): p is NonNullable<typeof p> => p !== null);
        return Object.fromEntries(filtered);
      }),

    /**
     * Renders document to PDF buffer
     */
    renderPdf: (
      contentJSON: TipTapDocument,
      metadata: PDFExportMetadata,
      options: {
        title?: string;
        author?: string;
        subject?: string;
        pageSize?: "A4" | "A3" | "A2" | "LETTER" | "LEGAL" | "TABLOID";
        pageOrientation?: "portrait" | "landscape";
        noAssets?: boolean;
      },
      requestId: string
    ): Effect.Effect<Buffer, PdfGenerationError | PdfTimeoutError> =>
      Effect.gen(function* () {
        yield* Effect.logDebug("PDF_EXPORT: Rendering PDF", { requestId });

        const pdfBuffer = yield* tryAsync(
          () =>
            renderPlaneDocToPdfBuffer(contentJSON, {
              title: options.title,
              author: options.author,
              subject: options.subject,
              pageSize: options.pageSize,
              pageOrientation: options.pageOrientation,
              metadata,
              noAssets: options.noAssets,
            }),
          (cause) =>
            new PdfGenerationError({
              message: "Failed to render PDF",
              cause,
            })
        ).pipe(withTimeoutAndRetry("render PDF", { timeoutMs: PDF_RENDER_TIMEOUT_MS, maxRetries: 0 }));

        yield* Effect.logInfo("PDF_EXPORT: PDF rendered successfully", {
          requestId,
          size: pdfBuffer.length,
        });

        return pdfBuffer;
      }),
  }),
}) {}

/**
 * Main export pipeline - orchestrates the entire PDF export process
 * Separate function to avoid circular dependency in service definition
 */
export const exportToPdf = (
  input: PdfExportInput
): Effect.Effect<PdfExportResult, PdfContentFetchError | PdfGenerationError | PdfTimeoutError, PdfExportService> =>
  Effect.gen(function* () {
    const service = yield* PdfExportService;
    const { requestId, pageId, workspaceSlug, projectId, noAssets } = input;

    yield* Effect.logInfo("PDF_EXPORT: Starting export", { requestId, pageId, workspaceSlug });

    // Create page service
    const documentType = service.getDocumentType(input);
    const pageService = getPageService(documentType, {
      workspaceSlug,
      projectId: projectId || null,
      cookie: input.cookie,
      documentType,
      userId: "",
    });

    // Fetch content
    const content = yield* service.fetchPageContent(pageService, pageId, requestId);

    // Extract image asset IDs
    const extractedImageIds = service.extractImageAssetIds(content.contentJSON as TipTapNode);

    // Fetch user mentions
    let metadata = yield* service.fetchUserMentions(pageService, pageId, requestId);

    // Process images if needed
    if (!noAssets && extractedImageIds.length > 0) {
      const resolvedImages = yield* service.processImages(
        pageService,
        workspaceSlug,
        projectId,
        extractedImageIds,
        requestId
      );
      metadata = { ...metadata, resolvedImageUrls: resolvedImages };
    }

    yield* Effect.logDebug("PDF_EXPORT: Metadata prepared", {
      requestId,
      userMentions: metadata.userMentions?.length ?? 0,
      resolvedImages: Object.keys(metadata.resolvedImageUrls ?? {}).length,
    });

    // Render PDF
    const documentTitle = input.title || content.titleHTML || undefined;
    const pdfBuffer = yield* service.renderPdf(
      content.contentJSON,
      metadata,
      {
        title: documentTitle,
        author: input.author,
        subject: input.subject,
        pageSize: input.pageSize,
        pageOrientation: input.pageOrientation,
        noAssets,
      },
      requestId
    );

    yield* Effect.logInfo("PDF_EXPORT: Export complete", {
      requestId,
      pageId,
      size: pdfBuffer.length,
    });

    return {
      pdfBuffer,
      outputFileName: input.fileName || `page-${pageId}.pdf`,
      pageId,
    };
  });
