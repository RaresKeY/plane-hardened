/** PDF renderers receive bytes prepared by the asset pipeline, never document URLs. */
export const ASSET_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const MAX_IMAGE_BYTES = 5 * 1024 * 1024;
export const MAX_DOCUMENT_IMAGES = 64;

export function preparedImage(src: unknown, images?: Record<string, string>): string | undefined {
  if (typeof src !== "string" || !ASSET_ID.test(src) || !images || !Object.prototype.hasOwnProperty.call(images, src))
    return;
  const value = images[src];
  if (typeof value !== "string" || value.length > 4 * Math.ceil(MAX_IMAGE_BYTES / 3) + 32) return;
  if (value.trim() === value && /^data:image\/jpeg;base64,\/9j\/[A-Za-z0-9+/]*={0,2}$/.test(value)) return value;
}

export function imageAssetIds(doc: unknown): string[] {
  const ids = new Set<string>();
  const stack: Array<{ node: unknown; depth: number }> = [{ node: doc, depth: 0 }];
  let visited = 0;
  while (stack.length) {
    const { node, depth } = stack.pop()!;
    if (++visited > 10000 || depth > 100) throw new Error("Document exceeds PDF image traversal limits");
    if (!node || typeof node !== "object") continue;
    const item = node as { type?: unknown; attrs?: { src?: unknown }; content?: unknown };
    const src = item.attrs?.src;
    if ((item.type === "image" || item.type === "imageComponent") && typeof src === "string" && ASSET_ID.test(src)) {
      ids.add(src);
      if (ids.size > MAX_DOCUMENT_IMAGES) throw new Error("Document exceeds PDF image count limit");
    }
    if (Array.isArray(item.content)) {
      if (item.content.length + stack.length > 10000) throw new Error("Document exceeds PDF image traversal limits");
      for (const child of item.content) stack.push({ node: child, depth: depth + 1 });
    }
  }
  return [...ids];
}

const invalid = () => new Error("PDF asset URL is not allowed");

/** Storage origins are operator configuration, independent of document attributes and redirects. */
export function assetUrl(value: string, configuredOrigins: string): URL {
  // eslint-disable-next-line no-control-regex -- Reject parser-normalized controls before URL parsing.
  if (/[\x00-\x20\x7f]/.test(value)) throw invalid();
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw invalid();
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.hash) throw invalid();
  const allowed = configuredOrigins
    .split(",")
    .filter(Boolean)
    .map((entry) => {
      try {
        const origin = new URL(entry.trim());
        if (origin.href !== origin.origin + "/" || !["http:", "https:"].includes(origin.protocol)) throw invalid();
        return origin.origin;
      } catch {
        throw invalid();
      }
    });
  if (!allowed.includes(url.origin)) throw invalid();
  return url;
}

export async function downloadAsset(url: URL, signal: AbortSignal): Promise<Buffer> {
  const response = await fetch(url, { signal, redirect: "error", credentials: "omit" });
  let completed = false;
  const reader = response.body?.getReader();
  try {
    const length = response.headers.get("content-length");
    if (!response.ok || !reader || (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_IMAGE_BYTES))) {
      throw new Error("PDF asset response rejected");
    }
    const chunks: Uint8Array[] = [];
    let size = 0;
    while (true) {
      // eslint-disable-next-line no-await-in-loop -- Backpressure and byte limits require one bounded chunk at a time.
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_IMAGE_BYTES) throw new Error("PDF asset body exceeds limit");
      chunks.push(value);
    }
    completed = true;
    return Buffer.concat(chunks);
  } finally {
    if (!completed) await reader?.cancel().catch(() => undefined);
    reader?.releaseLock();
  }
}
