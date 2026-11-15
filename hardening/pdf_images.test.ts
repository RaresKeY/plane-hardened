import { afterEach, expect, test } from "bun:test";
import {
  assetUrl,
  downloadAsset,
  imageAssetIds,
  MAX_DOCUMENT_IMAGES,
  MAX_IMAGE_BYTES,
  preparedImage,
} from "../apps/live/src/lib/pdf/image-policy";

const ID = "ccce47bd-54e7-4026-88d6-128477bd190e";
const JPEG = "data:image/jpeg;base64,/9j/2Q==";
const nativeFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = nativeFetch;
});

for (const value of [
  "http://127.0.0.1/secret",
  "https://example.invalid/",
  "file:///etc/passwd",
  "/etc/passwd",
  JPEG,
  { uri: "file:///etc/passwd" },
  null,
  42,
  "__proto__",
]) {
  test(`document image source rejected: ${JSON.stringify(value)}`, () => {
    expect(preparedImage(value)).toBeUndefined();
    expect(imageAssetIds({ type: "image", attrs: { src: value } })).toEqual([]);
  });
}

test("only own, bounded preprocessed JPEG data reaches the renderer", () => {
  expect(preparedImage(ID, { [ID]: JPEG })).toBe(JPEG);
  expect(preparedImage(ID, Object.create({ [ID]: JPEG }))).toBeUndefined();
  for (const value of [
    "http://127.0.0.1/",
    "file:///etc/passwd",
    "data:image/svg+xml;base64,PHN2Zz4=",
    JPEG + "\n",
    "data:image/jpeg;base64,/9j/" + "A".repeat(4 * Math.ceil(MAX_IMAGE_BYTES / 3) + 32),
  ]) {
    expect(preparedImage(ID, { [ID]: value })).toBeUndefined();
  }
});

test("image traversal deduplicates both editor forms and bounds depth/count/width", () => {
  expect(
    imageAssetIds({
      content: [
        { type: "image", attrs: { src: ID } },
        { type: "imageComponent", attrs: { src: ID } },
      ],
    })
  ).toEqual([ID]);
  let deep: object = {};
  for (let i = 0; i < 102; i++) deep = { content: [deep] };
  expect(() => imageAssetIds(deep)).toThrow("limits");
  expect(() => imageAssetIds({ content: Array(10001).fill({}) })).toThrow("limits");
  const many = Array.from({ length: MAX_DOCUMENT_IMAGES + 1 }, (_, i) => ({
    type: "image",
    attrs: { src: `${i.toString(16).padStart(8, "0")}-54e7-4026-88d6-128477bd190e` },
  }));
  expect(() => imageAssetIds({ content: many })).toThrow("count");
});

for (const value of [
  "http://storage.invalid:9000/a",
  "file:///etc/passwd",
  "https://storage.invalid.attacker.invalid/a",
  "https://user:secret@storage.invalid/a",
  "https://storage.invalid/a#fragment",
  "https://storage.invalid\n/a",
  "https://127.0.0.1/a",
]) {
  test(`storage origin must match exact operator allowlist: ${value}`, () => {
    expect(() => assetUrl(value, "https://storage.invalid")).toThrow("not allowed");
  });
}
test("empty policy denies downloads; exact presigned paths are preserved", () => {
  expect(() => assetUrl("https://storage.invalid/a", "")).toThrow();
  expect(() => assetUrl("https://storage.invalid/a", "https://storage.invalid/unexpected-path")).toThrow();
  expect(
    assetUrl("https://storage.invalid/a?signature=secret", "https://other.invalid,https://storage.invalid").href
  ).toBe("https://storage.invalid/a?signature=secret");
  expect(assetUrl("http://s3:9000/a", "http://s3:9000").hostname).toBe("s3");
});

test("download reads valid bytes with no redirects, cookies or ambient credentials", async () => {
  const signal = AbortSignal.timeout(1000);
  globalThis.fetch = (async (_url, options) => {
    expect(options?.signal).toBe(signal);
    expect(options?.redirect).toBe("error");
    expect(options?.credentials).toBe("omit");
    expect(options?.headers).toBeUndefined();
    return new Response("fixture", { headers: { "content-length": "7" } });
  }) as typeof fetch;
  expect((await downloadAsset(new URL("https://storage.invalid/a"), signal)).toString()).toBe("fixture");
});

for (const length of ["garbage", "-1", String(MAX_IMAGE_BYTES + 1)]) {
  test(`oversized or malformed declared body is canceled: ${length}`, async () => {
    let canceled = false;
    globalThis.fetch = (async () =>
      new Response(
        new ReadableStream({
          cancel() {
            canceled = true;
          },
        }),
        { headers: { "content-length": length } }
      )) as typeof fetch;
    await expect(downloadAsset(new URL("https://storage.invalid/"), AbortSignal.timeout(1000))).rejects.toThrow(
      "rejected"
    );
    expect(canceled).toBe(true);
  });
}

test("chunked body exceeding byte limit is canceled without buffering the rest", async () => {
  let canceled = false;
  const chunk = new Uint8Array(1024 * 1024);
  globalThis.fetch = (async () =>
    new Response(
      new ReadableStream({
        pull(controller) {
          controller.enqueue(chunk);
        },
        cancel() {
          canceled = true;
        },
      })
    )) as typeof fetch;
  await expect(downloadAsset(new URL("https://storage.invalid/"), AbortSignal.timeout(1000))).rejects.toThrow(
    "exceeds limit"
  );
  expect(canceled).toBe(true);
});

test("native fetch refuses redirects and aborts a stalled body against a local trap", async () => {
  let trap = 0;
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(req) {
      const route = new URL(req.url).pathname;
      if (route === "/redirect") return Response.redirect(`${server.url}trap`);
      if (route === "/trap") {
        trap++;
        return new Response("secret");
      }
      if (route === "/stall")
        return new Response(
          new ReadableStream({
            start(c) {
              c.enqueue(new Uint8Array([1]));
            },
          })
        );
      return new Response("fixture");
    },
  });
  try {
    await expect(downloadAsset(new URL("redirect", server.url), AbortSignal.timeout(1000))).rejects.toThrow();
    expect(trap).toBe(0);
    expect((await downloadAsset(new URL("ok", server.url), AbortSignal.timeout(1000))).toString()).toBe("fixture");
    await expect(downloadAsset(new URL("stall", server.url), AbortSignal.timeout(50))).rejects.toThrow();
  } finally {
    server.stop(true);
  }
});
