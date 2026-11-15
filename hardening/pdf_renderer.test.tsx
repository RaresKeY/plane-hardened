/* eslint-disable no-await-in-loop -- Bound native PDF work and trap observations by testing one hostile source at a time. */
import { expect, test } from "bun:test";
import sharp from "../apps/live/node_modules/sharp";
import { renderPlaneDocToPdfBuffer } from "../apps/live/src/lib/pdf/plane-pdf-exporter";
import { nodeRenderers, createKeyGenerator } from "../apps/live/src/lib/pdf/node-renderers";

const ID = "ccce47bd-54e7-4026-88d6-128477bd190e";
for (const type of ["image", "imageComponent"]) {
  test(`${type}: raw URLs and file paths never reach the native PDF image loader`, async () => {
    let hits = 0;
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch() {
        hits++;
        return new Response("fixture");
      },
    });
    try {
      for (const src of [server.url.href, "file:///etc/passwd", "/etc/passwd", { uri: server.url.href }]) {
        const node = { type, attrs: { src } };
        const rendered = nodeRenderers[type](node, [], { getKey: createKeyGenerator() });
        expect(JSON.stringify(rendered)).not.toContain("src");
        const output = await renderPlaneDocToPdfBuffer({ type: "doc", content: [node] });
        expect(output.subarray(0, 4).toString()).toBe("%PDF");
        expect(output.toString("latin1")).not.toContain("/Subtype /Image");
      }
      expect(hits).toBe(0);
    } finally {
      server.stop(true);
    }
  }, 15000);

  test(`${type}: prepared stored JPEGs still embed, and noAssets omits them`, async () => {
    const bytes = await sharp({ create: { width: 8, height: 8, channels: 3, background: "#5865f2" } })
      .jpeg()
      .toBuffer();
    const options = { metadata: { resolvedImageUrls: { [ID]: `data:image/jpeg;base64,${bytes.toString("base64")}` } } };
    const doc = { type: "doc" as const, content: [{ type, attrs: { src: ID } }] };
    const output = await renderPlaneDocToPdfBuffer(doc, options);
    expect(output.toString("latin1")).toContain("/Subtype /Image");
    const excluded = await renderPlaneDocToPdfBuffer(doc, { ...options, noAssets: true });
    expect(excluded.toString("latin1")).not.toContain("/Subtype /Image");
  }, 15000);
}
