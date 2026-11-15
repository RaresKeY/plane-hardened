// First-party, dependency-free Bun compatibility checks. No remote modules.
import { brotliCompressSync, brotliDecompressSync, gzipSync, gunzipSync } from "node:zlib";
import { strict as assert } from "node:assert";

assert.equal(Bun.version, "1.4.4");
const cases = [Buffer.alloc(0), Buffer.from("Plane restricted codec fixture"), Buffer.alloc(1024 * 1024, 65)];
for (const plain of cases) {
  assert.deepEqual(brotliDecompressSync(brotliCompressSync(plain)), plain);
  assert.deepEqual(gunzipSync(gzipSync(plain)), plain);
}
for (const bytes of [Buffer.from([0xff]), Buffer.from("invalid compressed stream")]) {
  assert.throws(() => brotliDecompressSync(bytes));
  assert.throws(() => gunzipSync(bytes));
}
console.log(
  JSON.stringify({
    bun: Bun.version,
    embedded: process.versions,
    passed: true,
    coverage: "Brotli/gzip empty, text, 1MiB roundtrips and malformed stream rejection",
    limit: "Does not reproduce CVE-2026-111497 or exercise allocation-failure/native sanitizer paths",
  })
);
