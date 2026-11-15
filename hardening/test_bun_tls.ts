/* eslint-disable no-await-in-loop -- Positive/negative phases deliberately mutate shared process TLS trust and must run in order. */
// Native loopback trust controls in the same Bun runtime intended for JS services.
import { strict as assert } from "node:assert";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { get } from "node:https";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { getCACertificates, setDefaultCACertificates } from "node:tls";
import { enforceTrustPolicy } from "./tls_policy.ts";

const root = await mkdtemp(join(tmpdir(), "plane-bun-tls-"));
const key = join(root, "key.pem");
const cert = join(root, "cert.pem");
const generated = spawnSync(
  "openssl",
  [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-keyout",
    key,
    "-out",
    cert,
    "-subj",
    "/CN=localhost",
    "-addext",
    "subjectAltName=DNS:localhost",
  ],
  { timeout: 10000 }
);
assert.equal(generated.status, 0);
const pem = await readFile(cert, "utf8");
const certificate = new X509Certificate(pem);
const spki = createHash("sha256")
  .update(certificate.publicKey.export({ type: "spki", format: "der" }))
  .digest("hex");
const policy = await Bun.file(process.env.PLANE_CA_POLICY!).json();
const saved = getCACertificates("default");
const used = new Set<number>();

function nodeRequest(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const request = get(url, { agent: false }, (response) => {
      let body = "";
      response.on("data", (chunk) => {
        body += chunk.toString();
      });
      response.on("end", () => resolve(body));
    });
    request.setTimeout(2000, () => request.destroy(new Error("fixture timeout")));
    request.on("error", reject);
  });
}

async function check(expectTrusted: boolean, phase: string, hostname = "localhost"): Promise<void> {
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    tls: { key: await readFile(key), cert: pem },
    fetch: async (request) =>
      new URL(request.url).pathname === "/echo"
        ? Response.json({
            method: request.method,
            body: await request.text(),
            header: request.headers.get("x-fixture"),
          })
        : new Response("tls-fixture"),
  });
  assert(!used.has(server.port), "Use a new port to exclude pooled connections or resumed sessions");
  used.add(server.port);
  const url = `https://${hostname}:${server.port}/`;
  try {
    for (const [client, request] of [
      ["https.get", () => nodeRequest(url)],
      ["Bun.fetch", () => fetch(url, { keepalive: false }).then((response) => response.text())],
      ["fetch Request", () => fetch(new Request(url), { keepalive: false }).then((response) => response.text())],
      [
        "fetch verification override",
        () =>
          fetch(url, {
            keepalive: false,
            tls: { rejectUnauthorized: false },
          } as any).then((response) => response.text()),
      ],
      [
        "fetch CA override",
        () =>
          fetch(url, {
            keepalive: false,
            tls: { ca: pem },
          } as any).then((response) => response.text()),
      ],
    ] as const) {
      if (expectTrusted) {
        assert.equal(await request(), "tls-fixture", `${phase}: ${client}`);
        console.log(JSON.stringify({ phase, client, result: "accepted" }));
      } else {
        await assert.rejects(request, (error: any) => {
          assert.match(
            String(error.code),
            /CERT|ISSUER|SELF_SIGNED|VERIFY/,
            `Require a certificate failure, not a network error: ${client}`
          );
          return true;
        });
      }
    }
    if (expectTrusted) {
      const expected = { method: "POST", body: "fixture-payload", header: "fixed" };
      const input = new Request(url + "echo", {
        method: "POST",
        headers: { "x-fixture": "fixed" },
        body: "fixture-payload",
      });
      assert.deepEqual(await (await fetch(input, { keepalive: false })).json(), expected);
      assert.deepEqual(
        await (
          await fetch(url + "echo", {
            method: "POST",
            headers: { "x-fixture": "fixed" },
            body: new Blob(["fixture-payload"]).stream(),
            duplex: "half",
            keepalive: false,
          } as any)
        ).json(),
        expected
      );
    }
  } finally {
    server.stop(true);
  }
}

try {
  await check(false, "untrusted positive rejection control");
  setDefaultCACertificates([...saved, pem]);
  enforceTrustPolicy(policy);
  await check(true, "valid trusted peer control");
  await check(false, "trusted CA with wrong hostname", "127.0.0.1");
  const result = enforceTrustPolicy({
    ...policy,
    blocked_spki_sha256: {
      ...policy.blocked_spki_sha256,
      [spki]: "synthetic negative fixture",
    },
  });
  assert.equal(result.removed, 1);
  await check(false, "blocked by SPKI after filtering");
  console.log(JSON.stringify({ passed: true, clients: ["Bun.fetch", "https.get"], controls: 22, result }));
} finally {
  setDefaultCACertificates(saved);
  await rm(root, { recursive: true, force: true });
}
