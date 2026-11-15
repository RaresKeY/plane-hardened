/* eslint-disable no-await-in-loop -- Poll dependent server/client state and exercise requests in a deterministic order. */
import { expect, test } from "bun:test";
import { openSync, closeSync } from "node:fs";
import { HocuspocusProvider } from "../packages/editor/node_modules/@hocuspocus/provider/dist/hocuspocus-provider.esm.js";
import * as Y from "../apps/live/node_modules/yjs/dist/yjs.mjs";
import { getBinaryDataFromDocumentEditorHTMLString } from "../packages/editor/dist/index.js";

const SECRET = "synthetic-cookie-query-document-never-log-31bf";
const OWNER = "9ed0d1c1-21e3-4660-9b84-ff06eaac949b";
const PROJECT = "e1358f8a-223f-4c2e-8817-c16b4382aa44";
const PAGE = "6477b414-7d4f-4f3b-a0df-321282650c86";
const COOKIE = `session-id=${SECRET}`;
const binary = getBinaryDataFromDocumentEditorHTMLString("<p>Ordinary fixture document</p>", "Fixture");

async function waitFor(predicate: () => boolean | Promise<boolean>, message: string, milliseconds = 10000) {
  const end = performance.now() + milliseconds;
  while (performance.now() < end) {
    if (await predicate()) return;
    await Bun.sleep(50);
  }
  throw new Error(message);
}

test("built live service HTTP, PDF and authenticated realtime flows", async () => {
  let apiCalls = 0;
  const api = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(req) {
      apiCalls++;
      if (req.headers.get("cookie") !== COOKIE) return Response.json({ message: SECRET }, { status: 401 });
      const path = new URL(req.url).pathname;
      if (path === "/api/users/me/") return Response.json({ id: OWNER, display_name: "Fixture user" });
      if (path.includes(`/projects/${PROJECT}/pages/${PAGE}/`)) {
        if (req.method === "PATCH") return Response.json({ id: PAGE });
        if (path.endsWith("/description/")) return new Response(binary);
        if (path.includes("mention")) return Response.json([]);
        return Response.json({ id: PAGE, name: "Fixture", description_html: "<p>Fixture</p>" });
      }
      return Response.json({ message: SECRET }, { status: 403 });
    },
  });
  // Reserve a private loopback port; no port is published by the owning container.
  const reservation = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response() });
  const port = reservation.port;
  reservation.stop(true);
  const base = `http://127.0.0.1:${port}/live`;
  const output = "/work/plane-live-http-output.log";
  const outputFd = openSync(output, "w");
  const child = Bun.spawn(
    [
      "/tools/bun",
      "--no-install",
      "--no-macros",
      "--use-openssl-ca",
      "--preload",
      "/work/hardening/tls_policy.ts",
      "/work/apps/live/dist/start.mjs",
    ],
    {
      env: {
        PATH: "/tools:/usr/local/bin:/usr/bin:/bin",
        HOME: "/tmp",
        API_BASE_URL: api.url.origin,
        LIVE_SERVER_SECRET_KEY: "synthetic-live-key-with-more-than-32-characters",
        REDIS_URL: process.env.PLANE_TEST_REDIS_URL,
        PORT: String(port),
        PLANE_CA_POLICY: "/work/hardening/trust/policy.json",
        CORS_ALLOWED_ORIGINS: "http://fixture.invalid",
      },
      stdout: outputFd,
      stderr: outputFd,
    }
  );
  const providers: HocuspocusProvider[] = [];
  try {
    await waitFor(async () => {
      if (child.exitCode !== null)
        throw new Error(
          "Live service startup failed: " +
            (await Bun.file(output).text()).replaceAll(SECRET, "[fixture redacted]").slice(-3000)
        );
      try {
        return (await fetch(base + "/health/")).ok;
      } catch {
        return false;
      }
    }, "Live service did not become healthy");
    for (const [body, status] of [
      [`{"${SECRET}":`, 400],
      [JSON.stringify({ description_html: SECRET.repeat(4000), variant: "rich" }), 413],
    ] as const) {
      const response = await fetch(base + "/convert-document/?token=" + SECRET, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": SECRET },
        body,
      });
      expect(response.status).toBe(status);
      expect(await response.text()).not.toContain(SECRET);
    }
    const converted = await fetch(base + "/convert-document/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description_html: "<p>Ordinary fixture</p>", variant: "rich" }),
    });
    expect(converted.status).toBe(200);
    expect((await converted.json()).description_json).toBeDefined();

    const pdfRequest = { pageId: PAGE, projectId: PROJECT, workspaceSlug: "fixture", noAssets: true };
    const pdf = (body: unknown, cookie?: string) =>
      fetch(base + "/pdf-export/", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}) },
        body: JSON.stringify(body),
      });
    expect((await pdf(pdfRequest)).status).toBe(401);
    const before = apiCalls;
    expect((await pdf({ ...pdfRequest, pageId: "../" + SECRET }, COOKIE)).status).toBe(400);
    expect(apiCalls).toBe(before);
    const rendered = await pdf(pdfRequest, COOKIE);
    expect(rendered.status).toBe(200);
    expect((await rendered.bytes()).subarray(0, 4)).toEqual(new Uint8Array([37, 80, 68, 70]));
    const denied = await pdf({ ...pdfRequest, projectId: OWNER }, COOKIE);
    expect(denied.status).toBe(502);
    expect(await denied.text()).not.toContain(SECRET);

    const connect = (user: string, cookie = COOKIE) => {
      const document = new Y.Doc();
      let synced = false,
        rejected = false;
      const provider = new HocuspocusProvider({
        url: base.replace("http:", "ws:") + "/collaboration/",
        name: PAGE,
        document,
        token: JSON.stringify({ id: user, cookie }),
        parameters: { workspaceSlug: "fixture", projectId: PROJECT, documentType: "project_page" },
        WebSocketPolyfill: WebSocket,
        onSynced: () => {
          synced = true;
        },
        onAuthenticationFailed: () => {
          rejected = true;
        },
      });
      providers.push(provider);
      return { document, synced: () => synced, rejected: () => rejected };
    };
    const first = connect(OWNER),
      second = connect(OWNER);
    await waitFor(() => first.synced() && second.synced(), "Authenticated realtime clients did not sync");
    first.document.getMap("hardening-fixture").set("marker", SECRET);
    await waitFor(
      () => second.document.getMap("hardening-fixture").get("marker") === SECRET,
      "Realtime update was not delivered"
    );
    const forged = connect(PROJECT);
    await waitFor(forged.rejected, "Forged user identity was not rejected");
    expect(forged.synced()).toBe(false);
    const missing = connect(OWNER, "");
    await waitFor(missing.rejected, "Missing cookie was not rejected");
    expect(missing.synced()).toBe(false);
  } finally {
    for (const provider of providers) provider.destroy();
    child.kill("SIGTERM");
    const force = setTimeout(() => child.kill("SIGKILL"), 5000);
    try {
      await child.exited;
    } finally {
      clearTimeout(force);
      closeSync(outputFd);
    }
    api.stop(true);
  }
  const logs = await Bun.file(output).text();
  expect(logs).not.toContain(SECRET);
  expect(logs).not.toContain(COOKIE);
}, 60000);
