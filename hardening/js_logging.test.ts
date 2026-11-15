// First-party logging boundary checks; no framework/dependency scripts or network.
import { describe, expect, mock, test } from "bun:test";
import { EventEmitter } from "node:events";
import { createRequestLogger } from "../packages/logger/src/request-metadata.ts";

const SECRET = "synthetic-body-query-header-secret";
function fixture() {
  const request: any = { method: "GET" };
  for (const name of ["url", "originalUrl", "headers", "body", "query", "params", "ip", "user"]) {
    Object.defineProperty(request, name, {
      get() {
        throw new Error(`${name} must not be read: ${SECRET}`);
      },
    });
  }
  const response: any = new EventEmitter();
  response.statusCode = 200;
  return { request, response };
}

describe("minimized shared HTTP logger", () => {
  test("uses the route assigned later and never reads secret-bearing properties", () => {
    const { request, response } = fixture();
    const write = mock(() => {});
    const next = mock(() => {});
    createRequestLogger(write)(request, response, next);
    request.route = { path: "/pages/:pageId" };
    response.emit("finish");
    response.emit("close");
    expect(next).toHaveBeenCalledTimes(1);
    expect(write).toHaveBeenCalledTimes(1);
    const data: any = write.mock.calls[0]![0];
    expect(Object.keys(data).toSorted()).toEqual(["duration_ms", "method", "outcome", "route", "status_code"]);
    expect(data.method).toBe("GET");
    expect(data.route).toBe("/pages/:pageId");
    expect(data.status_code).toBe(200);
    expect(data.outcome).toBe("completed");
    expect(Number.isInteger(data.duration_ms) && data.duration_ms >= 0).toBe(true);
    expect(JSON.stringify(data)).not.toContain(SECRET);
  });

  for (const pattern of [undefined, /dynamic/, ["/one", "/two"], "/bad\n" + SECRET, "/" + "a".repeat(256), SECRET]) {
    test(`invalid/unresolved pattern ${typeof pattern} stays constant`, () => {
      const { request, response } = fixture();
      request.route = { path: pattern };
      request.method = SECRET;
      const write = mock(() => {});
      createRequestLogger(write)(request, response, () => {});
      response.emit("finish");
      const data: any = write.mock.calls[0]![0];
      expect(data.route).toBe("/[unresolved]");
      expect(data.method).toBe("OTHER");
      expect(JSON.stringify(data)).not.toContain(SECRET);
    });
  }

  test("aborted responses do not report a successful default status or duplicate events", () => {
    const { request, response } = fixture();
    const write = mock(() => {});
    createRequestLogger(write)(request, response, () => {});
    response.emit("close");
    response.emit("finish");
    expect(write).toHaveBeenCalledTimes(1);
    const data: any = write.mock.calls[0]![0];
    expect(data.outcome).toBe("aborted");
    expect(data.status_code).toBeNull();
  });

  test("failed log sinks do not leak their error or alter the response path", () => {
    const { request, response } = fixture();
    const write = mock(() => {
      throw new Error(SECRET);
    });
    const next = mock(() => {});
    createRequestLogger(write)(request, response, next);
    expect(() => response.emit("finish")).not.toThrow();
    response.emit("close");
    expect(write).toHaveBeenCalledTimes(1);
    expect(next).toHaveBeenCalledTimes(1);
  });
});
