import { expect, test } from "bun:test";
import { AppError } from "../apps/live/src/lib/errors";

const SECRET = "fixture-cookie-query-body-must-not-be-logged";
test("Axios errors preserve status but never read response bodies, config or raw messages", () => {
  const response = Object.defineProperty({ status: 413 }, "data", {
    get() {
      throw new Error("Do not read body");
    },
  });
  const external = Object.defineProperties(
    { isAxiosError: true, response, code: "ERR_BAD_RESPONSE" },
    {
      config: {
        get() {
          throw new Error("Do not read config");
        },
      },
      message: {
        get() {
          throw new Error("Do not read transport message");
        },
      },
    }
  );
  const error = new AppError(external);
  expect(error.statusCode).toBe(413);
  expect(error.message).toBe("API request failed");
  expect(error.code).toBe("API_REQUEST_FAILED");
});

for (const error of [
  new Error(SECRET),
  new SyntaxError(SECRET),
  new DOMException(SECRET, "AbortError"),
  {
    isAxiosError: true,
    message: SECRET,
    code: SECRET,
    response: { status: SECRET, data: { message: SECRET } },
    config: { url: SECRET },
  },
  SECRET.length,
  undefined,
]) {
  test(`external error content removed: ${typeof error}`, () => {
    const safe = new AppError(error);
    expect(JSON.stringify(safe)).not.toContain(SECRET);
    expect(safe.message).not.toContain(SECRET);
    expect(safe.stack).not.toContain(SECRET);
  });
}

test("abort classification remains compatible with page-update cancellation", () => {
  expect(new AppError(new DOMException(SECRET, "AbortError")).code).toBe("ABORT_ERROR");
  expect(new AppError({ isAxiosError: true, code: "ERR_CANCELED" }).code).toBe("ABORT_ERROR");
});

test("first-party error options cannot inject causes, URLs, arbitrary codes or context", () => {
  const error = new AppError("Authentication unsuccessful", {
    statusCode: 403,
    code: "AUTH_USER_MISMATCH",
    context: { operation: "handleAuthentication", cookie: SECRET },
    cause: SECRET,
    stack: SECRET,
  });
  expect(error.statusCode).toBe(403);
  expect(error.code).toBe("AUTH_USER_MISMATCH");
  expect(error.context).toEqual({ operation: "handleAuthentication" });
  expect(JSON.stringify(error)).not.toContain(SECRET);
  expect(error.stack).not.toContain(SECRET);
});

test("reprocessing an AppError preserves its safe classification", () => {
  const error = new AppError("Credentials not provided", { code: "AUTH_MISSING_CREDENTIALS" });
  expect(new AppError(error)).toBe(error);
});
