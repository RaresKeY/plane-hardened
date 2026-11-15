// Dependency-free CA policy for Bun compatibility runtimes, preloaded before app imports.
import { createHash, X509Certificate } from "node:crypto";
import { getCACertificates, setDefaultCACertificates } from "node:tls";

const nativeFetch = globalThis.fetch;
let activeRoots: string[] = [];

type TrustPolicy = {
  schema: number;
  blocked_spki_sha256: Record<string, string>;
  blocked_certificate_sha256?: Record<string, string>;
};

const validMap = (value: unknown): value is Record<string, string> =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).every((key) => /^[0-9a-f]{64}$/.test(key));

export function enforceTrustPolicy(policy: TrustPolicy): { before: number; after: number; removed: number } {
  if (
    policy.schema !== 1 ||
    !validMap(policy.blocked_spki_sha256) ||
    !Object.keys(policy.blocked_spki_sha256).length ||
    (policy.blocked_certificate_sha256 !== undefined && !validMap(policy.blocked_certificate_sha256))
  ) {
    throw new Error("Missing or unsupported CA policy");
  }
  const digest = (data: Buffer) => createHash("sha256").update(data).digest("hex");
  const roots = getCACertificates("default");
  const kept = roots.filter((pem) => {
    const certificate = new X509Certificate(pem);
    const spki = certificate.publicKey.export({ type: "spki", format: "der" });
    return (
      !Object.hasOwn(policy.blocked_spki_sha256, digest(spki)) &&
      !Object.hasOwn(policy.blocked_certificate_sha256 ?? {}, digest(certificate.raw))
    );
  });
  if (!kept.length) throw new Error("CA policy would remove every root");
  setDefaultCACertificates(kept);
  activeRoots = kept;
  // Bun's native fetch has a separate TLS path: the node:tls default setter
  // alone does not affect it. Supply the filtered roots on every fetch call.
  globalThis.fetch = ((input: Parameters<typeof nativeFetch>[0], init?: Parameters<typeof nativeFetch>[1]) => {
    const supplied = init as (RequestInit & { tls?: Record<string, unknown> }) | undefined;
    const tls = supplied?.tls ?? {};
    if (tls.checkServerIdentity) {
      throw new Error("Custom TLS identity verification requires explicit review");
    }
    return nativeFetch(input, { ...init, tls: { ...tls, ca: activeRoots, rejectUnauthorized: true } });
  }) as typeof nativeFetch;
  return { before: roots.length, after: kept.length, removed: roots.length - kept.length };
}

const policyPath = process.env.PLANE_CA_POLICY ?? "/opt/plane-hardening/policy.json";
const startupPolicy = (await Bun.file(policyPath).json()) as TrustPolicy;
enforceTrustPolicy(startupPolicy);
