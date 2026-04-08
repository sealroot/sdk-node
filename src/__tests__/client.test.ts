/**
 * Unit tests for the AIA Node.js SDK.
 * Tests crypto primitives, SIE generation, and error classes.
 * Network calls are mocked.
 */
import {
  b64urlEncode,
  b64urlDecode,
  canonicalize,
  generateKeypair,
  generateNonce,
  keypairFromPrivateKey,
  reasoningHash,
  sha256Hex,
  sign,
  verify,
} from "../crypto";
import { AIAError, VerificationDeniedError, RevocationError } from "../errors";
import { AIAClient } from "../client";
import type { AgentRegistration, CapabilityToken } from "../types";

// ---------------------------------------------------------------------------
// Crypto primitives
// ---------------------------------------------------------------------------

describe("b64url", () => {
  it("round-trips bytes through base64url", () => {
    const original = new Uint8Array([1, 2, 3, 4, 255, 0, 128]);
    const encoded = b64urlEncode(original);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
    const decoded = b64urlDecode(encoded);
    expect(decoded).toEqual(original);
  });
});

describe("Ed25519", () => {
  it("sign + verify round-trip", () => {
    const kp = generateKeypair();
    const message = new TextEncoder().encode("hello world");
    const sig = sign(kp.privateKey, message);
    expect(sig).toHaveLength(64);
    expect(verify(kp.publicKey, message, sig)).toBe(true);
  });

  it("verify fails with wrong message", () => {
    const kp = generateKeypair();
    const message = new TextEncoder().encode("hello");
    const sig = sign(kp.privateKey, message);
    const wrong = new TextEncoder().encode("world");
    expect(verify(kp.publicKey, wrong, sig)).toBe(false);
  });

  it("keypairFromPrivateKey recovers public key", () => {
    const kp = generateKeypair();
    const recovered = keypairFromPrivateKey(b64urlEncode(kp.privateKey));
    expect(recovered.publicKey).toEqual(kp.publicKey);
  });
});

describe("sha256Hex", () => {
  it("produces correct SHA-256 of empty string", () => {
    expect(sha256Hex("")).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });

  it("reasoningHash wraps with sha256: prefix", () => {
    const h = reasoningHash("test reasoning");
    expect(h).toMatch(/^sha256:[a-f0-9]{64}$/);
  });
});

describe("canonicalize", () => {
  it("sorts keys deterministically", () => {
    const a = canonicalize({ z: 1, a: 2 });
    const b = canonicalize({ a: 2, z: 1 });
    expect(Buffer.from(a).toString()).toEqual(Buffer.from(b).toString());
    expect(Buffer.from(a).toString()).toBe('{"a":2,"z":1}');
  });

  it("handles nested objects", () => {
    const bytes = canonicalize({ b: { d: 4, c: 3 }, a: 1 });
    expect(Buffer.from(bytes).toString()).toBe('{"a":1,"b":{"c":3,"d":4}}');
  });

  it("handles arrays (preserves order)", () => {
    const bytes = canonicalize({ items: [3, 1, 2] });
    expect(Buffer.from(bytes).toString()).toBe('{"items":[3,1,2]}');
  });
});

describe("generateNonce", () => {
  it("returns a 32-char hex string (128-bit)", () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[a-f0-9]{32}$/);
  });

  it("generates unique nonces", () => {
    expect(generateNonce()).not.toEqual(generateNonce());
  });
});

// ---------------------------------------------------------------------------
// Error classes
// ---------------------------------------------------------------------------

describe("Errors", () => {
  it("AIAError is an Error", () => {
    const e = new AIAError("test");
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe("AIAError");
  });

  it("VerificationDeniedError carries reason and verificationId", () => {
    const e = new VerificationDeniedError("policy_deny", "abc-123");
    expect(e.reason).toBe("policy_deny");
    expect(e.verificationId).toBe("abc-123");
  });

  it("RevocationError is an AIAError", () => {
    const e = new RevocationError("already revoked");
    expect(e).toBeInstanceOf(AIAError);
  });
});

// ---------------------------------------------------------------------------
// AIAClient.generateSIE — local method, no network
// ---------------------------------------------------------------------------

const mockRegistration: AgentRegistration = (() => {
  const kp = generateKeypair();
  return {
    agent_id: "agent-001",
    agent_name: "test-agent",
    org_id: "org-001",
    certificate: { agent_id: "agent-001", org_id: "org-001", public_key: b64urlEncode(kp.publicKey) },
    private_key: b64urlEncode(kp.privateKey),
    public_key: b64urlEncode(kp.publicKey),
    issued_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 86400_000).toISOString(),
  };
})();

const mockCapability: CapabilityToken = {
  capability_id: "cap-001",
  agent_id: "agent-001",
  capability_name: "data:read",
  token: "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhZ2VudC0wMDEifQ.fakesig",
  jwt_id: "jwt-001",
  issued_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 3600_000).toISOString(),
};

describe("AIAClient.generateSIE", () => {
  const client = new AIAClient({ baseUrl: "http://localhost:8000", apiKey: "test-key" });

  it("generates a valid SIE structure", () => {
    const sie = client.generateSIE(mockRegistration, mockCapability, {});
    expect(sie.agent_certificate).toBeDefined();
    expect(sie.capability_token).toBe(mockCapability.token);
    expect(sie.intent.capability).toBe("data:read");
    expect(sie.nonce).toMatch(/^[a-f0-9]{32}$/);
    expect(sie.signature).toBeTruthy();
    expect(sie.timestamp).toBeTruthy();
  });

  it("includes reasoning_hash when reasoning is provided", () => {
    const sie = client.generateSIE(mockRegistration, mockCapability, {}, "I am reading data for analysis");
    expect(sie.reasoning_hash).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it("does not include reasoning_hash when reasoning is absent", () => {
    const sie = client.generateSIE(mockRegistration, mockCapability, {});
    expect(sie.reasoning_hash).toBeUndefined();
  });

  it("produces a different nonce on each call", () => {
    const sie1 = client.generateSIE(mockRegistration, mockCapability, {});
    const sie2 = client.generateSIE(mockRegistration, mockCapability, {});
    expect(sie1.nonce).not.toEqual(sie2.nonce);
  });

  it("signature is a valid base64url string", () => {
    const sie = client.generateSIE(mockRegistration, mockCapability, {});
    expect(sie.signature).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});
