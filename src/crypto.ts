/**
 * Cryptographic primitives for the AIA Node.js SDK.
 *
 * - Ed25519 signing/verification via tweetnacl
 * - SHA-256 via js-sha256
 * - JCS (RFC 8785) canonicalization — stable JSON key ordering
 * - Base64url encoding/decoding (RFC 4648 no-padding)
 * - Nonce generation (128-bit CSPRNG)
 */
import nacl from "tweetnacl";
import { sha256 } from "js-sha256";

// ---------------------------------------------------------------------------
// Base64url (RFC 4648, no padding)
// ---------------------------------------------------------------------------

export function b64urlEncode(bytes: Uint8Array): string {
  const b64 = Buffer.from(bytes).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function b64urlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (padded.length % 4)) % 4;
  return new Uint8Array(Buffer.from(padded + "=".repeat(padding), "base64"));
}

// ---------------------------------------------------------------------------
// Ed25519 key generation
// ---------------------------------------------------------------------------

export interface KeyPair {
  privateKey: Uint8Array; // 64 bytes (seed || public)
  publicKey: Uint8Array;  // 32 bytes
}

export function generateKeypair(): KeyPair {
  const kp = nacl.sign.keyPair();
  return { privateKey: kp.secretKey, publicKey: kp.publicKey };
}

export function keypairFromPrivateKey(privateKeyB64url: string): KeyPair {
  const secretKey = b64urlDecode(privateKeyB64url);
  const kp = nacl.sign.keyPair.fromSecretKey(secretKey);
  return { privateKey: kp.secretKey, publicKey: kp.publicKey };
}

// ---------------------------------------------------------------------------
// Ed25519 signing / verification
// ---------------------------------------------------------------------------

export function sign(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
  // nacl.sign returns (signature + message); we extract the 64-byte signature
  const signed = nacl.sign(message, privateKey);
  return signed.slice(0, 64);
}

export function verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean {
  // nacl.sign.open expects signature prepended to message
  const signedMsg = new Uint8Array(signature.length + message.length);
  signedMsg.set(signature);
  signedMsg.set(message, signature.length);
  return nacl.sign.open(signedMsg, publicKey) !== null;
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

export function sha256Hex(input: string | Uint8Array): string {
  if (typeof input === "string") {
    return sha256(input);
  }
  return sha256(Array.from(input));
}

export function reasoningHash(reasoning: string): string {
  return `sha256:${sha256Hex(reasoning)}`;
}

// ---------------------------------------------------------------------------
// JCS (RFC 8785) — deterministic JSON serialisation
// Recursively sorts object keys; arrays are left in insertion order.
// ---------------------------------------------------------------------------

function jcsValue(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite numbers not allowed in JCS");
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map(jcsValue).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const pairs = keys.map((k) => `${JSON.stringify(k)}:${jcsValue(obj[k])}`);
    return "{" + pairs.join(",") + "}";
  }
  throw new Error(`Unsupported type: ${typeof value}`);
}

export function canonicalize(obj: unknown): Uint8Array {
  const json = jcsValue(obj);
  return new TextEncoder().encode(json);
}

// ---------------------------------------------------------------------------
// Nonce generation (128-bit CSPRNG)
// ---------------------------------------------------------------------------

export function generateNonce(): string {
  const bytes = nacl.randomBytes(16);
  return Buffer.from(bytes).toString("hex");
}
