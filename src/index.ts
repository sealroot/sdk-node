export { AIAClient } from "./client.js";
export type { AIAClientOptions } from "./client.js";
export {
  AIAError,
  AgentNotFoundError,
  VerificationDeniedError,
  RevocationError,
} from "./errors.js";
export type {
  AgentRegistration,
  CapabilityToken,
  SIE,
  VerifyResult,
  RevokeResult,
  AuditLogResult,
  AuditRecord,
  RegisterAgentOptions,
  IssueCapabilityOptions,
  GetAuditLogOptions,
} from "./types.js";
export {
  b64urlEncode,
  b64urlDecode,
  canonicalize,
  generateNonce,
  generateKeypair,
  keypairFromPrivateKey,
  reasoningHash,
  sha256Hex,
  sign,
  verify,
} from "./crypto.js";
