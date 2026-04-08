/**
 * AIAClient — AIA Protocol Platform Node.js / TypeScript client.
 *
 * Provides the same 6 core methods as the Python SDK:
 *   1. registerAgent       — POST /agents
 *   2. issueCapability      — POST /capabilities
 *   3. generateSIE          — local (no network), signs SIE with agent's private key
 *   4. verify               — POST /verify
 *   5. revokeAgent          — DELETE /agents/{id}
 *   6. getAuditLog          — GET /audit
 */
import {
  AIAError,
  AgentNotFoundError,
  RevocationError,
  VerificationDeniedError,
} from "./errors.js";
import {
  b64urlEncode,
  b64urlDecode,
  canonicalize,
  generateNonce,
  keypairFromPrivateKey,
  reasoningHash,
  sha256Hex,
  sign,
} from "./crypto.js";
import type {
  AgentRegistration,
  AuditLogResult,
  CapabilityToken,
  GetAuditLogOptions,
  IssueCapabilityOptions,
  RegisterAgentOptions,
  RevokeResult,
  SIE,
  VerifyResult,
} from "./types.js";

export interface AIAClientOptions {
  /** Base URL of the AIA server, e.g. "https://aia.example.com" */
  baseUrl: string;
  /** Org API key (X-API-Key header) */
  apiKey: string;
}

export class AIAClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;

  constructor(options: AIAClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.apiKey = options.apiKey;
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  private async _request<T>(
    method: string,
    path: string,
    body?: unknown,
    authenticated = true,
  ): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Accept": "application/json",
    };
    if (authenticated) {
      headers["X-API-Key"] = this.apiKey;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

    if (!res.ok) {
      let detail = res.statusText;
      try {
        const err = await res.json() as { detail?: string };
        if (err.detail) detail = err.detail;
      } catch {
        // ignore JSON parse errors
      }

      if (res.status === 404) throw new AgentNotFoundError(detail);
      throw new AIAError(`HTTP ${res.status}: ${detail}`);
    }

    if (res.status === 204) return undefined as T;
    return res.json() as Promise<T>;
  }

  // -------------------------------------------------------------------------
  // 1. Register agent
  // -------------------------------------------------------------------------

  async registerAgent(
    agentName: string,
    options: RegisterAgentOptions = {},
  ): Promise<AgentRegistration> {
    return this._request<AgentRegistration>("POST", "/agents", {
      agent_name: agentName,
      validity_hours: options.validityHours ?? 24,
      metadata: options.metadata,
    });
  }

  // -------------------------------------------------------------------------
  // 2. Issue capability token
  // -------------------------------------------------------------------------

  async issueCapability(
    agentId: string,
    capabilityName: string,
    options: IssueCapabilityOptions = {},
  ): Promise<CapabilityToken> {
    return this._request<CapabilityToken>("POST", "/capabilities", {
      agent_id: agentId,
      capability_name: capabilityName,
      parameters: options.parameters,
      validity_seconds: options.validitySeconds ?? 3600,
    });
  }

  // -------------------------------------------------------------------------
  // 3. Generate SIE (local — no network call)
  //    Mirrors the Python SDK's generate_sie() exactly.
  // -------------------------------------------------------------------------

  generateSIE(
    registration: AgentRegistration,
    capabilityToken: CapabilityToken,
    intent: Record<string, unknown>,
    reasoning?: string,
  ): SIE {
    const timestamp = new Date().toISOString();
    const nonce = generateNonce();

    const sie: Omit<SIE, "signature"> & { signature?: string } = {
      agent_certificate: registration.certificate as Record<string, unknown>,
      capability_token: capabilityToken.token,
      intent: { capability: capabilityToken.capability_name, ...intent },
      timestamp,
      nonce,
    };

    if (reasoning !== undefined) {
      sie.reasoning_hash = reasoningHash(reasoning);
    }

    // Sign the canonical form of the envelope (without the signature field)
    const kp = keypairFromPrivateKey(registration.private_key);
    const canonical = canonicalize(sie);
    const sigBytes = sign(kp.privateKey, canonical);
    sie.signature = b64urlEncode(sigBytes);

    return sie as SIE;
  }

  // -------------------------------------------------------------------------
  // 4. Verify SIE
  // -------------------------------------------------------------------------

  async verify(sie: SIE): Promise<VerifyResult> {
    const result = await this._request<VerifyResult>(
      "POST",
      "/verify",
      { sie },
      false, // POST /verify is unauthenticated
    );

    if (result.result === "deny") {
      throw new VerificationDeniedError(result.reason ?? "unknown", result.verification_id);
    }

    return result;
  }

  // -------------------------------------------------------------------------
  // 5. Revoke agent
  // -------------------------------------------------------------------------

  async revokeAgent(agentId: string, reason?: string): Promise<RevokeResult> {
    try {
      return await this._request<RevokeResult>(
        "DELETE",
        `/agents/${agentId}${reason ? `?reason=${encodeURIComponent(reason)}` : ""}`,
      );
    } catch (err) {
      if (err instanceof AIAError) throw new RevocationError(err.message);
      throw err;
    }
  }

  // -------------------------------------------------------------------------
  // 6. Get audit log
  // -------------------------------------------------------------------------

  async getAuditLog(options: GetAuditLogOptions = {}): Promise<AuditLogResult> {
    const params = new URLSearchParams();
    if (options.agentId) params.set("agent_id", options.agentId);
    if (options.result) params.set("result", options.result);
    if (options.limit !== undefined) params.set("limit", String(options.limit));
    if (options.offset !== undefined) params.set("offset", String(options.offset));

    const qs = params.toString();
    return this._request<AuditLogResult>("GET", `/audit${qs ? `?${qs}` : ""}`);
  }
}
