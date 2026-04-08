export interface AgentRegistration {
  agent_id: string;
  agent_name: string;
  org_id: string;
  certificate: Record<string, unknown>;
  /** Base64url-encoded Ed25519 private key — returned ONCE at registration only */
  private_key: string;
  public_key: string;
  issued_at: string;
  expires_at: string;
  warning?: string;
}

export interface CapabilityToken {
  capability_id: string;
  agent_id: string;
  capability_name: string;
  /** Signed JWT */
  token: string;
  jwt_id: string;
  issued_at: string;
  expires_at: string;
}

export interface SIE {
  agent_certificate: Record<string, unknown>;
  capability_token: string;
  intent: {
    capability: string;
    parameters?: Record<string, unknown>;
    [key: string]: unknown;
  };
  timestamp: string;
  nonce: string;
  reasoning_hash?: string;
  signature: string;
}

export interface VerifyResult {
  result: "allow" | "deny";
  reason: string | null;
  verification_id: string;
  latency_ms: number;
  risk_score: number;
  risk_level: "low" | "medium" | "high";
}

export interface RevokeResult {
  agent_id: string;
  revoked_at: string;
  message: string;
}

export interface AuditRecord {
  id: number;
  verification_id: string;
  agent_id: string | null;
  result: string;
  reason: string | null;
  sie_hash: string;
  timestamp: string;
  previous_hash: string;
  record_hash: string;
}

export interface AuditLogResult {
  records: AuditRecord[];
  total: number;
  chain_integrity: boolean;
}

export interface RegisterAgentOptions {
  validityHours?: number;
  metadata?: Record<string, unknown>;
}

export interface IssueCapabilityOptions {
  parameters?: Record<string, unknown>;
  validitySeconds?: number;
}

export interface GetAuditLogOptions {
  agentId?: string;
  result?: "allow" | "deny";
  limit?: number;
  offset?: number;
}
