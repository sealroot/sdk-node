export class AIAError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AIAError";
  }
}

export class AgentNotFoundError extends AIAError {
  constructor(agentId: string) {
    super(`Agent not found: ${agentId}`);
    this.name = "AgentNotFoundError";
  }
}

export class VerificationDeniedError extends AIAError {
  readonly reason: string;
  readonly verificationId: string;

  constructor(reason: string, verificationId: string) {
    super(`Verification denied: ${reason} (id=${verificationId})`);
    this.name = "VerificationDeniedError";
    this.reason = reason;
    this.verificationId = verificationId;
  }
}

export class RevocationError extends AIAError {
  constructor(message: string) {
    super(message);
    this.name = "RevocationError";
  }
}
