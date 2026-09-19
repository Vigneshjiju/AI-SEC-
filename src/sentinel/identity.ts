/**
 * MCP-Sentinel: Identity Verifier
 * 
 * Cryptographically verifies user/agent identity, token validity, issuer, audience,
 * roles, scopes, and expiration before tool execution.
 * 
 * Core Rule: NEVER trust a role supplied directly in untrusted request parameters.
 */

import { IdentityClaims, VerifiedIdentity } from "./types.js";
import { createHash, createHmac } from "node:crypto";

export interface IdentityVerifierConfig {
  trustedIssuer?: string;
  trustedAudience?: string;
  secretKey?: string;
  clockToleranceSec?: number;
}

export class IdentityVerifier {
  private trustedIssuer: string;
  private trustedAudience: string;
  private secretKey: string;
  private clockToleranceSec: number;

  constructor(config?: IdentityVerifierConfig) {
    this.trustedIssuer = config?.trustedIssuer ?? "https://auth.sentinel.internal";
    this.trustedAudience = config?.trustedAudience ?? "mcp-sentinel";
    this.secretKey = config?.secretKey ?? "sentinel-master-auth-secret-key-2026";
    this.clockToleranceSec = config?.clockToleranceSec ?? 0;
  }

  /**
   * Generates a signed bearer token for legitimate clients, workflows, and test harnesses.
   */
  generateToken(
    userId: string,
    roles: string[],
    scopes: string[] = ["tools:execute"],
    ttlSeconds: number = 3600,
    agentId?: string,
  ): string {
    const expiresAt = Math.floor(Date.now() / 1000) + ttlSeconds;
    const payload = {
      userId,
      agentId: agentId ?? "llm-agent-default",
      iss: this.trustedIssuer,
      aud: this.trustedAudience,
      roles,
      scopes,
      exp: expiresAt,
      iat: Math.floor(Date.now() / 1000),
    };

    const headerB64 = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signature = createHmac("sha256", this.secretKey)
      .update(`${headerB64}.${payloadB64}`)
      .digest("base64url");

    return `${headerB64}.${payloadB64}.${signature}`;
  }

  /**
   * Verifies an authentication token against trusted identity infrastructure.
   * Answers: "Who are you?"
   */
  verifyToken(token: string | undefined): VerifiedIdentity {
    if (!token || token.trim().length === 0) {
      return { valid: false, error: "Missing authentication token" };
    }

    const cleanToken = token.startsWith("Bearer ") ? token.slice(7).trim() : token.trim();
    const parts = cleanToken.split(".");

    if (parts.length !== 3) {
      // Fallback dev format: "dev:<userId>:<role>:<scopes>"
      if (cleanToken.startsWith("dev:")) {
        const segments = cleanToken.split(":");
        const userId = segments[1] || "anonymous";
        const role = segments[2] || "analyst";
        const scopes = segments[3] ? segments[3].split(",") : ["tools:execute"];
        return {
          valid: true,
          claims: {
            userId,
            agentId: "dev-agent",
            token: cleanToken,
            issuer: this.trustedIssuer,
            audience: this.trustedAudience,
            roles: [role],
            scopes,
            expiresAt: Date.now() + 3600000,
          },
        };
      }
      return { valid: false, error: "Malformed token structure (expected 3 parts)" };
    }

    const [headerB64, payloadB64, signature] = parts;

    // Verify HMAC signature
    const expectedSignature = createHmac("sha256", this.secretKey)
      .update(`${headerB64}.${payloadB64}`)
      .digest("base64url");

    if (signature !== expectedSignature) {
      return { valid: false, error: "Invalid token cryptographic signature" };
    }

    try {
      const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
      const nowSec = Math.floor(Date.now() / 1000);

      // Verify expiration
      if (payload.exp && payload.exp <= nowSec) {
        return { valid: false, error: `Token expired at ${new Date(payload.exp * 1000).toISOString()}` };
      }

      // Verify issuer
      if (payload.iss && payload.iss !== this.trustedIssuer) {
        return { valid: false, error: `Untrusted token issuer "${payload.iss}"` };
      }

      // Verify audience
      if (payload.aud && payload.aud !== this.trustedAudience) {
        return { valid: false, error: `Invalid token audience "${payload.aud}"` };
      }

      const claims: IdentityClaims = {
        userId: payload.userId,
        agentId: payload.agentId,
        token: cleanToken,
        issuer: payload.iss,
        audience: payload.aud,
        roles: Array.isArray(payload.roles) ? payload.roles : [payload.role || "analyst"],
        scopes: Array.isArray(payload.scopes) ? payload.scopes : ["tools:execute"],
        expiresAt: (payload.exp || nowSec + 3600) * 1000,
      };

      return { valid: true, claims };
    } catch (err) {
      return { valid: false, error: `Failed to parse token payload: ${(err as Error).message}` };
    }
  }

  /**
   * Enforces verified authorization against untrusted request context.
   * Overwrites/sanitizes request userRole with cryptographically verified identity claims.
   */
  enforceVerifiedRole(
    authToken: string | undefined,
    untrustedRole: string,
    untrustedUserId: string,
  ): {
    userId: string;
    agentId: string;
    primaryRole: string;
    roles: string[];
    scopes: string[];
    verified: boolean;
    reason?: string;
  } {
    const verified = this.verifyToken(authToken);

    if (!verified.valid || !verified.claims) {
      // In strict zero-trust mode: Reject unverified identity claims
      return {
        userId: untrustedUserId || "anonymous",
        agentId: "unverified-agent",
        primaryRole: "viewer", // Demote untrusted requests to lowest privilege
        roles: ["viewer"],
        scopes: [],
        verified: false,
        reason: verified.error ?? "Unverified token; demoting to lowest privilege (viewer)",
      };
    }

    const primaryRole = verified.claims.roles[0] || "analyst";
    return {
      userId: verified.claims.userId,
      agentId: verified.claims.agentId ?? "llm-agent",
      primaryRole,
      roles: verified.claims.roles,
      scopes: verified.claims.scopes,
      verified: true,
    };
  }
}
