/**
 * MCP-Sentinel: Authentication & Authorization Manager
 * Provides identity verification, role-based access control (RBAC),
 * and Just-In-Time (JIT) temporary permission grants.
 * 
 * Supports dev mode (mocked tokens/headers) and architecture ready
 * for Keycloak / OIDC integration.
 */

import type { UserIdentity, CapabilityType } from "./types.js";
import { classifyTool, roleHasCapability, ROLE_CAPABILITIES } from "./capability-model.js";

export { ROLE_CAPABILITIES };

export interface AuthorizationCheck {
  allowed: boolean;
  reason?: string;
  /** How the decision was reached — surfaced in the dashboard's explainability view. */
  via?: "admin" | "jit-grant" | "role-permission" | "role-capability";
  capability?: CapabilityType;
}

export interface TemporaryGrant {
  id: string;
  userId: string;
  permissions: string[];
  reason: string;
  grantedAt: number;
  expiresAt: number;
}

export const ROLE_PERMISSIONS: Record<UserIdentity["role"], string[]> = {
  viewer: [
    "search_logs",
    "lookup_ip",
    "read_logs",
    "get_status",
    "list_tools",
  ],
  analyst: [
    "search_logs",
    "lookup_ip",
    "read_logs",
    "get_status",
    "list_tools",
    "create_incident",
    "tag_artifact",
    "export_report",
  ],
  incident_responder: [
    "search_logs",
    "lookup_ip",
    "read_logs",
    "get_status",
    "list_tools",
    "create_incident",
    "tag_artifact",
    "export_report",
    "block_ip",
    "isolate_host",
    "quarantine_server",
    "trigger_containment",
  ],
  admin: [
    "*", // All permissions
  ],
};

export class AuthManager {
  private mode: "dev" | "oidc";
  private defaultRole: UserIdentity["role"];
  private temporaryGrants: Map<string, TemporaryGrant[]> = new Map(); // userId -> grants
  private knownUsers: Map<string, UserIdentity> = new Map();

  constructor(mode: "dev" | "oidc" = "dev", defaultRole: UserIdentity["role"] = "analyst") {
    this.mode = mode;
    this.defaultRole = defaultRole;

    // Seed default mock users for testing/demo
    this.seedDefaultUsers();
  }

  private seedDefaultUsers(): void {
    const defaultUsers: UserIdentity[] = [
      {
        userId: "user-viewer-1",
        username: "alice_viewer",
        role: "viewer",
        permissions: [...ROLE_PERMISSIONS.viewer],
      },
      {
        userId: "analyst1",
        username: "bob_analyst",
        role: "analyst",
        permissions: [...ROLE_PERMISSIONS.analyst],
      },
      {
        userId: "user-ir-1",
        username: "carol_responder",
        role: "incident_responder",
        permissions: [...ROLE_PERMISSIONS.incident_responder],
      },
      {
        userId: "user-admin-1",
        username: "dave_admin",
        role: "admin",
        permissions: ["*"],
      },
    ];

    for (const u of defaultUsers) {
      this.knownUsers.set(u.userId, u);
    }
  }

  /**
   * Authenticate a request token or fallback to dev identity.
   * Format in dev mode:
   *   "Bearer dev:<userId>:<role>" or just userId or empty (defaults to defaultRole)
   */
  public authenticate(tokenOrHeader?: string): UserIdentity {
    if (!tokenOrHeader || tokenOrHeader.trim() === "") {
      return this.getDefaultIdentity();
    }

    const token = tokenOrHeader.startsWith("Bearer ")
      ? tokenOrHeader.slice(7).trim()
      : tokenOrHeader.trim();

    if (this.knownUsers.has(token)) {
      return this.knownUsers.get(token)!;
    }

    if (token.startsWith("dev:")) {
      const parts = token.split(":");
      const userId = parts[1] || "dev-user";
      const role = (parts[2] as UserIdentity["role"]) || this.defaultRole;
      const validRole = (["viewer", "analyst", "incident_responder", "admin"].includes(role))
        ? role
        : this.defaultRole;

      const user: UserIdentity = {
        userId,
        username: userId,
        role: validRole,
        permissions: [...(ROLE_PERMISSIONS[validRole] || [])],
      };
      this.knownUsers.set(userId, user);
      return user;
    }

    // In OIDC mode, this would decode and verify the JWT with Keycloak public key / JWKS
    // For MVP / dev fallback:
    return this.getDefaultIdentity();
  }

  public getDefaultIdentity(): UserIdentity {
    return (
      this.knownUsers.get("analyst1") || {
        userId: "analyst1",
        username: "default_analyst",
        role: this.defaultRole,
        permissions: [...(ROLE_PERMISSIONS[this.defaultRole] || [])],
      }
    );
  }

  /**
   * Check if a user may execute a specific tool.
   *
   * Authorization is resolved in four stages, most-specific first:
   *   1. Admin / wildcard permission
   *   2. Active Just-In-Time grant (by tool name or capability class)
   *   3. Explicit named permission on the role
   *   4. Capability-tier permission — lets the policy cover tools that were
   *      never enumerated, which is the normal case for third-party MCP servers
   */
  public canExecuteTool(
    identity: UserIdentity,
    toolName: string,
    sensitivity: "public" | "internal" | "confidential" | "restricted" = "internal",
    description?: string
  ): AuthorizationCheck {
    const profile = classifyTool(toolName, description);
    const capability = profile.primaryCapability;

    if (identity.role === "admin" || identity.permissions.includes("*")) {
      return { allowed: true, via: "admin", capability };
    }

    // ── Just-In-Time grants (tool name or capability class) ──
    this.cleanExpiredGrants(identity.userId);
    const activeGrants = this.temporaryGrants.get(identity.userId) ?? [];
    for (const grant of activeGrants) {
      if (
        grant.permissions.includes("*") ||
        grant.permissions.includes(toolName) ||
        grant.permissions.includes(profile.toolName) ||
        grant.permissions.includes(capability)
      ) {
        return { allowed: true, via: "jit-grant", capability };
      }
    }

    // ── Explicit named permission ──
    const toolNormalized = profile.toolName.toLowerCase();
    const hasRolePermission = identity.permissions.some(
      (p) => p.toLowerCase() === toolNormalized || p === "*"
    );
    if (hasRolePermission) {
      if (sensitivity === "restricted" && identity.role === "viewer") {
        return {
          allowed: false,
          reason:
            `Tool '${profile.toolName}' is classified sensitivity 'restricted', ` +
            `which requires analyst or higher (role '${identity.role}')`,
          capability,
        };
      }
      return { allowed: true, via: "role-permission", capability };
    }

    // ── Capability-tier permission ──
    if (roleHasCapability(identity.role, capability)) {
      if (sensitivity === "restricted" && identity.role === "viewer") {
        return {
          allowed: false,
          reason:
            `Tool '${profile.toolName}' is classified sensitivity 'restricted', ` +
            `which requires analyst or higher (role '${identity.role}')`,
          capability,
        };
      }
      return { allowed: true, via: "role-capability", capability };
    }

    return {
      allowed: false,
      reason:
        `Role '${identity.role}' is not authorized for capability class ` +
        `'${capability}' required by tool '${profile.toolName}'`,
      capability,
    };
  }

  /**
   * Resolve a role name into a full identity without needing a token.
   * Used by the gateway, which carries a role on the request context.
   */
  public identityForRole(userId: string, role: string): UserIdentity {
    const validRole = (["viewer", "analyst", "incident_responder", "admin"].includes(role)
      ? role
      : this.defaultRole) as UserIdentity["role"];

    const existing = this.knownUsers.get(userId);
    if (existing && existing.role === validRole) return existing;

    const identity: UserIdentity = {
      userId,
      username: userId,
      role: validRole,
      permissions: [...(ROLE_PERMISSIONS[validRole] || [])],
    };
    this.knownUsers.set(userId, identity);
    return identity;
  }

  /** All currently active JIT grants across every user (dashboard telemetry). */
  public getAllActiveGrants(): TemporaryGrant[] {
    this.cleanExpiredGrants();
    return Array.from(this.temporaryGrants.values()).flat();
  }

  public revokeGrant(grantId: string): boolean {
    for (const [userId, grants] of this.temporaryGrants) {
      const idx = grants.findIndex((g) => g.id === grantId);
      if (idx >= 0) {
        grants.splice(idx, 1);
        if (grants.length === 0) this.temporaryGrants.delete(userId);
        return true;
      }
    }
    return false;
  }

  /**
   * Issue temporary Just-In-Time (JIT) permissions for emergency or incident response
   */
  public grantTemporaryPermission(
    userId: string,
    permissions: string[],
    durationSeconds: number,
    reason: string
  ): TemporaryGrant {
    const grantId = `jit-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const now = Date.now();
    const grant: TemporaryGrant = {
      id: grantId,
      userId,
      permissions,
      reason,
      grantedAt: now,
      expiresAt: now + durationSeconds * 1000,
    };

    const current = this.temporaryGrants.get(userId) ?? [];
    current.push(grant);
    this.temporaryGrants.set(userId, current);

    return grant;
  }

  /**
   * Revoke or clean up expired grants
   */
  public cleanExpiredGrants(userId?: string): void {
    const now = Date.now();
    const checkUser = (uid: string) => {
      const grants = this.temporaryGrants.get(uid);
      if (!grants) return;
      const valid = grants.filter((g) => g.expiresAt > now);
      if (valid.length > 0) {
        this.temporaryGrants.set(uid, valid);
      } else {
        this.temporaryGrants.delete(uid);
      }
    };

    if (userId) {
      checkUser(userId);
    } else {
      for (const uid of this.temporaryGrants.keys()) {
        checkUser(uid);
      }
    }
  }

  public getActiveGrants(userId: string): TemporaryGrant[] {
    this.cleanExpiredGrants(userId);
    return this.temporaryGrants.get(userId) ?? [];
  }
}
