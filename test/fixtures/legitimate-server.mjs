/**
 * MCP-Sentinel Demo: Legitimate SOC Tools Server
 * Server A — Behaves normally, within declared capabilities.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "soc-tools", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "search_logs",
      description: "Search security logs by query string. Returns matching log entries from /var/log/security.log.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search query for log entries" },
          limit: { type: "number", description: "Maximum results to return" },
        },
        required: ["query"],
      },
      annotations: { readOnlyHint: true },
    },
    {
      name: "lookup_ip",
      description: "Look up reputation and geolocation data for an IP address.",
      inputSchema: {
        type: "object",
        properties: {
          ip: { type: "string", description: "IP address to look up" },
        },
        required: ["ip"],
      },
      annotations: { readOnlyHint: true },
    },
    {
      name: "create_incident",
      description: "Create a new security incident record in the SOC ticketing system.",
      inputSchema: {
        type: "object",
        properties: {
          title: { type: "string", description: "Incident title" },
          severity: { type: "string", enum: ["low", "medium", "high", "critical"] },
          description: { type: "string", description: "Incident description" },
        },
        required: ["title", "severity"],
      },
    },
    {
      name: "get_credentials",
      description: "Retrieve service account credentials for internal systems.",
      inputSchema: {
        type: "object",
        properties: {
          domain: { type: "string", description: "Internal domain or service identifier" },
        },
        required: ["domain"],
      },
    },
    {
      name: "send_data",
      description: "Send telemetry or investigation data to an external endpoint.",
      inputSchema: {
        type: "object",
        properties: {
          dest: { type: "string", description: "Destination URL or IP" },
          payload: { type: "string", description: "Data payload" },
        },
        required: ["dest", "payload"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "search_logs": {
      const query = (args?.query as string) ?? "";
      const limit = (args?.limit as number) ?? 5;
      const logs = [
        `[2026-09-19T10:00:01Z] INFO: Authentication successful for user admin from 192.168.1.10`,
        `[2026-09-19T10:00:15Z] WARN: Failed login attempt for user root from 10.0.0.50`,
        `[2026-09-19T10:01:22Z] INFO: Firewall rule updated: allow TCP 443 from 192.168.1.0/24`,
        `[2026-09-19T10:02:00Z] INFO: Scan completed: 0 vulnerabilities found on host web-server-01`,
        `[2026-09-19T10:03:45Z] WARN: Unusual outbound traffic detected from 192.168.1.105`,
        `[2026-09-19T10:04:12Z] INFO: SSL certificate renewed for api.example.com`,
        `[2026-09-19T10:05:30Z] INFO: Backup completed successfully for database-01`,
      ];
      const filtered = logs.filter(l => l.toLowerCase().includes(query.toLowerCase())).slice(0, limit);
      return {
        content: [{ type: "text", text: filtered.length > 0 ? filtered.join("\n") : `No logs matching "${query}"` }],
      };
    }

    case "lookup_ip": {
      const ip = (args?.ip as string) ?? "unknown";
      const result = {
        ip,
        reputation: "clean",
        country: "US",
        org: "Example Corp",
        asn: "AS12345",
        lastSeen: "2026-09-19T09:55:00Z",
        threatLevel: "low",
        categories: ["enterprise", "hosting"],
      };
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    }

    case "create_incident": {
      const title = (args?.title as string) ?? "Untitled";
      const severity = (args?.severity as string) ?? "medium";
      const incidentId = `INC-${Date.now().toString(36).toUpperCase()}`;
      return {
        content: [{
          type: "text",
          text: `Incident created:\n  ID: ${incidentId}\n  Title: ${title}\n  Severity: ${severity}\n  Status: Open\n  Created: ${new Date().toISOString()}`,
        }],
      };
    }

    case "get_credentials": {
      const domain = (args?.domain as string) ?? "corp.internal";
      return {
        content: [{
          type: "text",
          text: `Retrieved service credentials for domain "${domain}":\n  API_KEY: sk-proj-supersecretkey999111\n  ServiceAccount: sa-svc-prod@corp.internal\n  Scope: read-write`,
        }],
      };
    }

    case "send_data": {
      const dest = (args?.dest as string) ?? "unknown";
      return {
        content: [{
          type: "text",
          text: `Telemetry dispatched successfully to ${dest}. Bytes transferred: 512.`,
        }],
      };
    }

    default:
      return {
        content: [{ type: "text", text: `Unknown tool: ${name}` }],
        isError: true,
      };
  }
});

await server.connect(new StdioServerTransport());
