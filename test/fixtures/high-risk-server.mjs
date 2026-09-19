/**
 * MCP-Sentinel Demo: High-Risk SOC Tools Server
 * Server C — Destructive operations requiring human approval.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

const server = new Server(
  { name: "soc-response", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "block_ip",
      description: "Block an IP address at the network firewall. This is a DESTRUCTIVE action that may disrupt services.",
      inputSchema: {
        type: "object",
        properties: {
          ip: { type: "string", description: "IP address to block" },
          reason: { type: "string", description: "Reason for blocking" },
          duration: { type: "number", description: "Duration in minutes (0 = permanent)" },
        },
        required: ["ip", "reason"],
      },
      annotations: { destructiveHint: true, readOnlyHint: false },
    },
    {
      name: "isolate_host",
      description: "Isolate a host from the network for containment. WARNING: Host will lose all connectivity.",
      inputSchema: {
        type: "object",
        properties: {
          hostname: { type: "string", description: "Hostname to isolate" },
          reason: { type: "string", description: "Reason for isolation" },
        },
        required: ["hostname", "reason"],
      },
      annotations: { destructiveHint: true, readOnlyHint: false },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "block_ip": {
      const ip = (args?.ip as string) ?? "unknown";
      const reason = (args?.reason as string) ?? "No reason provided";
      const duration = (args?.duration as number) ?? 0;
      return {
        content: [{
          type: "text",
          text: `Firewall rule created:\n  Action: BLOCK\n  IP: ${ip}\n  Reason: ${reason}\n  Duration: ${duration === 0 ? "permanent" : `${duration} minutes`}\n  Applied: ${new Date().toISOString()}\n  Rule ID: FW-${Date.now().toString(36).toUpperCase()}`,
        }],
      };
    }

    case "isolate_host": {
      const hostname = (args?.hostname as string) ?? "unknown";
      const reason = (args?.reason as string) ?? "No reason provided";
      return {
        content: [{
          type: "text",
          text: `Host isolation applied:\n  Host: ${hostname}\n  Reason: ${reason}\n  Status: ISOLATED\n  Network: DISCONNECTED\n  Applied: ${new Date().toISOString()}\n  Recovery: Manual re-enable required`,
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
