import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { DomainLookupTool } from "./tools/domain-lookup.js";

/**
 * DomainDetails MCP Server
 * Provides comprehensive domain research tools including RDAP, WHOIS, and DNS lookup
 */
class DomainDetailsMcpServer {
  constructor() {
    this.server = new Server(
      {
        name: "domaindetails-mcp",
        version: "1.1.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.domainLookupTool = new DomainLookupTool();
    this.setupHandlers();
  }

  setupHandlers() {
    // List available tools
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [this.domainLookupTool.getToolDefinition()],
      };
    });

    // Handle tool execution
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case "domain_lookup":
            const result = await this.domainLookupTool.execute(args);
            return {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(result, null, 2),
                },
              ],
            };

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
      } catch (error) {
        return {
          content: [
            {
              type: "text",
              text: `Error: ${error.message}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);

    // Log to stderr so it doesn't interfere with stdio communication
    console.error("DomainDetails MCP Server running on stdio");
  }
}

// Start the server
const server = new DomainDetailsMcpServer();
server.run().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
