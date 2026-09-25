#!/usr/bin/env node
// stdio entry point: `npx supabase-security-mcp`
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "../src/server.mjs";

const server = createServer();
const transport = new StdioServerTransport();
await server.connect(transport);
