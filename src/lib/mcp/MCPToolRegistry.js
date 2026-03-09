/**
 * src/lib/mcp/MCPToolRegistry.js
 * Tool registry — manages built-in tools and external MCP server tools.
 *
 * Built-in tools (always available, no server needed):
 *   score_cvss         — CVSS v3.1 base score calculator
 *   lookup_mitre       — MITRE ATT&CK cloud technique lookup
 *   check_compliance   — HIPAA/PCI/SOC2/FedRAMP gap checker
 *
 * External tools: discovered from a connected MCP server via tools/list.
 *
 * Tool call routing:
 *   Built-in  → direct JS function call (synchronous-ish)
 *   External  → MCPClient.callTool() → JSON-RPC over WebSocket/HTTP
 *
 * Usage:
 *   import { mcpRegistry } from './MCPToolRegistry.js';
 *   await mcpRegistry.tryConnectExternal('ws://localhost:3747');
 *   const tools = mcpRegistry.getToolsForPrompt();
 *   const result = await mcpRegistry.invoke('score_cvss', { vector: 'AV:N/...' });
 */

import { MCPClient }        from './MCPClient.js';
import { scoreCVSS }        from './tools/CVSSScorer.js';
import { lookupMitre }      from './tools/ThreatDBTool.js';
import { checkCompliance }  from './tools/ComplianceChecker.js';

class MCPToolRegistry {
  constructor() {
    /** @type {Map<string, { description, inputSchema, fn: Function, source: 'builtin'|'external' }>} */
    this._tools    = new Map();
    /** @type {MCPClient|null} */
    this._client   = null;
    this._status   = 'disconnected'; // 'disconnected' | 'connected' | 'error'

    this._registerBuiltins();
  }

  // ── Built-in tool registration ────────────────────────────────────────────

  _registerBuiltins() {
    this._register({
      name:        'score_cvss',
      source:      'builtin',
      description: 'Calculate CVSS v3.1 base score and severity from a CVSS vector string. Example: score_cvss("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") → 9.8 Critical',
      inputSchema: {
        type:       'object',
        properties: { vector: { type: 'string', description: 'CVSS v3.1 vector string, e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"' } },
        required:   ['vector'],
      },
      fn: ({ vector }) => {
        const r = scoreCVSS(vector);
        if (r.error) return `Error: ${r.error}`;
        return `CVSS v3.1 Score: ${r.score} (${r.severity})\nVector: ${r.vector}\nMetrics: AV:${r.metrics.AV} AC:${r.metrics.AC} PR:${r.metrics.PR} UI:${r.metrics.UI} S:${r.metrics.S} C:${r.metrics.C} I:${r.metrics.I} A:${r.metrics.A}`;
      },
    });

    this._register({
      name:        'lookup_mitre',
      source:      'builtin',
      description: 'Look up MITRE ATT&CK cloud/IaaS techniques by ID or keyword. Examples: "T1078", "T1552.005", "credential", "S3 bucket", "IMDSv2"',
      inputSchema: {
        type:       'object',
        properties: { query: { type: 'string', description: 'ATT&CK technique ID (T1078, T1552.005) or keyword' } },
        required:   ['query'],
      },
      fn: ({ query }) => {
        const r = lookupMitre(query);
        if (r.error) return `Error: ${r.error}`;
        if (!r.results.length) return r.message ?? `No techniques found for "${query}"`;
        return r.results.map(t =>
          `**${t.id}: ${t.name}**\nTactics: ${t.tactics.join(', ')}\n${t.description}\nMitigations:\n${t.mitigations.map(m => `  • ${m}`).join('\n')}\n${t.url}`
        ).join('\n\n');
      },
    });

    this._register({
      name:        'check_compliance',
      source:      'builtin',
      description: 'Check an AWS resource configuration against HIPAA, PCI DSS, SOC 2, or FedRAMP controls. Provide the framework name, resource type, and parsed attributes.',
      inputSchema: {
        type:       'object',
        properties: {
          framework:     { type: 'string', description: 'Framework: HIPAA, PCI, SOC2, or FedRAMP' },
          resource_type: { type: 'string', description: 'Terraform resource type, e.g. aws_s3_bucket, aws_rds_instance' },
          attrs:         { type: 'object', description: 'Parsed HCL attributes from the resource block' },
        },
        required: ['framework', 'resource_type'],
      },
      fn: ({ framework, resource_type, attrs }) => {
        const r = checkCompliance(framework, resource_type, attrs ?? {});
        if (r.error) return `Error: ${r.error}`;
        if (r.score === null) return r.message ?? `No controls found for ${resource_type}`;
        const lines = [r.summary];
        if (r.gaps.length) {
          lines.push('\nGaps:');
          for (const g of r.gaps) lines.push(`  ✗ [${g.control}] ${g.description}\n    Fix: ${g.remediation}`);
        }
        if (r.met.length) {
          lines.push('\nPassing:');
          for (const m of r.met) lines.push(`  ✓ [${m.control}] ${m.description}`);
        }
        return lines.join('\n');
      },
    });
  }

  _register({ name, source, description, inputSchema, fn }) {
    this._tools.set(name, { description, inputSchema, fn, source });
  }

  // ── External MCP server connection ───────────────────────────────────────

  /**
   * Attempt to connect to an external MCP server and discover its tools.
   * Non-throwing — returns false if connection fails.
   *
   * @param {string} url  ws:// or http:// URL
   * @returns {Promise<boolean>}  true if connected and tools discovered
   */
  async tryConnectExternal(url) {
    // Disconnect existing external connection if any
    if (this._client) {
      try { this._client.disconnect(); } catch { /* ignore */ }
      this._client = null;
      // Remove previously registered external tools
      for (const [name, tool] of this._tools) {
        if (tool.source === 'external') this._tools.delete(name);
      }
    }

    try {
      const client = new MCPClient(url);
      const externalTools = await client.connect();

      this._client = client;
      this._status = 'connected';

      // Register external tools (external takes precedence over builtin for same name)
      for (const tool of externalTools) {
        const name = tool.name;
        if (!name) continue;
        this._tools.set(name, {
          description: tool.description ?? `External tool: ${name}`,
          inputSchema: tool.inputSchema ?? tool.input_schema ?? {},
          fn:          (args) => client.callTool(name, args),
          source:      'external',
        });
      }

      return true;
    } catch (e) {
      this._status = 'error';
      return false;
    }
  }

  /** Disconnect from external server but keep builtins. */
  disconnectExternal() {
    if (this._client) {
      try { this._client.disconnect(); } catch { /* ignore */ }
      this._client = null;
    }
    for (const [name, tool] of this._tools) {
      if (tool.source === 'external') this._tools.delete(name);
    }
    this._status = 'disconnected';
  }

  // ── Tool access ───────────────────────────────────────────────────────────

  /**
   * Get tool definitions formatted for injection into an LLM system prompt.
   * @returns {Array<{name, description, inputSchema}>}
   */
  getToolsForPrompt() {
    return [...this._tools.entries()].map(([name, t]) => ({
      name,
      description:  t.description,
      inputSchema:  t.inputSchema,
    }));
  }

  /**
   * Get a summary string listing available tools.
   * @returns {string}
   */
  getToolsSummary() {
    const builtins  = [...this._tools.entries()].filter(([,t]) => t.source === 'builtin').map(([n]) => n);
    const externals = [...this._tools.entries()].filter(([,t]) => t.source === 'external').map(([n]) => n);
    const parts = [];
    if (builtins.length)  parts.push(`Built-in: ${builtins.join(', ')}`);
    if (externals.length) parts.push(`External (${this._status}): ${externals.join(', ')}`);
    return parts.join(' | ') || 'No tools available';
  }

  /**
   * Invoke a tool by name.
   * @param {string} name
   * @param {object} args
   * @returns {Promise<string|object>}
   */
  async invoke(name, args = {}) {
    const tool = this._tools.get(name);
    if (!tool) throw new Error(`Unknown tool: "${name}". Available: ${[...this._tools.keys()].join(', ')}`);
    return tool.fn(args);
  }

  /** Check if a tool is available. */
  hasTool(name) { return this._tools.has(name); }

  /** Connection status: 'disconnected' | 'connected' | 'error' */
  get status() { return this._status; }

  /** Number of available tools (builtin + external). */
  get toolCount() { return this._tools.size; }

  /**
   * Parse and execute any tool calls embedded in an LLM response string.
   * Replaces <tool_call>{"name":"...","args":{...}}</tool_call> with tool output.
   *
   * @param {string} response  LLM response text
   * @returns {Promise<string>}  Response with tool calls replaced by results
   */
  async executeToolCalls(response) {
    const re = /<tool_call>([\s\S]*?)<\/tool_call>/g;
    const matches = [...response.matchAll(re)];
    if (!matches.length) return response;

    let out = response;
    for (const match of matches) {
      try {
        const payload = JSON.parse(match[1].trim());
        const name    = payload.name ?? payload.tool;
        const args    = payload.args ?? payload.arguments ?? payload.parameters ?? {};
        if (!name) continue;

        const result    = await this.invoke(name, args);
        const resultStr = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
        out = out.replace(match[0], `\n**[${name}]**\n${resultStr}\n`);
      } catch (e) {
        // Replace with error message but keep the rest of the response
        out = out.replace(match[0], `\n**[tool error: ${e.message}]**\n`);
      }
    }
    return out;
  }
}

/** Module-level singleton — import and use everywhere. */
export const mcpRegistry = new MCPToolRegistry();
export default mcpRegistry;
