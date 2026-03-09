/**
 * src/lib/mcp/MCPClient.js
 * Model Context Protocol (MCP) client — WebSocket JSON-RPC 2.0 transport.
 *
 * Implements the MCP 2024-11-05 specification client side:
 *   - initialize handshake
 *   - tools/list
 *   - tools/call
 *   - resources/list (future)
 *   - prompts/list   (future)
 *
 * Fallback: if WebSocket is unavailable, falls back to a fetch-based HTTP
 * transport (for MCP servers that expose HTTP POST /rpc).
 *
 * Usage:
 *   const client = new MCPClient('ws://localhost:3747');
 *   const tools = await client.connect();
 *   const result = await client.callTool('score_cvss', { vector: 'AV:N/...' });
 *   client.disconnect();
 */

const MCP_PROTOCOL_VERSION = '2024-11-05';
const DEFAULT_TIMEOUT_MS   = 10_000;
const CONNECT_TIMEOUT_MS   = 3_000;

export class MCPClient {
  /**
   * @param {string} url  WebSocket URL (ws:// or wss://) or HTTP URL (http:// or https://)
   */
  constructor(url = 'ws://localhost:3747') {
    this.url       = url;
    this.connected = false;
    this.tools     = [];

    this._ws      = null;
    this._id      = 0;
    this._pending = new Map(); // id → { res, rej, timer }
    this._useHttp = url.startsWith('http');
  }

  /**
   * Connect to MCP server and perform initialize handshake.
   * @returns {Promise<object[]>}  List of available tools
   * @throws {Error} if connection fails within CONNECT_TIMEOUT_MS
   */
  async connect() {
    if (this._useHttp) {
      return this._connectHttp();
    }
    return this._connectWS();
  }

  /** Disconnect and clean up. */
  disconnect() {
    this._ws?.close();
    this._ws       = null;
    this.connected = false;
    for (const { rej, timer } of this._pending.values()) {
      clearTimeout(timer);
      rej(new Error('MCP disconnected'));
    }
    this._pending.clear();
  }

  /**
   * Call an MCP tool.
   * @param {string} name   Tool name
   * @param {object} args   Tool arguments
   * @returns {Promise<string|object>}  Tool result (content[0].text or raw result)
   */
  async callTool(name, args = {}) {
    if (!this.connected) throw new Error('MCP client not connected');
    const result = await this._rpc('tools/call', { name, arguments: args });
    // MCP result format: { content: [{ type: 'text', text: '...' }] }
    if (result?.content?.[0]?.text !== undefined) return result.content[0].text;
    if (result?.content?.length)                  return result.content.map(c => c.text ?? JSON.stringify(c)).join('\n');
    return result;
  }

  /**
   * List available resources (MCP resources/list).
   * @returns {Promise<object[]>}
   */
  async listResources() {
    if (!this.connected) return [];
    try { return (await this._rpc('resources/list', {})).resources ?? []; }
    catch { return []; }
  }

  // ── Private: WebSocket transport ─────────────────────────────────────────

  async _connectWS() {
    return new Promise((res, rej) => {
      const ws = new WebSocket(this.url);
      this._ws = ws;

      const timeout = setTimeout(() => {
        ws.close();
        rej(new Error(`MCP connection timeout (${CONNECT_TIMEOUT_MS}ms)`));
      }, CONNECT_TIMEOUT_MS);

      ws.onopen = async () => {
        clearTimeout(timeout);
        try {
          // MCP initialize handshake
          await this._rpc('initialize', {
            protocolVersion: MCP_PROTOCOL_VERSION,
            capabilities:    { tools: {}, resources: {}, prompts: {} },
            clientInfo:      { name: 'threataform', version: '1.0.0' },
          });
          // Discover available tools
          const toolsResult = await this._rpc('tools/list', {});
          this.tools     = toolsResult?.tools ?? [];
          this.connected = true;
          res(this.tools);
        } catch (e) {
          ws.close();
          rej(e);
        }
      };

      ws.onerror = (e) => {
        clearTimeout(timeout);
        this.connected = false;
        rej(new Error(`MCP WebSocket error: ${e.message ?? 'connection refused'}`));
      };

      ws.onclose = () => {
        this.connected = false;
        // Reject all pending requests
        for (const { rej: r, timer } of this._pending.values()) {
          clearTimeout(timer);
          r(new Error('MCP connection closed'));
        }
        this._pending.clear();
      };

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          this._handleMessage(msg);
        } catch { /* ignore malformed messages */ }
      };
    });
  }

  // ── Private: HTTP transport (fallback) ───────────────────────────────────

  async _connectHttp() {
    // HTTP transport: fire initialize, then tools/list
    try {
      await this._rpcHttp('initialize', {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities:    { tools: {} },
        clientInfo:      { name: 'threataform', version: '1.0.0' },
      });
      const toolsResult = await this._rpcHttp('tools/list', {});
      this.tools     = toolsResult?.tools ?? [];
      this.connected = true;
      return this.tools;
    } catch (e) {
      this.connected = false;
      throw e;
    }
  }

  async _rpcHttp(method, params) {
    const id   = ++this._id;
    const body = JSON.stringify({ jsonrpc: '2.0', id, method, params });
    const resp = await fetch(this.url, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body,
      signal:  AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    });
    if (!resp.ok) throw new Error(`MCP HTTP ${resp.status}: ${resp.statusText}`);
    const msg = await resp.json();
    if (msg.error) throw new Error(msg.error.message ?? JSON.stringify(msg.error));
    return msg.result;
  }

  // ── Private: JSON-RPC helpers ─────────────────────────────────────────────

  _rpc(method, params) {
    if (this._useHttp) return this._rpcHttp(method, params);

    const id = ++this._id;
    return new Promise((res, rej) => {
      const timer = setTimeout(() => {
        this._pending.delete(id);
        rej(new Error(`MCP request timeout: ${method}`));
      }, DEFAULT_TIMEOUT_MS);

      this._pending.set(id, { res, rej, timer });
      this._ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
    });
  }

  _handleMessage(msg) {
    // Handle both responses (id present) and notifications (no id)
    if (msg.id === undefined) return; // notification — ignore for now

    const pending = this._pending.get(msg.id);
    if (!pending) return;

    clearTimeout(pending.timer);
    this._pending.delete(msg.id);

    if (msg.error) {
      pending.rej(new Error(msg.error.message ?? JSON.stringify(msg.error)));
    } else {
      pending.res(msg.result);
    }
  }
}
