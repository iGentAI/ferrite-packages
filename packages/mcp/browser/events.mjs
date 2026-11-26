const MAX_FRAME_BYTES = 1024 * 1024;

function eventsEndpoint(endpoint) {
  const url = new URL(endpoint);
  const localHttp = url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.username || url.password || (!localHttp && url.protocol !== 'https:')) {
    throw new Error('Events endpoint requires HTTPS or loopback HTTP without embedded credentials');
  }
  return url.href;
}

async function* eventBlocks(reader) {
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const buffer = new Uint8Array(MAX_FRAME_BYTES);
  let length = 0;
  let previousCr = false;
  let previousNewline = false;
  let boundaryCr = false;

  function takeBlock() {
    const block = decoder.decode(buffer.subarray(0, length)).replace(/\r\n?/g, '\n');
    length = 0;
    previousNewline = false;
    return block;
  }

  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      if (boundaryCr) yield takeBlock();
      return;
    }
    for (const byte of value) {
      if (boundaryCr) {
        // At the limit, distinguish a bare CR from an over-limit CRLF before yielding.
        if (byte === 10) throw new Error('Oversized Events frame');
        boundaryCr = false;
        yield takeBlock();
      }
      const continuedCr = byte === 10 && previousCr;
      previousCr = byte === 13;
      // A CRLF in the frame counts as two wire bytes. After a dispatched frame,
      // its trailing LF still fits because an exact-cap CR was deferred above.
      if (continuedCr && length === 0) continue;
      if (length === MAX_FRAME_BYTES) throw new Error('Oversized Events frame');
      buffer[length++] = byte;
      if (continuedCr) continue;

      const newline = previousCr || byte === 10;
      const frameEnded = newline && previousNewline;
      previousNewline = newline;
      if (!frameEnded) continue;
      boundaryCr = previousCr && length === MAX_FRAME_BYTES;
      if (!boundaryCr) yield takeBlock();
    }
  }
}

/** Experimental SEP-3415 client. Uses fetch, so it also works in modern Node.
 * The caller owns credentials, cursor persistence and event processing. */
export class EventsClient {
  constructor(endpoint, { fetch: fetcher = globalThis.fetch, headers = () => ({}), heartbeatMs = 15000 } = {}) {
    this.endpoint = eventsEndpoint(endpoint); this.fetch = fetcher; this.headers = headers;
    this.heartbeatMs = heartbeatMs; this.sequence = 0;
    if (!Number.isFinite(heartbeatMs) || heartbeatMs < 100 || heartbeatMs > 30000) throw new Error('Invalid heartbeat interval');
  }
  async request(method, params, signal) {
    const endpoint = eventsEndpoint(this.endpoint);
    const id = ++this.sequence;
    const response = await this.fetch(endpoint, {
      method: 'POST', redirect: 'error', signal,
      headers: { ...await this.headers(), 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream',
        'MCP-Protocol-Version': '2026-07-28', 'Mcp-Method': method, ...(params.name ? { 'Mcp-Name': params.name } : {}) },
      body: JSON.stringify({ jsonrpc: '2.0', id, method, params: { ...params, _meta: {
        'io.modelcontextprotocol/protocolVersion': '2026-07-28', 'io.modelcontextprotocol/clientCapabilities': {} } } }),
    });
    return { id, response };
  }
  async call(method, params = {}, { signal } = {}) {
    const { id, response } = await this.request(method, params, AbortSignal.any([...(signal ? [signal] : []), AbortSignal.timeout(15000)]));
    const reader = response.body?.getReader(); if (!reader) throw new Error('Missing response body');
    let text = ''; const decoder = new TextDecoder(); let size = 0;
    try { for (;;) { const {done, value} = await reader.read(); if (done) break;
      if ((size += value.byteLength) > 1048576) throw new Error('Oversized MCP response'); text += decoder.decode(value, {stream:true});
    } } finally { await reader.cancel().catch(() => {}); }
    text += decoder.decode();
    const message = JSON.parse(text);
    if (message.jsonrpc !== '2.0' || message.id !== id) throw new Error('MCP response correlation failed');
    if (message.error) throw Object.assign(new Error(message.error.message), message.error);
    if (!response.ok || !message.result || message.result.resultType !== 'complete') throw new Error(`Unexpected MCP response (${response.status})`);
    return message.result;
  }
  list(options) { return this.call('events/list', {}, options); }
  poll(params, options) { return this.call('events/poll', params, options); }
  subscribe(params, options) { return this.call('events/subscribe', params, options); }
  unsubscribe(params, options) { return this.call('events/unsubscribe', params, options); }
  /** Yield each correlated active/event/heartbeat/gap/error/terminated message.
   * No silent reconnect: persist the cursor only after processing the message,
   * then reopen with that cursor. Aborting closes the underlying HTTP request. */
  async *stream(params, { signal } = {}) {
    const controller = new AbortController();
    const combined = AbortSignal.any([controller.signal, ...(signal ? [signal] : [])]);
    let timer;
    const arm = () => { clearTimeout(timer); timer = setTimeout(() => controller.abort(new Error('Events stream heartbeat timed out')), this.heartbeatMs * 2); };
    let reader;
    try {
      arm();
      const { id, response } = await this.request('events/stream', params, combined);
      if (!response.ok || !response.headers.get('content-type')?.startsWith('text/event-stream')) throw new Error(`Events stream refused (${response.status})`);
      reader = response.body.getReader();
      let activated = false;
      let terminated = false;
      for await (const block of eventBlocks(reader)) {
        const data = block.split('\n')
          .filter(line => line === 'data' || line.startsWith('data:'))
          .map(line => line.slice(5).replace(/^ /, ''))
          .join('\n');
        if (!data) continue;
        const message = JSON.parse(data);
        if (!message || typeof message !== 'object' || message.jsonrpc !== '2.0' || ('result' in message && 'error' in message)) throw new Error('Invalid Events envelope');
        if ('id' in message) {
          if (!activated || 'method' in message || message.id !== id || message.result?.resultType !== 'complete' || message.result?._meta?.['io.modelcontextprotocol/subscriptionId'] !== id) throw new Error('Invalid Events completion');
          return;
        }
        if (terminated || 'result' in message || 'error' in message) throw new Error('Invalid Events notification order');
        if (typeof message.method !== 'string' || !message.method.startsWith('notifications/events/')) throw new Error('Invalid Events notification method');
        const kind = message.method.slice('notifications/events/'.length);
        if (!['active','event','heartbeat','error','terminated'].includes(kind) || message.params?._meta?.['io.modelcontextprotocol/subscriptionId'] !== id) throw new Error('Events subscription correlation failed');
        if (!activated && kind !== 'active') throw new Error('Events stream did not activate');
        if (['active','event','heartbeat'].includes(kind)) {
          if (!(message.params.cursor === null || typeof message.params.cursor === 'string')) throw new Error('Invalid Events cursor');
          arm();
        }
        if (kind === 'active') {
          if (typeof message.params.truncated !== 'boolean') throw new Error('Invalid gap signal');
          if (activated && !message.params.truncated) throw new Error('Duplicate Events activation without a gap');
          activated = true;
        }
        if (kind === 'event' && (typeof message.params.eventId !== 'string' || message.params.name !== params.name || !message.params.data || typeof message.params.data !== 'object' || Array.isArray(message.params.data))) throw new Error('Invalid event occurrence');
        terminated = kind === 'terminated';
        yield { ...message.params, kind };
      }
      throw new Error('Events stream ended without its final response');
    } finally { clearTimeout(timer); controller.abort(); await reader?.cancel().catch(() => {}); }
  }
}

/** Generate a callback secret locally; never log it or send it to an LLM. */
export function createWebhookSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return 'whsec_' + btoa(String.fromCharCode(...bytes));
}
