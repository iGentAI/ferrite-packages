import test from 'node:test';
import assert from 'node:assert/strict';
import { EventsClient, createWebhookSecret } from './events.mjs';

const endpoint = 'https://fixture.invalid/mcp';
const meta = { 'io.modelcontextprotocol/subscriptionId': 1 };
const active = {
  jsonrpc: '2.0', method: 'notifications/events/active',
  params: { cursor: 'c0', truncated: false, _meta: meta },
};
const event = {
  jsonrpc: '2.0', method: 'notifications/events/event',
  params: {
    cursor: 'c1', eventId: 'occurrence-1', name: 'changed',
    data: { text: 'café 世界 👋' }, timestamp: '2026-11-10T00:00:00Z', _meta: meta,
  },
};
const terminated = {
  jsonrpc: '2.0', method: 'notifications/events/terminated',
  params: { error: { code: -32024, message: 'permission revoked' }, _meta: meta },
};
const final = { jsonrpc: '2.0', id: 1, result: { resultType: 'complete', _meta: meta } };
const encoder = new TextEncoder();

function wire(frames, newline = '\n') {
  return encoder.encode(frames.map(frame => `data: ${JSON.stringify(frame)}${newline}${newline}`).join(''));
}

function stream(chunks, { close = true, cancel } = {}) {
  const body = new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      if (close) controller.close();
    },
    cancel,
  });
  const client = new EventsClient(endpoint, {
    fetch: async () => new Response(body, { headers: { 'Content-Type': 'text/event-stream' } }),
  });
  return client.stream({ name: 'changed' });
}

async function collect(source) {
  const frames = [];
  for await (const frame of source) frames.push(frame);
  return frames;
}

test('event destinations refuse unsafe URLs before looking up credentials or fetching', async () => {
  let credentials = 0;
  const requests = [];
  const options = {
    headers: () => { credentials++; return { Authorization: 'Bearer fixture' }; },
    fetch: async (url, request) => {
      requests.push({ url, authorization: request.headers.Authorization, redirect: request.redirect });
      const { id } = JSON.parse(request.body);
      return Response.json({ jsonrpc: '2.0', id, result: { resultType: 'complete', events: [] } });
    },
  };
  const refused = [
    'http://fixture.invalid/mcp',
    'http://127.0.0.1.fixture.invalid/mcp',
    'https://user:password@fixture.invalid/mcp',
    'http://user@127.0.0.1/mcp',
    'file:///tmp/mcp',
  ];
  for (const url of refused) {
    assert.throws(() => new EventsClient(url, options), /endpoint requires HTTPS or loopback HTTP/, url);
  }
  const client = new EventsClient(endpoint, options);
  client.endpoint = refused[0];
  await assert.rejects(client.list(), /endpoint requires HTTPS or loopback HTTP/);
  assert.equal(credentials, 0);
  assert.deepEqual(requests, []);

  const allowed = [endpoint, 'http://localhost:9080/mcp', 'http://127.0.0.1:9080/mcp', 'http://[::1]:9080/mcp'];
  for (const url of allowed) {
    const result = await new EventsClient(url, options).list();
    assert.deepEqual(result, { resultType: 'complete', events: [] });
  }
  assert.equal(credentials, allowed.length);
  assert.deepEqual(requests, allowed.map(url => ({ url, authorization: 'Bearer fixture', redirect: 'error' })));
});

test('stream yields exact activation and occurrence across every UTF-8 and CRLF split', async () => {
  const bytes = wire([active, event, final], '\r\n');
  const expected = [{ ...active.params, kind: 'active' }, { ...event.params, kind: 'event' }];
  for (let split = 0; split <= bytes.length; split++) {
    const source = stream([bytes.subarray(0, split), bytes.subarray(split)]);
    assert.deepEqual(await collect(source), expected, `split at byte ${split}`);
  }
});

test('invalid stream envelopes and ordering cancel the reader', async () => {
  const cases = [
    [[{ ...active, method: 'active' }], /notification method/],
    [[{ ...active, params: { ...active.params, _meta: { 'io.modelcontextprotocol/subscriptionId': 2 } } }], /subscription correlation/],
    [[{ ...final, error: { code: -1, message: 'contradiction' } }], /Invalid Events envelope/],
    [[final], /Invalid Events completion/],
    [[event], /did not activate/],
    [[active, active], /Duplicate Events activation/],
    [[active, terminated, event], /notification order/],
  ];
  for (const [frames, expected] of cases) {
    let cancelled = false;
    const source = stream([wire(frames)], { close: false, cancel: () => { cancelled = true; } });
    await assert.rejects(collect(source), expected);
    assert.equal(cancelled, true, String(expected));
  }
  const gap = { ...active, params: { ...active.params, cursor: 'replay-start', truncated: true } };
  assert.deepEqual(await collect(stream([wire([active, gap, event, terminated, final])])), [
    { ...active.params, kind: 'active' }, { ...gap.params, kind: 'active' },
    { ...event.params, kind: 'event' }, { ...terminated.params, kind: 'terminated' },
  ]);
});

test('stream refuses incomplete frames and malformed UTF-8 before yielding their payload', async () => {
  const activation = wire([active]);
  const occurrence = wire([event]);
  const truncated = stream([activation, occurrence.subarray(0, occurrence.length - 1)]);
  assert.deepEqual(await truncated.next(), { done: false, value: { ...active.params, kind: 'active' } });
  await assert.rejects(truncated.next(), /ended without its final response/);

  const broken = occurrence.slice();
  broken[broken.indexOf(0xc3)] = 0xff;
  let cancelled = false;
  const invalid = stream([activation, broken], { close: false, cancel: () => { cancelled = true; } });
  assert.deepEqual(await invalid.next(), { done: false, value: { ...active.params, kind: 'active' } });
  await assert.rejects(invalid.next(), TypeError);
  assert.equal(cancelled, true);
});

test('the 1 MiB Events limit bounds individual frames in bytes across chunks', async () => {
  const empty = { ...event, params: { ...event.params, data: { text: '' } } };
  const paddingBytes = 1024 * 1024 - wire([empty]).length;
  const text = 'é'.repeat(Math.floor(paddingBytes / 2)) + 'x'.repeat(paddingBytes % 2);
  const boundary = { ...event, params: { ...event.params, data: { text } } };
  const bytes = wire([boundary]);
  assert.equal(bytes.length, 1024 * 1024);
  // A transport chunk can contain multiple frames and exceed 1 MiB in total.
  const joined = Buffer.concat([wire([active]), bytes, wire([final])]);
  assert.deepEqual(await collect(stream([joined])), [
    { ...active.params, kind: 'active' }, { ...boundary.params, kind: 'event' },
  ]);

  const oversized = { ...event, params: { ...event.params, data: { text: text + 'x' } } };
  const over = wire([oversized]);
  assert.equal(over.length, 1024 * 1024 + 1);
  let cancelled = false;
  const source = stream([wire([active]), over.subarray(0, over.length - 1), over.subarray(over.length - 1)], {
    close: false, cancel: () => { cancelled = true; },
  });
  assert.deepEqual(await source.next(), { done: false, value: { ...active.params, kind: 'active' } });
  await assert.rejects(source.next(), /Oversized Events frame/);
  assert.equal(cancelled, true);
});

test('the Events byte limit counts both CRLF bytes even when the final LF is split', async () => {
  const empty = { ...event, params: { ...event.params, data: { text: '' } } };
  const limit = 1024 * 1024;
  const text = 'x'.repeat(limit - wire([empty], '\r\n').length);
  const boundary = { ...event, params: { ...event.params, data: { text } } };
  const exact = wire([boundary], '\r\n');
  assert.equal(exact.length, limit);
  assert.deepEqual(await collect(stream([
    wire([active], '\r\n'), exact.subarray(0, limit - 1), exact.subarray(limit - 1), wire([final], '\r\n'),
  ])), [{ ...active.params, kind: 'active' }, { ...boundary.params, kind: 'event' }]);

  const bare = { ...event, params: { ...event.params, data: { text: text + 'xx' } } };
  const bareCr = wire([bare], '\r');
  assert.equal(bareCr.length, limit);
  assert.deepEqual(await collect(stream([
    wire([active], '\r'), bareCr, wire([final], '\r'),
  ])), [{ ...active.params, kind: 'active' }, { ...bare.params, kind: 'event' }]);

  const oversized = { ...event, params: { ...event.params, data: { text: text + 'x' } } };
  const over = wire([oversized], '\r\n');
  assert.equal(over.length, limit + 1);
  assert.deepEqual([...over.subarray(limit - 1)], [13, 10]);
  let cancelled = false;
  const source = stream([wire([active], '\r\n'), over.subarray(0, limit), over.subarray(limit)], {
    close: false, cancel: () => { cancelled = true; },
  });
  assert.deepEqual(await source.next(), { done: false, value: { ...active.params, kind: 'active' } });
  await assert.rejects(source.next(), /Oversized Events frame/);
  assert.equal(cancelled, true);
});

test('callback secrets are fresh standard 256-bit secrets', () => {
  const first = createWebhookSecret();
  const second = createWebhookSecret();
  assert.notEqual(first, second);
  assert.equal(Buffer.from(first.slice(6), 'base64').length, 32);
  assert.match(first, /^whsec_[A-Za-z0-9+/]{43}=$/);
});

test('stream heartbeat timeout aborts an unresponsive fetch', async () => {
  let signal;
  const client = new EventsClient(endpoint, {
    heartbeatMs: 100,
    fetch: async (_url, options) => {
      signal = options.signal;
      return new Promise((_, reject) => signal.addEventListener('abort', () => reject(signal.reason), { once: true }));
    },
  });
  await assert.rejects(collect(client.stream({ name: 'changed' })), /heartbeat timed out/);
  assert.equal(signal.aborted, true);
});
