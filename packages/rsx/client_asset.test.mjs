// Regression tests for the Rsx browser runtime (src/client_asset.js).
//
// The runtime is run as written, in a `vm` context with a minimal fake
// DOM and cookie jar, a scripted `fetch`, and a fake IndexedDB (with real
// request callbacks inside a transaction) whose storage can be shared by
// several simulated tabs and page loads.
//
//   node --test packages/rsx/client_asset.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes, randomUUID } from 'node:crypto';
import vm from 'node:vm';

const SOURCE = readFileSync(new URL('./src/client_asset.js', import.meta.url), 'utf8');
const ORIGIN = 'https://app.example';
const DAY = 24 * 60 * 60 * 1000;
const SCOPE_COOKIE = 'shop_reader';
const CSRF_COOKIE = '__Host-rsx_csrf';
const TOKEN_A = 'a'.repeat(64);
const TOKEN_B = 'b'.repeat(64);

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
async function settle(rounds = 30) {
  for (let i = 0; i < rounds; i++) await tick();
}

function fakeIndexedDB(backing) {
  // Transactions on one store run one after another, across every tab that
  // shares the storage, as IndexedDB serialises overlapping readwrite work.
  const turn = (backing.__turn ||= { chain: Promise.resolve() });
  return {
    open() {
      const request = {};
      setTimeout(() => {
        request.result = {
          objectStoreNames: { contains: () => true },
          createObjectStore() {},
          transaction() {
            const tx = {};
            const queue = [];
            const req = (work) => {
              const r = {};
              queue.push({ r, work });
              return r;
            };
            const store = {
              put: (value) => req(() => void backing.set(value.key, structuredClone(value))),
              delete: (key) => req(() => void backing.delete(key)),
              clear: () => req(() => backing.clear()),
              get: (key) => req(() => (backing.has(key) ? structuredClone(backing.get(key)) : undefined)),
              count: () => req(() => backing.size),
              getAll: () => req(() => [...backing.values()].map((v) => structuredClone(v))),
            };
            tx.objectStore = () => store;
            turn.chain = turn.chain.then(async () => {
              await tick();
              while (queue.length) {
                const { r, work } = queue.shift();
                r.result = work();
                if (r.onsuccess) r.onsuccess();
                await tick();
              }
              if (tx.oncomplete) tx.oncomplete();
            });
            return tx;
          },
        };
        if (request.onsuccess) request.onsuccess();
      }, 0);
      return request;
    },
  };
}

const CRYPTO_FULL = {
  randomUUID: () => randomUUID(),
  getRandomValues: (array) => {
    const bytes = randomBytes(array.length);
    for (let i = 0; i < array.length; i++) array[i] = bytes[i];
    return array;
  },
};
const CRYPTO_NO_UUID = { getRandomValues: CRYPTO_FULL.getRandomValues };

class FakeFormData {
  constructor(form) {
    this.fields = form.fields || {};
  }
  forEach(callback) {
    for (const [name, value] of Object.entries(this.fields)) callback(value, name);
  }
}

function form(action, fields = {}) {
  const attrs = new Map([['data-rsx-action', action]]);
  return {
    tagName: 'FORM',
    fields,
    events: [],
    getAttribute: (k) => (attrs.has(k) ? attrs.get(k) : null),
    setAttribute: (k, v) => attrs.set(k, v),
    removeAttribute: (k) => attrs.delete(k),
    hasAttribute: (k) => attrs.has(k),
    querySelector: () => null,
    querySelectorAll: () => [],
    reset() {},
    dispatchEvent(event) {
      this.events.push(event);
      return true;
    },
  };
}

/**
 * One page load (or tab). `backing` is the IndexedDB contents, shared
 * between page loads and tabs of one browser profile. With `scoped`, the
 * page names the `shop_reader` cookie as its outbox scope, and `reader`
 * is that cookie's initial value (none when empty).
 */
function page({
  backing = new Map(),
  scoped = false,
  reader = '',
  crypto = CRYPTO_FULL,
  csrf = TOKEN_A,
  respond,
  origin = ORIGIN,
  csrfName = CSRF_COOKIE,
  planted = '',
} = {}) {
  const events = [];
  const listeners = {};
  const assigned = [];
  const calls = [];
  // The page was served with the action token cookie unless `csrf` is ''.
  const state = { reader, csrf };
  const jar = {
    get cookie() {
      let cookie = 'theme=dark';
      if (state.reader) cookie += `; ${SCOPE_COOKIE}=${state.reader}`;
      if (state.csrf) cookie += `; ${csrfName}=${state.csrf}`;
      if (planted) cookie += `; ${planted}`;
      return cookie;
    },
  };
  const meta = scoped ? { getAttribute: (n) => (n === 'content' ? SCOPE_COOKIE : null) } : null;
  const attrs = new Map();
  const document = {
    title: '',
    hidden: false,
    get cookie() {
      return jar.cookie;
    },
    documentElement: {
      style: {},
      setAttribute: (k, v) => attrs.set(k, v),
      removeAttribute: (k) => attrs.delete(k),
      getAttribute: (k) => (attrs.has(k) ? attrs.get(k) : null),
    },
    querySelector: (selector) => (selector === 'meta[name="rsx-outbox-scope-cookie"]' ? meta : null),
    querySelectorAll: () => [],
    addEventListener: (type, fn) => (listeners[type] ||= []).push(fn),
    dispatchEvent: (event) => {
      events.push(event);
      return true;
    },
  };
  const location = {
    origin,
    protocol: new URL(origin).protocol,
    pathname: '/page',
    search: '',
    hash: '',
    get href() {
      return `${origin}/page`;
    },
    set href(value) {
      assigned.push(value);
    },
  };
  const context = {
    document,
    location,
    history: { state: null, replaceState() {}, pushState() {} },
    navigator: { onLine: true },
    indexedDB: fakeIndexedDB(backing),
    crypto,
    URL,
    setTimeout,
    clearTimeout,
    console: { warn() {}, error() {}, log() {} },
    CustomEvent: class {
      constructor(type, init) {
        this.type = type;
        this.detail = init && init.detail;
      }
    },
    FormData: FakeFormData,
    scrollY: 0,
    scrollTo() {},
    fetch: (url, init) => {
      calls.push({ url: String(url), init });
      return respond ? respond(String(url), init) : Promise.reject(new TypeError('offline'));
    },
  };
  context.window = context;
  context.addEventListener = (type, fn) => (listeners[`window:${type}`] ||= []).push(fn);
  vm.createContext(context);
  // A guessable key must never be minted: any use of Math.random fails.
  vm.runInContext('Math.random = function () { throw new Error("Math.random is not a key source"); };', context);
  vm.runInContext(SOURCE, context);
  return {
    rsx: context.__rsx,
    events,
    assigned,
    calls,
    backing,
    /** Another tab (or an in-page sign-in) changes the scope cookie. */
    setReader: (value) => {
      state.reader = value;
    },
    /** The browser stores (or loses) the action token cookie. */
    setCsrf: (value) => {
      state.csrf = value;
    },
    actionCalls: () => calls.filter((c) => c.url.startsWith('/_rsx/action/')),
    named: (type) => events.filter((e) => e.type === type),
    fire: (type) => (listeners[`window:${type}`] || []).forEach((fn) => fn({})),
    submit: (f) =>
      (listeners.submit || []).forEach((fn) => fn({ target: f, defaultPrevented: false, preventDefault() {} })),
  };
}

const envelope = (extra = {}) =>
  new Response(
    JSON.stringify({ v: 1, status: 'ok', result: null, error: null, http_status: 200, expired_tags: [], redirect: null, ...extra }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const notFound = () => new Response('no', { status: 404 });
const answerActions = (make) => (url) => Promise.resolve(url.startsWith('/_rsx/action/') ? make(url) : notFound());

function queued(key, extra = {}) {
  return { key, action: 'save', args: { title: key }, at: Date.now(), attempts: 0, scope: '', ...extra };
}

/** A fetch that answers actions only when told to. */
function controlled() {
  const waiting = [];
  return {
    respond: (url) =>
      url.startsWith('/_rsx/action/')
        ? new Promise((resolve, reject) => waiting.push({ resolve, reject }))
        : Promise.resolve(notFound()),
    waiting,
  };
}

// ------------------------------------------------------------ F190

test('F190: an action redirect is followed only to a local path', async () => {
  for (const redirect of ['javascript:alert(document.cookie)', 'data:text/html,<script>x</script>', 'https://evil.example/login', '//evil.example/', '/\t/evil.example/']) {
    const p = page({ respond: answerActions(() => envelope({ redirect })) });
    await settle();
    await p.rsx.action('save', {});
    await settle();
    assert.deepEqual(p.assigned.filter((u) => !u.startsWith(`${ORIGIN}/page`)), [], `redirect ${redirect} must not be followed`);
  }
  const p = page({ respond: answerActions(() => envelope({ redirect: '/orders/1' })) });
  await settle();
  await p.rsx.action('save', {});
  await settle();
  assert.ok(p.calls.some((c) => c.url === '/orders/1'), 'a local redirect is navigated to');
  assert.deepEqual(p.assigned, [`${ORIGIN}/orders/1`], 'and falls back to a full load of the same path');
});

test('F190: navigate never assigns a non-http(s) URL to location', async () => {
  const p = page({ respond: () => Promise.resolve(notFound()) });
  await settle();
  for (const url of ['javascript:alert(1)', 'JaVaScRiPt:alert(1)', 'data:text/html,x', 'vbscript:x']) {
    await p.rsx.navigate(url);
  }
  await settle();
  assert.deepEqual(p.assigned, []);
  await p.rsx.navigate('https://other.example/x');
  assert.deepEqual(p.assigned, ['https://other.example/x'], 'an explicit cross-origin http(s) navigation still works');
});

// ------------------------------------------------------------ F489

test('F489: keys come from a CSPRNG, and without one nothing is sent', async () => {
  let p = page({ crypto: CRYPTO_NO_UUID, respond: answerActions(() => envelope()) });
  await settle();
  await p.rsx.action('save', {});
  const key = p.actionCalls()[0].init.headers['idempotency-key'];
  assert.match(key, /^[0-9a-f]{32}$/, 'getRandomValues supplies the key when randomUUID is missing');

  p = page({ crypto: null, respond: answerActions(() => envelope()) });
  await settle();
  await assert.rejects(p.rsx.action('save', {}), (e) => e.decided === true);
  assert.equal(p.actionCalls().length, 0, 'no request with a guessable key');

  const f = form('save', { title: 'x' });
  p.submit(f);
  await settle();
  assert.equal(p.actionCalls().length, 0);
  assert.equal(p.rsx.pending().length, 0, 'and nothing is queued');
  assert.equal(f.events.at(-1).detail.queued, false);
});

// ------------------------------------------------------------ F490

test('F490: a completed reply that is not an envelope, below 500, is decided: not retried or queued', async () => {
  for (const reply of [
    () => new Response('<html>sign in</html>', { status: 200, headers: { 'content-type': 'text/html' } }),
    () => new Response('request body too large', { status: 413 }),
    () => new Response('<html>forbidden</html>', { status: 403 }),
    () => json(200, { error: 'login required' }),
    () => json(403, { error: 'forbidden' }),
  ]) {
    const p = page({ respond: answerActions(reply) });
    await settle();
    const f = form('save', { title: 'x' });
    p.submit(f);
    await settle();
    assert.equal(p.actionCalls().length, 1, 'no retry');
    assert.equal(p.rsx.pending().length, 0, 'not queued');
    assert.equal(p.backing.size, 0);
    const failed = f.events.find((e) => e.type === 'rsx:action-failed');
    assert.equal(failed.detail.queued, false);
    assert.equal(failed.detail.retryable, false);
  }
});

test('F490: an ambiguous failure, JSON or not, is retried and queued with an attempt count', async () => {
  for (const reply of [() => new Response('deadline exceeded', { status: 504 }), () => json(503, { error: 'unavailable' })]) {
    const p = page({ respond: answerActions(reply) });
    await settle();
    p.submit(form('save', { title: 'x' }));
    await settle();
    assert.equal(p.actionCalls().length, 3, 'the first attempt and two retries, under one key');
    assert.equal(new Set(p.actionCalls().map((c) => c.init.headers['idempotency-key'])).size, 1);
    assert.equal(p.rsx.pending().length, 1);
    assert.equal(p.rsx.pending()[0].attempts, 0);
  }
});

test('F490: a drain drops refused and expired entries, and a JSON 503 is not a replay', async () => {
  const backing = new Map();
  const p = page({ backing, respond: answerActions(() => new Response('<html>sign in</html>', { status: 200 })) });
  await settle();
  const now = Date.now();
  for (const entry of [
    queued('too-many', { attempts: 8, at: now - 3 }),
    queued('too-old', { at: now - 8 * DAY }),
    queued('refused', { at: now - 1 }),
  ]) {
    backing.set(entry.key, entry);
  }
  await p.rsx.drain({ confirm: true });
  await settle();
  assert.deepEqual(p.actionCalls().map((c) => c.init.headers['idempotency-key']), ['refused'], 'expired entries are not replayed');
  assert.equal(backing.size, 0, 'refused and expired entries are removed');
  assert.equal(p.named('rsx:action-expired').length, 2);
  assert.equal(p.named('rsx:action-refused').length, 1);

  const busy = page({ backing, respond: answerActions(() => json(503, { error: 'unavailable' })) });
  await settle();
  backing.set('first', queued('first', { at: now - 2 }));
  backing.set('second', queued('second', { at: now - 1 }));
  await busy.rsx.drain({ confirm: true });
  await settle();
  assert.deepEqual(busy.actionCalls().map((c) => c.init.headers['idempotency-key']), ['first'], 'the drain stops at the first ambiguous failure');
  assert.equal(busy.named('rsx:action-replayed').length, 0, 'a gateway error body is not an envelope');
  assert.equal(backing.get('first').attempts, 1, 'the attempt is counted and the entry kept');
  assert.equal(backing.get('second').attempts, 0);
});

test('F490: the queue is bounded, across tabs', async () => {
  const backing = new Map();
  // A second tab that is already open, and so has read the queue empty.
  const other = page({ backing });
  await settle();
  const p = page({ backing });
  await settle();
  const forms = [];
  for (let i = 0; i < 55; i++) {
    const f = form('save', { title: `t${i}` });
    forms.push(f);
    p.submit(f);
  }
  await settle(800);
  assert.equal(backing.size, 50);
  assert.equal(forms.at(-1).events.find((e) => e.type === 'rsx:action-failed').detail.queued, false);

  // The other tab has not seen those entries; it is still refused, because
  // the bound is checked in the storage transaction.
  const f = form('save', { title: 'from the other tab' });
  other.submit(f);
  await settle();
  assert.equal(backing.size, 50);
  assert.equal(f.events.find((e) => e.type === 'rsx:action-failed').detail.queued, false);
});

// ------------------------------------------------------------ F191

test('F191: without a declared identity, nothing replays automatically, even on the same page', async () => {
  const backing = new Map();
  let online = false;
  const respond = (url) => (online ? answerActions(() => envelope())(url) : Promise.reject(new TypeError('offline')));
  const first = page({ backing, respond });
  await settle();
  first.submit(form('save', { title: 'from A' }));
  await settle();
  assert.equal(backing.size, 1, 'queued durably');
  online = true;
  const before = first.actionCalls().length;
  first.fire('online');
  await settle();
  assert.equal(first.actionCalls().length, before, 'an in-page sign-out and sign-in cannot be seen, so it is held');

  const second = page({ backing, respond: answerActions(() => envelope()) });
  await settle();
  assert.equal(second.actionCalls().length, 0, 'nor after a reload');
  assert.equal(second.named('rsx:pending').at(-1).detail.held, 1);
  assert.equal(await second.rsx.drain({ confirm: true }), 1, 'the application confirms with the reader');
  assert.equal(backing.size, 0);
});

test('F191: a scoped mutation replays automatically only while the same reader holds the scope cookie', async () => {
  let backing = new Map();
  let online = false;
  const respond = (url) => (online ? answerActions(() => envelope())(url) : Promise.reject(new TypeError('offline')));
  const p = page({ backing, scoped: true, reader: 'reader-a', respond });
  await settle();
  p.submit(form('save', { title: 'from A' }));
  await settle();
  assert.equal([...backing.values()][0].scope, 'reader-a');
  online = true;
  p.fire('online');
  await settle();
  assert.equal(p.named('rsx:action-replayed').length, 1, 'same reader, same page: replayed');

  backing = new Map();
  const a = page({ backing, scoped: true, reader: 'reader-a' });
  await settle();
  a.submit(form('save', { title: 'from A' }));
  await settle();
  const reloaded = page({ backing, scoped: true, reader: 'reader-a', respond: answerActions(() => envelope()) });
  await settle();
  assert.equal(reloaded.actionCalls().length, 1, 'same reader after a reload: replayed');
});

test('F191: a reader change in another tab or in-page discards the entry; a signed-out page holds it', async () => {
  const backing = new Map();
  const p = page({ backing, scoped: true, reader: 'reader-a' });
  await settle();
  p.submit(form('save', { title: 'from A' }));
  await settle();
  assert.equal(backing.size, 1);

  // Signed out: the owner is not here, so not even a confirmed drain sends it.
  const signedOut = page({ backing, scoped: true, respond: answerActions(() => envelope()) });
  await settle();
  await signedOut.rsx.drain({ confirm: true });
  await settle();
  assert.equal(signedOut.actionCalls().length, 0);
  assert.equal(backing.size, 1, 'held for its owner');

  // The same tab, after B signed in elsewhere: the cookie now says B.
  p.setReader('reader-b');
  p.fire('online');
  await p.rsx.drain({ confirm: true });
  await settle();
  assert.equal(p.actionCalls().filter((c) => c.init.headers['idempotency-key']).length, 3, 'only the original three attempts');
  assert.equal(backing.size, 0, 'discarded, never sent as B');
  assert.equal(p.named('rsx:action-discarded').length, 1);
});

test('F191: the identity is the one at the press, and a reader change stops the retries', async () => {
  const backing = new Map();
  let p;
  const respond = (url) => {
    if (!url.startsWith('/_rsx/action/')) return Promise.resolve(notFound());
    p.setReader('reader-b'); // B signs in while A's request is in flight
    return Promise.reject(new TypeError('offline'));
  };
  p = page({ backing, scoped: true, reader: 'reader-a', respond });
  await settle();
  p.submit(form('save', { title: 'from A' }));
  await settle();
  assert.equal(p.actionCalls().length, 1, 'no retry after the reader changed');
  assert.equal([...backing.values()][0].scope, 'reader-a', 'queued as A, not as B');
});

test('F191: clearOutbox forgets every queued mutation (sign-out)', async () => {
  const backing = new Map();
  const p = page({ backing });
  await settle();
  p.submit(form('save', { title: 'one' }));
  p.submit(form('save', { title: 'two' }));
  await settle();
  assert.equal(backing.size, 2);
  assert.equal(await p.rsx.clearOutbox(), true);
  await settle();
  assert.equal(backing.size, 0);
  assert.equal(p.rsx.pending().length, 0);
});

test('F191: a clear during an in-flight drain stops it and nothing is written back', async () => {
  const backing = new Map();
  const fetcher = controlled();
  const p = page({ backing, scoped: true, reader: 'reader-a', respond: fetcher.respond });
  await settle();
  const now = Date.now();
  backing.set('first', queued('first', { at: now - 2, scope: 'reader-a' }));
  backing.set('second', queued('second', { at: now - 1, scope: 'reader-a' }));
  const draining = p.rsx.drain();
  await settle();
  assert.equal(p.actionCalls().length, 1, 'the first replay is in flight');
  await p.rsx.clearOutbox();
  fetcher.waiting[0].reject(new TypeError('offline'));
  await draining;
  await settle();
  assert.equal(p.actionCalls().length, 1, 'the second entry is never sent');
  assert.equal(backing.size, 0, 'the ambiguous failure does not resurrect the cleared entry');
});

test('F191: a clear while a submission is in flight means it is not queued', async () => {
  const backing = new Map();
  const fetcher = controlled();
  const p = page({ backing, respond: fetcher.respond });
  await settle();
  const f = form('save', { title: 'x' });
  p.submit(f);
  await settle();
  await p.rsx.clearOutbox();
  // Reject the first attempt and both retries.
  for (let i = 0; i < 3; i++) {
    await settle();
    if (fetcher.waiting[i]) fetcher.waiting[i].reject(new TypeError('offline'));
  }
  await settle();
  assert.equal(backing.size, 0);
  assert.equal(f.events.find((e) => e.type === 'rsx:action-failed').detail.queued, false);
});

// ------------------------------------------------------------ the action token

const sentBody = (call) => JSON.parse(call.init.body);

test('an action call carries the cookie\'s token in its body, read when it is sent', async () => {
  const p = page({ respond: answerActions(() => envelope()) });
  await settle();
  await p.rsx.action('save', { title: 'x' });
  assert.deepEqual(sentBody(p.actionCalls()[0]), { title: 'x', _rsx_csrf: TOKEN_A });
  p.setCsrf(TOKEN_B);
  await p.rsx.action('save', { title: 'y' });
  assert.equal(sentBody(p.actionCalls()[1])._rsx_csrf, TOKEN_B, 'the token as it is now, not as it was at load');
  assert.equal(p.calls.filter((c) => c.url === '/_rsx/csrf').length, 0, 'a held cookie needs no request');
});

test('without a cookie the runtime asks /_rsx/csrf for a token before it posts', async () => {
  let p;
  const respond = (url) => {
    if (url === '/_rsx/csrf') {
      p.setCsrf(TOKEN_B); // the browser stores the cookie the reply sets
      return Promise.resolve(json(200, { v: 1, token: TOKEN_B }));
    }
    return answerActions(() => envelope())(url);
  };
  p = page({ csrf: '', respond });
  await settle();
  await p.rsx.action('save', { title: 'x' });
  assert.deepEqual(p.calls.map((c) => c.url).filter((u) => u !== '/page'), ['/_rsx/csrf', '/_rsx/action/save']);
  assert.equal(sentBody(p.actionCalls()[0])._rsx_csrf, TOKEN_B);
});

test('a page served over plain http by ferrite dev sends the token from the unprefixed cookie', async () => {
  // Safari keeps no `Secure` cookie on http://localhost, so `ferrite dev`
  // issues the token as `rsx_csrf_dev`, and the runtime reads that name there.
  const p = page({ origin: 'http://localhost:8787', csrfName: 'rsx_csrf_dev', respond: answerActions(() => envelope()) });
  await settle();
  await p.rsx.action('save', { title: 'x' });
  assert.deepEqual(sentBody(p.actionCalls()[0]), { title: 'x', _rsx_csrf: TOKEN_A });
  assert.equal(p.calls.filter((c) => c.url === '/_rsx/csrf').length, 0, 'a held cookie needs no request');
});

test('over https the unprefixed cookie is never read in place of the prefixed one', async () => {
  // A sibling host can plant `rsx_csrf_dev`; a deployed page ignores it.
  let p;
  const respond = (url) => {
    if (url === '/_rsx/csrf') {
      p.setCsrf(TOKEN_A);
      return Promise.resolve(json(200, { v: 1, token: TOKEN_A }));
    }
    return answerActions(() => envelope())(url);
  };
  p = page({ csrf: '', planted: `rsx_csrf_dev=${TOKEN_B}`, respond });
  await settle();
  await p.rsx.action('save', { title: 'x' });
  assert.deepEqual(p.calls.map((c) => c.url).filter((u) => u !== '/page'), ['/_rsx/csrf', '/_rsx/action/save']);
  assert.equal(sentBody(p.actionCalls()[0])._rsx_csrf, TOKEN_A);
});

test('a form\'s stale token field is not an argument, and a queued mutation stores no token', async () => {
  const backing = new Map();
  let online = false;
  const respond = (url) => (online ? answerActions(() => envelope())(url) : Promise.reject(new TypeError('offline')));
  const p = page({ backing, respond });
  await settle();
  p.submit(form('save', { title: 'x', _rsx_csrf: 'c'.repeat(64) }));
  await settle();
  assert.equal(backing.size, 1, 'queued');
  const [entry] = [...backing.values()];
  assert.deepEqual(entry.args, { title: 'x' }, 'the queue keeps arguments, never a token');
  for (const call of p.actionCalls()) assert.equal(sentBody(call)._rsx_csrf, TOKEN_A, 'every attempt sends the cookie\'s token');
  // The reader's token changes before the replay; the replay carries the new one.
  p.setCsrf(TOKEN_B);
  online = true;
  await p.rsx.drain({ confirm: true });
  await settle();
  assert.equal(sentBody(p.actionCalls().at(-1))._rsx_csrf, TOKEN_B);
  assert.equal(backing.size, 0);
});

test('prefetch caches the soft-navigation payload without polluting pendingActions', async () => {
  const payload = { v: 1, title: 'Orders', head: '', body: '<main>Orders</main>', slots: {} };
  const p = page({
    respond: (url) =>
      url === '/orders'
        ? Promise.resolve(
            new Response(JSON.stringify(payload), {
              status: 200,
              headers: { 'content-type': 'application/json', 'cache-control': 'max-age=60' },
            }),
          )
        : Promise.resolve(notFound()),
  });
  await settle();
  await p.rsx.prefetch('/orders');
  await settle();
  assert.equal(p.rsx.pending().length, 0, 'prefetch must not push URLs into pendingActions');
  await p.rsx.prefetch('/orders');
  assert.equal(
    p.calls.filter((c) => c.url === '/orders').length,
    1,
    'second prefetch hits the in-memory navigation cache',
  );
});

test('cross-origin redirects in soft navigation and slot fetches are refused without DOM injection', async () => {
  const crossOriginResponse = (body) => {
    const res = new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
    Object.defineProperty(res, 'url', { value: 'https://evil.example/payload' });
    Object.defineProperty(res, 'redirected', { value: true });
    return res;
  };
  const p = page({
    respond: (url) => {
      if (url === '/out') {
        return Promise.resolve(
          crossOriginResponse({
            v: 1,
            patch_at: 'seg:/',
            html: '<img src=x onerror=alert(1)>',
            segments: [{ id: 'seg:/', hash: 'evil' }],
            head: { title: 'Pwned' },
          }),
        );
      }
      return Promise.resolve(notFound());
    },
  });
  await settle();
  await p.rsx.navigate('/out');
  await settle();
  assert.ok(
    p.assigned.includes('https://evil.example/payload'),
    'cross-origin redirect in soft navigation must fall back to hard navigation to res.url rather than applying payload HTML',
  );
});

