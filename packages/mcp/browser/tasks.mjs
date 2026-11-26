/** MCP Tasks 2026-07-28. Uses native Fetch in browsers and Node 22+. */
export const TASKS_EXTENSION = 'io.modelcontextprotocol/tasks';
const terminal = new Set(['completed', 'failed', 'cancelled']);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

function validSamplingBlock(block) {
  return object(block) && (block.type !== 'text' || typeof block.text === 'string');
}

function validSamplingMessage(message) {
  if (!object(message) || !['user', 'assistant'].includes(message.role)) return false;
  const { content } = message;
  return Array.isArray(content) ? content.every(validSamplingBlock) : validSamplingBlock(content);
}

function validMultiSelectItems(items) {
  return object(items) && (
    (items.type === 'string' && Array.isArray(items.enum) && items.enum.every(value => typeof value === 'string')) ||
    (Array.isArray(items.anyOf) && items.anyOf.every(option =>
      object(option) && typeof option.const === 'string' && typeof option.title === 'string'))
  );
}

function validFormProperty(property) {
  return object(property) && (['string', 'integer', 'number', 'boolean'].includes(property.type) ||
    (property.type === 'array' && validMultiSelectItems(property.items)));
}

function validInputRequest(request) {
  if (!object(request)) return false;
  const { method, params } = request;
  if (method === 'roots/list') return params === undefined || object(params);
  if (!object(params)) return false;
  if (method === 'sampling/createMessage') {
    return Number.isSafeInteger(params.maxTokens) && Array.isArray(params.messages) && params.messages.every(validSamplingMessage);
  }
  if (method !== 'elicitation/create' || typeof params.message !== 'string') return false;
  if (params.mode === 'url') return typeof params.url === 'string';
  const schema = params.requestedSchema;
  return (params.mode === undefined || params.mode === 'form') && object(schema) &&
    schema.type === 'object' && object(schema.properties) && Object.values(schema.properties).every(validFormProperty) &&
    (schema.required === undefined || (Array.isArray(schema.required) && schema.required.every(key => typeof key === 'string')));
}

export function validateTask(task, detailed = true) {
  for (const key of ['taskId', 'createdAt', 'lastUpdatedAt']) {
    if (typeof task?.[key] !== 'string' || !task[key]) throw new Error(`Task has no ${key}`);
  }
  if (task.ttlMs !== null && !Number.isSafeInteger(task.ttlMs)) throw new Error('Invalid task ttlMs');
  if (task.pollIntervalMs !== undefined && (!Number.isSafeInteger(task.pollIntervalMs) || task.pollIntervalMs < 0)) throw new Error('Invalid pollIntervalMs');
  if (task.statusMessage !== undefined && typeof task.statusMessage !== 'string') throw new Error('Invalid task statusMessage');
  if (!terminal.has(task.status) && !['working', 'input_required'].includes(task.status)) throw new Error('Unknown task status');
  const field = {completed:'result', failed:'error', input_required:'inputRequests'}[task.status];
  if (detailed && field && !object(task[field])) throw new Error(`Task has no ${field} object`);
  if (detailed && task.status === 'failed' && (!Number.isSafeInteger(task.error.code) || typeof task.error.message !== 'string')) throw new Error('Failed task has no structured protocol error');
  if (detailed && task.status === 'input_required' && !Object.values(task.inputRequests).every(validInputRequest)) throw new Error('Invalid task input request');
  return task;
}

function delay(ms, signal) {
  return new Promise((resolve, reject) => {
    signal?.throwIfAborted();
    const finish = () => { signal?.removeEventListener('abort', abort); resolve(); };
    const timer = setTimeout(finish, ms);
    const abort = () => { clearTimeout(timer); reject(signal.reason); };
    signal?.addEventListener('abort', abort, {once:true});
  });
}

export class TasksClient {
  constructor(endpoint, {fetch = globalThis.fetch, headers = () => ({}), accountId, saveReceipt, timeoutMs = 30000, elicitationForm = false} = {}) {
    this.endpoint = new URL(endpoint).href;
    const url = new URL(this.endpoint);
    if (url.username || url.password || (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost','127.0.0.1','[::1]'].includes(url.hostname)))) throw new Error('Tasks endpoint requires HTTPS or loopback HTTP');
    if (typeof fetch !== 'function') throw new Error('Fetch is required');
    this.fetch = fetch;
    this.headers = headers;
    this.accountId = accountId;
    this.saveReceipt = saveReceipt;
    this.timeoutMs = timeoutMs;
    this.elicitationForm = elicitationForm === true;
    this.sequence = 0;
    this.negotiated = false;
  }

  async open(method, params = {}, {signal, timeoutMs = this.timeoutMs} = {}) {
    const id = ++this.sequence;
    const timeout = AbortSignal.timeout(timeoutMs);
    const requestSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
    const name = method === 'tools/call' ? params.name : params.taskId;
    const capabilities = this.negotiated || method.startsWith('tasks/') || method === 'subscriptions/listen' ? {extensions:{[TASKS_EXTENSION]:{}}} : {};
    if (this.elicitationForm) capabilities.elicitation = {form:{}};
    const response = await this.fetch(this.endpoint, {
      method:'POST', redirect:'error', signal:requestSignal,
      headers:{...await this.headers(), 'Content-Type':'application/json', Accept:'application/json,text/event-stream',
        'MCP-Protocol-Version':'2026-07-28', 'Mcp-Method':method, ...(name ? {'Mcp-Name':name} : {})},
      body:JSON.stringify({jsonrpc:'2.0',id,method,params:{...params,_meta:{
        'io.modelcontextprotocol/protocolVersion':'2026-07-28',
        'io.modelcontextprotocol/clientCapabilities':capabilities
      }}})
    });
    return {id,response};
  }

  async request(method, params = {}, options) {
    const {id,response} = await this.open(method,params,options);
    return this.readResponse(method,id,response);
  }

  async readResponse(method,id,response) {
    const reader = response.body.getReader();
    let bytes = 0;
    let text = '';
    const decoder = new TextDecoder();
    try {
      while (true) {
        const {done,value} = await reader.read();
        if (done) break;
        bytes += value.byteLength;
        if (bytes > 1024 * 1024) throw new Error('MCP response exceeds 1 MiB');
        text += decoder.decode(value,{stream:true});
      }
      text += decoder.decode();
    } finally { await reader.cancel().catch(() => {}); }
    let documents;
    try {
      documents = response.headers.get('content-type')?.includes('text/event-stream')
      ? text.replace(/\r\n/g,'\n').split('\n\n').flatMap(frame => {
        const data = frame.split('\n').filter(line => line.startsWith('data:')).map(line => line.slice(5).trimStart()).join('\n');
        return data ? [JSON.parse(data)] : [];
      }) : [JSON.parse(text)];
    } catch (cause) {
      if (!response.ok) throw new Error(`MCP ${method} HTTP ${response.status}`, {cause});
      throw cause;
    }
    const matches = documents.filter(doc => doc.jsonrpc === '2.0' && doc.id === id);
    if (matches.length !== 1) throw new Error('MCP response ID mismatch');
    const reply = matches[0];
    if ('result' in reply && 'error' in reply) throw new Error('Invalid MCP result/error envelope');
    if (reply.error) {
      if (!object(reply.error) || !Number.isSafeInteger(reply.error.code) || typeof reply.error.message !== 'string') throw new Error('Invalid MCP error envelope');
      const error = new Error(`MCP ${method} error ${reply.error.code}: ${reply.error.message}`);
      error.code = reply.error.code;
      error.data = reply.error.data;
      throw error;
    }
    if (!response.ok) throw new Error(`MCP ${method} HTTP ${response.status}`);
    const result = reply.result;
    if (!object(result)) throw new Error('Missing MCP result');
    if (result.resultType === 'task') {
      if (!this.negotiated || method !== 'tools/call') throw new Error('Unnegotiated task result');
      return validateTask(result,false);
    }
    if (result.resultType !== 'complete') throw new Error('Expected complete MCP result');
    return result;
  }

  async discover(options) {
    const discovery = await this.request('server/discover',{},options);
    this.negotiated = object(discovery.capabilities?.extensions?.[TASKS_EXTENSION]);
    return discovery;
  }

  async callTool(name, args, options) {
    if (!this.accountId || typeof this.saveReceipt !== 'function') throw new Error('accountId and durable saveReceipt are required before starting a task');
    if (!this.negotiated) await this.discover(options);
    if (!this.negotiated) throw new Error('Server does not advertise MCP Tasks');
    const result = await this.request('tools/call',{name,arguments:args},options);
    if (result.resultType === 'task') {
      const receipt = {version:1,endpoint:this.endpoint,accountId:this.accountId,taskId:result.taskId};
      try { await this.saveReceipt(receipt); }
      catch (cause) { const error = new Error('Task started but receipt persistence failed; recover with the attached receipt',{cause}); error.receipt = receipt; throw error; }
      return {...result,receipt};
    }
    return result;
  }

  async get(taskId, options) {
    const task = validateTask(await this.request('tasks/get',{taskId},options));
    if (task.taskId !== taskId) throw new Error('Task ID mismatch');
    return task;
  }

  async update(taskId, inputResponses, options) {
    if (!object(inputResponses) || !Object.keys(inputResponses).length || Object.entries(inputResponses).some(([id,result]) => !id || !object(result) || 'jsonrpc' in result)) throw new Error('inputResponses must contain result objects keyed by request ID');
    return this.request('tasks/update',{taskId,inputResponses},options);
  }

  /** ACK means cancellation requested. get/watch observes confirmed cancellation. */
  async cancel(taskId, options) { return this.request('tasks/cancel',{taskId},options); }

  /** Selective status push. Reconnect with the saved IDs; get remains authoritative. */
  async *listen(taskIds, {signal} = {}) {
    if (!Array.isArray(taskIds) || !taskIds.length || taskIds.some(id => typeof id !== 'string' || !id) || new Set(taskIds).size !== taskIds.length) throw new Error('taskIds must be distinct nonempty IDs');
    const controller = new AbortController();
    const combined = signal ? AbortSignal.any([signal,controller.signal]) : controller.signal;
    let reader;
    try {
      const {id,response} = await this.open('subscriptions/listen',{notifications:{taskIds}},{signal:combined,timeoutMs:this.timeoutMs+5000});
      if (!response.ok) await this.readResponse('subscriptions/listen',id,response);
      if (!response.headers.get('content-type')?.startsWith('text/event-stream')) throw new Error('Tasks subscription requires an SSE response');
      reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      let acknowledged = false;
      while (true) {
        const {done,value} = await reader.read();
        if (done) throw new Error('Tasks subscription ended without completion');
        buffer += decoder.decode(value,{stream:true});
        buffer = buffer.replace(/\r\n/g,'\n');
        if (buffer.length > 1024*1024) throw new Error('Tasks subscription frame exceeds 1 MiB');
        let end;
        while ((end = buffer.indexOf('\n\n')) >= 0) {
          const frame = buffer.slice(0,end); buffer = buffer.slice(end+2);
          const data = frame.split('\n').filter(line=>line.startsWith('data:')).map(line=>line.slice(5).trimStart()).join('\n');
          if (!data) continue;
          const message = JSON.parse(data);
          if (message.jsonrpc !== '2.0' || ('result' in message && 'error' in message)) throw new Error('Invalid Tasks subscription envelope');
          if ('id' in message) {
            if (!acknowledged || message.id !== id || message.result?.resultType !== 'complete' || message.result?._meta?.['io.modelcontextprotocol/subscriptionId'] !== id) throw new Error('Invalid Tasks subscription completion');
            return;
          }
          const params = message.params;
          if (params?._meta?.['io.modelcontextprotocol/subscriptionId'] !== id) throw new Error('Tasks subscription ID mismatch');
          if (message.method === 'notifications/subscriptions/acknowledged') {
            const accepted = params.notifications?.taskIds;
            if (acknowledged || !Array.isArray(accepted) || accepted.length !== taskIds.length || new Set(accepted).size !== taskIds.length || accepted.some(taskId => !taskIds.includes(taskId))) throw new Error('Tasks acknowledgement filter mismatch');
            acknowledged = true;
          } else {
            if (!acknowledged || message.method !== 'notifications/tasks' || !taskIds.includes(params.taskId)) throw new Error('Unexpected Tasks notification');
            yield validateTask(params);
          }
        }
      }
    } finally { controller.abort(); await reader?.cancel().catch(()=>{}); }
  }

  /** Reconnect using only the saved identity. Never resubmits tools/call. */
  async watch(receipt, {signal,onUpdate = () => {}} = {}) {
    if (receipt.version !== 1 || receipt.endpoint !== this.endpoint || receipt.accountId !== this.accountId || !receipt.taskId) throw new Error('Task receipt belongs to another endpoint or account');
    while (true) {
      const task = await this.get(receipt.taskId,{signal});
      await onUpdate(task);
      if (terminal.has(task.status) || task.status === 'input_required') return task;
      await delay(Math.max(100, Math.min(task.pollIntervalMs ?? 3000,60000)),signal);
    }
  }
}
