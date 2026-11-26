import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createServer} from 'node:http';
import {TasksClient,TASKS_EXTENSION} from './tasks.mjs';
const task = (status,extra={}) => ({resultType:'complete',taskId:'owned',status,createdAt:'2026-11-04T00:00:00Z',lastUpdatedAt:'2026-11-04T00:00:00Z',ttlMs:3600000,pollIntervalMs:100,...extra});
async function server(t,respond) {
  const calls=[];
  const http=createServer(async(req,res)=>{
    const chunks=[];for await(const part of req)chunks.push(part);
    const rpc=JSON.parse(Buffer.concat(chunks));calls.push({rpc,at:performance.now()});
    const value=respond(rpc,res,calls);
    if(value!==undefined){res.setHeader('Content-Type','application/json');res.end(JSON.stringify({jsonrpc:'2.0',id:rpc.id,result:value}));}
  });
  await new Promise(resolve=>http.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{http.closeAllConnections();await new Promise(resolve=>http.close(resolve));});
  return {endpoint:`http://127.0.0.1:${http.address().port}/mcp`,calls};
}
test('JS direct results preserve tool-error without fabricating a receipt',async t=>{
  const f=await server(t,rpc=>rpc.method==='server/discover'?{resultType:'complete',capabilities:{extensions:{[TASKS_EXTENSION]:{}}}}:{resultType:'complete',isError:true,content:[]});
  let saved=0;const client=new TasksClient(f.endpoint,{accountId:'owner',saveReceipt:async()=>saved++});
  assert.equal((await client.callTool('direct',{})).isError,true);assert.equal(saved,0);
  assert.deepEqual(f.calls.map(c=>c.rpc.method),['server/discover','tools/call']);
});
test('JS stops observer polling after abort and preserves the running task',async t=>{
  const f=await server(t,()=>task('working',{pollIntervalMs:150}));
  const client=new TasksClient(f.endpoint,{accountId:'owner'});
  const controller=new AbortController();let updates=0;
  await assert.rejects(client.watch({version:1,endpoint:f.endpoint,accountId:'owner',taskId:'owned'},{signal:controller.signal,onUpdate:()=>{if(++updates===2)controller.abort(new Error('stop observer'));}}),/stop observer/);
  assert.equal(f.calls.length,2);assert.ok(f.calls[1].at-f.calls[0].at>=135);
  await new Promise(resolve=>setTimeout(resolve,200));assert.equal(f.calls.length,2);
  assert.ok(f.calls.every(c=>c.rpc.method==='tasks/get'));
  assert.equal((await client.get('owned')).status,'working');
});
test('JS refuses identity mismatch before loading credentials and never follows a redirect',async t=>{
  for(const endpoint of ['http://public.example/mcp','https://user:secret@example.test/mcp'])assert.throws(()=>new TasksClient(endpoint));
  let credentialReads=0;
  const sink=await server(t,()=>{assert.fail('redirect target received request');});
  const redirect=await server(t,(_rpc,res)=>{res.writeHead(307,{Location:sink.endpoint});res.end();});
  const client=new TasksClient(redirect.endpoint,{accountId:'owner',headers:()=>{credentialReads++;return {Authorization:'Bearer synthetic-only'};}});
  for(const override of [{accountId:'other'},{endpoint:sink.endpoint}])await assert.rejects(client.watch({version:1,endpoint:redirect.endpoint,accountId:'owner',taskId:'owned',...override}),/another endpoint or account/);
  assert.equal(credentialReads,0);assert.equal(redirect.calls.length,0);
  await assert.rejects(client.get('owned'));assert.equal(sink.calls.length,0);assert.equal(redirect.calls.length,1);
});
test('JS preserves failed/cancelled/input states and rejects invalid terminal details',async t=>{
  for(const [status,extra] of [['failed',{error:{code:-32603,message:'fixture'}}],['cancelled',{}],['input_required',{inputRequests:{approval:{method:'elicitation/create',params:{message:'Approve?',requestedSchema:{type:'object',properties:{}}}}}}]]) {
    const f=await server(t,()=>task(status,extra));const client=new TasksClient(f.endpoint,{accountId:'owner'});
    assert.equal((await client.watch({version:1,endpoint:f.endpoint,accountId:'owner',taskId:'owned'})).status,status);assert.equal(f.calls.length,1);
  }
  const f=await server(t,()=>task('completed'));const client=new TasksClient(f.endpoint);
  await assert.rejects(client.get('owned'),/no result object/);
});

test('JS checks pinned Task reply vectors before returning a result or saving a receipt', async t => {
  const fixture = new URL('../../../tools/protocol-acceptance/task-reply-vectors.json', import.meta.url);
  const { cases } = JSON.parse(await readFile(fixture, 'utf8'));
  let reply;
  const f = await server(t, rpc => rpc.method === 'server/discover'
    ? { resultType: 'complete', capabilities: { extensions: { [TASKS_EXTENSION]: {} } } }
    : reply);
  for (const { name, definition, accept, task: expected } of cases) {
    await t.test(name, async () => {
      reply = expected;
      const creation = definition === 'CreateTaskResult';
      const receipts = [];
      const client = new TasksClient(f.endpoint, { accountId: 'owner', saveReceipt: receipt => receipts.push(receipt) });
      const callStart = f.calls.length;
      const result = creation ? client.callTool('fixture', {}) : client.get('owned');
      if (!accept) {
        await assert.rejects(result);
        assert.deepEqual(receipts, []);
      } else if (creation) {
        const receipt = { version: 1, endpoint: f.endpoint, accountId: 'owner', taskId: 'owned' };
        assert.deepEqual(await result, { ...expected, receipt });
        assert.deepEqual(receipts, [receipt]);
      } else {
        assert.deepEqual(await result, expected);
        assert.deepEqual(receipts, []);
      }
      assert.deepEqual(f.calls.slice(callStart).map(c => c.rpc.method), creation ? ['server/discover', 'tools/call'] : ['tasks/get']);
    });
  }
});
