import test from 'node:test';
import assert from 'node:assert/strict';
import {TasksClient,TASKS_EXTENSION} from './tasks.mjs';
const endpoint = 'https://example.test/mcp';
const task = status => ({taskId:'task-1',status,createdAt:'2026-11-04T00:00:00Z',lastUpdatedAt:'2026-11-04T00:00:00Z',ttlMs:10000,pollIntervalMs:100});
function harness(replies,extra={}) {
  const calls=[];
  const client=new TasksClient(endpoint,{accountId:'owner',saveReceipt:async () => {},fetch:async (_,options) => {
    const request=JSON.parse(options.body); calls.push({request,headers:options.headers});
    const reply=replies.shift();
    if (reply instanceof Error) throw reply;
    return Response.json({jsonrpc:'2.0',id:request.id,result:reply});
  },...extra});
  return {client,calls};
}
const discovery={resultType:'complete',capabilities:{extensions:{[TASKS_EXTENSION]:{}}}};
test('negotiates, persists, reconnects and returns terminal isError without a second launch',async () => {
  let saved;
  const {client,calls}=harness([discovery,{...task('working'),resultType:'task'}],{saveReceipt:async r => {saved=r;}});
  const start=await client.callTool('build',{source:'example'});
  assert.deepEqual(saved,start.receipt);
  assert.equal(calls[1].request.params._meta['io.modelcontextprotocol/clientCapabilities'].extensions[TASKS_EXTENSION] instanceof Object,true);
  const resumed=harness([{...task('completed'),resultType:'complete',result:{isError:true,content:[]}}]);
  const final=await resumed.client.watch(saved);
  assert.equal(final.result.isError,true);
  assert.deepEqual(resumed.calls.map(c=>c.request.method),['tasks/get']);
  assert.equal(resumed.calls[0].headers['Mcp-Name'],'task-1');
});
test('lost submission reply is never retried',async () => {
  const {client,calls}=harness([discovery,new Error('connection lost')]);
  await assert.rejects(client.callTool('build',{}),/connection lost/);
  assert.equal(calls.filter(c=>c.request.method==='tools/call').length,1);
});
test('input and cancellation acknowledgements remain distinct from terminal state',async () => {
  const {client,calls}=harness([
    {...task('input_required'),resultType:'complete',inputRequests:{ask:{method:'elicitation/create',params:{message:'Approve?',requestedSchema:{type:'object',properties:{}}}}}},
    {resultType:'complete'},{resultType:'complete'},
    {...task('cancelled'),resultType:'complete'}]);
  const receipt={version:1,endpoint,accountId:'owner',taskId:'task-1'};
  assert.equal((await client.watch(receipt)).status,'input_required');
  await client.update('task-1',{ask:{action:'accept',content:{approved:true}}});
  const ack=await client.cancel('task-1'); assert.equal(ack.status,undefined);
  assert.equal((await client.watch(receipt)).status,'cancelled');
  assert.equal(calls[1].request.params.inputResponses.ask.action,'accept');
  await assert.rejects(client.update('task-1',{ask:{jsonrpc:'2.0',result:{}}}),/result objects/);
});
test('refuses unsupported discovery, wrong account and lost persistence',async () => {
  const unsupported=harness([{resultType:'complete',capabilities:{}}]);
  await assert.rejects(unsupported.client.callTool('build',{}),/does not advertise/);
  assert.equal(unsupported.calls.length,1);
  await assert.rejects(unsupported.client.watch({version:1,endpoint,accountId:'other',taskId:'t'}),/another endpoint or account/);
  const lost=harness([discovery,{...task('working'),resultType:'task'}],{saveReceipt:async()=>{throw new Error('disk full');}});
  await assert.rejects(lost.client.callTool('build',{}),error=>error.receipt.taskId==='task-1');
});
test('selective push requires acknowledgement and exact task/subscription correlation',async () => {
  const meta={'io.modelcontextprotocol/subscriptionId':1};
  const acknowledged={jsonrpc:'2.0',method:'notifications/subscriptions/acknowledged',params:{notifications:{taskIds:['task-1']},_meta:meta}};
  const notification={jsonrpc:'2.0',method:'notifications/tasks',params:{...task('completed'),result:{content:[]},_meta:meta}};
  const complete={jsonrpc:'2.0',id:1,result:{resultType:'complete',_meta:meta}};
  const create=frames=>new TasksClient(endpoint,{fetch:async()=>new Response(frames.map(f=>'data: '+JSON.stringify(f)+'\n\n').join(''),{headers:{'Content-Type':'text/event-stream'}})});
  const seen=[]; for await(const state of create([acknowledged,notification,complete]).listen(['task-1'])) seen.push(state);
  assert.equal(seen[0].status,'completed');
  for(const frames of [[notification,complete],[acknowledged,{...notification,params:{...notification.params,taskId:'other'}},complete],[acknowledged,notification]]) {
    await assert.rejects(async()=>{for await(const state of create(frames).listen(['task-1'])) {} });
  }
});

test('form elicitation requires explicit client opt-in and never implies sampling',async () => {
  for (const elicitationForm of [false,true]) {
    const {client,calls}=harness([discovery,{...task('working'),resultType:'task'}],{elicitationForm});
    await client.callTool('report',{});
    const capabilities=calls[1].request.params._meta['io.modelcontextprotocol/clientCapabilities'];
    assert.deepEqual(capabilities.elicitation,elicitationForm?{form:{}}:undefined);
    assert.equal(capabilities.sampling,undefined);
  }
});

test('non-success HTTP replies preserve bounded correlated JSON-RPC errors for polling and push',async () => {
  const fetch=async(_,options)=> {
    const request=JSON.parse(options.body);
    return Response.json({jsonrpc:'2.0',id:request.id,error:{code:-32021,message:'Form capability required',data:{requiredCapabilities:{elicitation:{form:{}}}}}},{status:400});
  };
  const client=new TasksClient(endpoint,{fetch});
  const typed=error=>error.code===-32021&&error.message.includes('Form capability required')&&Boolean(error.data.requiredCapabilities.elicitation.form);
  await assert.rejects(client.get('task-1'),typed);
  await assert.rejects(async()=>{for await(const state of client.listen(['task-1'])) {}},typed);
  const invalid=new TasksClient(endpoint,{fetch:async()=>new Response('upstream unavailable',{status:503})});
  await assert.rejects(invalid.get('task-1'),/HTTP 503/);
  const huge=new TasksClient(endpoint,{fetch:async()=>new Response('x'.repeat(1024*1024+1),{status:503})});
  await assert.rejects(huge.get('task-1'),/exceeds 1 MiB/);
});
