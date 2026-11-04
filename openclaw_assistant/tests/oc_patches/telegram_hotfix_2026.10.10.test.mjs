// Regression tests for the Telegram hotfix VOLT-TG-20261023 on OpenClaw 2026.10.10 (oc-patches/2026.10.10).
// Ported from telegram_hotfix_2026.10.4.test.mjs (written by Volt, exported 2026-10-25). Changes for 2026.10.10:
// chunk names; import bindings (export letters) are read from the patched send chunk instead of being
// hard-coded; the custody field is attempt.voltReleaseLive; the session entry is read asynchronously
// (readSessionEntryReadOnlyInWorker); sendMediaBatch uses sendLogger, recordActivity() and the object form of
// reportDelivery; the fetch slice ends at the transport's return object (2026.10.10 has no `const close`).
// New cases: the notice decision after the asynchronous session read, the real deliverReply tail with
// deferred finalization, the voice-privacy rejection after the text, and long non-voice audio.
// They exercise the patched function bodies with synthetic fake transports (no bot token, no gateway).
// Run in a container of the image built with OPENCLAW_VERSION=2026.10.10 (needs Node 24: the modules use
// `using` declarations):
//   node --test tests/oc_patches/telegram_hotfix_2026.10.10.test.mjs
// or against an unpacked package patched by oc_dist_patch.py whose runtime dependencies resolve:
//   OC_DIST=<copy>/dist OC_STOCK_DIST=<package>/dist node --test tests/oc_patches/telegram_hotfix_2026.10.10.test.mjs
// Limits (as for 2026.10.4): the transport harness's sourceFetch ignores init.body, so the two fetch cases
// about fallbacks do not model grammY's one-shot multipart upload body; sendChunkedText and the lifecycle
// wiring are stubbed.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const OPENCLAW_VERSION = '2026.10.10';
// Patched chunks (tests/test_dist_patch.py checks these names against oc-patches/2026.10.10/manifest.json).
const LIFECYCLE = 'lifecycle-CTu0ulYU.mjs';
const EXECUTION = 'execution-Bn2DNr5X.mjs';
const SEND = 'send-CWj-wSIU.mjs';
const FETCH = 'fetch-ThK4NBmH.mjs';

// OC_DIST: the patched dist of the image (default: $(npm root -g)/openclaw/dist).
// OC_STOCK_DIST: a directory with the unpatched 2026.10.10 modules for the two negative controls
// (skipped when unset), e.g. package/dist of `npm pack openclaw@2026.10.10`.
const distDir = process.env.OC_DIST || path.join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'openclaw', 'dist');
const stockDir = process.env.OC_STOCK_DIST || '';
const pkgJson = path.join(distDir, '..', 'package.json');
if (fs.existsSync(pkgJson)) {
  const version = JSON.parse(fs.readFileSync(pkgJson, 'utf8')).version;
  assert.equal(version, OPENCLAW_VERSION, `these tests are for OpenClaw ${OPENCLAW_VERSION}; OC_DIST belongs to ${version}`);
}
const read = name => fs.readFileSync(path.join(distDir, name), 'utf8');
const life = read(LIFECYCLE);
const execution = read(EXECUTION);
const send = read(SEND);
const fetchSource = read(FETCH);
// Export letters change with every build: resolve what the send chunk imports under these local names.
const importOf = (source, local) => {
  for (const m of source.matchAll(/^import \{([^}]*)\} from "\.\/([^"]+)";$/gm)) {
    for (const spec of m[1].split(',')) {
      const [name, alias] = spec.trim().split(/\s+as\s+/);
      if ((alias ?? name) === local) return { file: m[2], name };
    }
  }
  assert.fail(`${SEND} does not import ${local}`);
};
const load = async ({ file, name }) => (await import(pathToFileURL(path.join(distDir, file)).href))[name];
const netImport = importOf(send, 'isRecoverableTelegramNetworkError');
const safeImport = importOf(send, 'isSafeToRetrySendError');
assert.equal(netImport.file, FETCH);
assert.equal(safeImport.file, FETCH);
const realNetworkError = await load(netImport);
const realSafeRetry = await load(safeImport);
const realReceipt = await load(importOf(send, 'createMessageReceiptFromOutboundResults'));
const slice = (s,a,b) => { const start=s.indexOf(a); assert(start>=0,a); const end=s.indexOf(b,start+a.length);assert(end>=0,b);return s.slice(start,end); };
const registry = slice(life,'const voltLiveDeliveries =','function resolvePendingFinalCompletion');
const guard = slice(execution,'function voltHasLiveDelivery','const PENDING_DELIVERY_NOTICE');
const noticeCode = slice(execution,'const PENDING_DELIVERY_NOTICE =','//#endregion\n//#region src/channels/turn/execution.ts');
const defer = () => { let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject}; };
const completion = {sessionId:'session',intentId:'intent'};

function liveHarness() {
  const scope=vm.createContext({Map,Symbol,JSON,globalThis:{},resolvePendingFinalCompletion:p=>p.completion});
  vm.runInContext(registry+guard,scope);
  return scope;
}
function noticeStubs(entryOrRead, counter) {
  return {
    readSessionEntryReadOnlyInWorker: typeof entryOrRead === 'function' ? entryOrRead : async()=>entryOrRead,
    normalizeDeliveryContext:x=>x,deliveryContextKey:()=> 'route',deliveryContextFromSession:()=>({}),
    getGatewayRecoveryRuntime:()=>({sendRecoveryNotice:async()=>{counter.notices++;return {suppressed:false}}}),
    findDeliveryIntentOwner:async()=>null,appendAssistantMessageToSessionTranscript:async()=>({ok:true}),updateSessionEntry:async()=>{},
  };
}
const owedEntry = () => ({sessionId:'session',pendingDeliveryNotice:{state:'owed',intentId:'intent',context:{channel:'telegram',to:'synthetic'}},deliveryContext:{}});

test('in-flight exact intent is guarded; unrelated intent/session is not',()=>{
  const s=liveHarness();const release=s.voltAcquireDelivery(completion);
  assert.equal(s.voltHasLiveDelivery('session','intent'),true);
  assert.equal(s.voltHasLiveDelivery('other','intent'),false);
  assert.equal(s.voltHasLiveDelivery('session','other'),false);
  release();assert.equal(s.voltHasLiveDelivery('session','intent'),false);
});
test('parallel sends share refcount; releasing one cannot expose the other',()=>{
  const s=liveHarness();const a=s.voltAcquireDelivery(completion),b=s.voltAcquireDelivery(completion);
  a();a();assert.equal(s.voltHasLiveDelivery('session','intent'),true);
  b();assert.equal(s.voltHasLiveDelivery('session','intent'),false);
});
test('delivery guard spans async send and clears on failure',async()=>{
  const s=liveHarness(), d=defer();
  s.voltDeliverReply=async()=>d.promise;
  vm.runInContext(slice(life,'\tasync function deliverReply(', '    async function voltDeliverReply('),s);
  const p=s.deliverReply({completion},{},{});
  assert.equal(s.voltHasLiveDelivery('session','intent'),true);
  d.reject(new Error('unknown outcome'));await assert.rejects(p,/unknown outcome/);
  assert.equal(s.voltHasLiveDelivery('session','intent'),false);
});
test('deferred finalization keeps live guard until canonical settlement',async()=>{
  const s=liveHarness(), d=defer(); let attempt;
  s.voltDeliverReply=async(p,i,o,c)=>{c.deferred=true;attempt={voltReleaseLive:c.release};return {finalization:d.promise};};
  s.voltSettleChannelDeliveryAttempt=async()=>d.promise;
  vm.runInContext(slice(life,'\tasync function deliverReply(', '    async function voltDeliverReply('),s);
  vm.runInContext(slice(life,'async function settleChannelDeliveryAttempt(', 'async function voltSettleChannelDeliveryAttempt('),s);
  await s.deliverReply({completion},{},{});
  assert.equal(s.voltHasLiveDelivery('session','intent'),true);
  const settling=s.settleChannelDeliveryAttempt(attempt);
  d.resolve();await settling;
  assert.equal(s.voltHasLiveDelivery('session','intent'),false);
});
test('patched deliverReply tail hands the live custody to a deferred attempt or to the immediate settlement',async()=>{
  // The test above stubs voltDeliverReply; this one runs its real tail (attempt object + finalization branch).
  const tail=slice(life,'\t\tconst attempt = {\n\t\t\tstate: "fulfilled",','\n\t\treturn result;\n\t}');
  const s=liveHarness();
  const run=vm.runInContext(`(async (voltLive, result, pendingAttempts, settleChannelDeliveryAttempt) => {\nconst effectivePayload = {}, directInfo = {}, emitMessageSentForDelivery = void 0, delivery = {};\n${tail}\n})`,s);
  const deferred={release:s.voltAcquireDelivery(completion),deferred:false}, pending=[];
  await run(deferred,{finalization:new Promise(()=>{})},pending,async()=>assert.fail('settled before its finalization'));
  assert.equal(deferred.deferred,true);assert.equal(pending.length,1);assert.equal(pending[0].voltReleaseLive,deferred.release);
  assert.equal(s.voltHasLiveDelivery('session','intent'),true);
  const direct={release:()=>{},deferred:false};let settled;
  await run(direct,{},[],async attempt=>{settled=attempt;});
  assert.equal(direct.deferred,false);assert.equal(settled.voltReleaseLive,direct.release);
  deferred.release();assert.equal(s.voltHasLiveDelivery('session','intent'),false);
});
test('actual notice path skips active send, retains genuine unknown and restart notice',async()=>{
  const s=liveHarness();const counter={notices:0};const entry=owedEntry();
  Object.assign(s,noticeStubs(entry,counter));
  vm.runInContext(noticeCode,s);
  const release=s.voltAcquireDelivery(completion);
  await s.deliverPendingDeliveryNotice('synthetic','store');assert.equal(counter.notices,0);
  assert.equal(entry.pendingDeliveryNotice.state,'owed');
  release();await s.deliverPendingDeliveryNotice('synthetic','store');assert.equal(counter.notices,1);
  const restart=liveHarness();Object.assign(restart,s); // use a fresh registry below
  restart.globalThis={};
  await restart.deliverPendingDeliveryNotice('synthetic','store');assert.equal(counter.notices,2);
});
test('notice decision uses the live state after the asynchronous session read',async()=>{
  const s=liveHarness();const counter={notices:0};const read=defer();
  Object.assign(s,noticeStubs(()=>read.promise,counter));
  vm.runInContext(noticeCode,s);
  const pending=s.deliverPendingDeliveryNotice('synthetic','store');
  const release=s.voltAcquireDelivery(completion); // a delivery starts while the worker read is in flight
  read.resolve(owedEntry());await pending;assert.equal(counter.notices,0);
  release();
});

const mediaStart='\t\tconst sendMediaBatch = async (batch) => {', mediaEnd='\n\t\tif (mediaUrls.length > 0)';
function mediaHarness({long=true,voice=true,failure,signalAborted=false,textFailure,source=send}={}) {
  const events=[],parts=[];let id=100;
  const media={result:{message_id:200,chat:{id:'synthetic'}},messageId:200,acceptedParams:{},plainText:'',hasInlineKeyboard:false,sender:{operation:voice?'sendVoice':'sendAudio',label:voice?'voice':'audio'}};
  const scope=vm.createContext({
    finalMediaBatch:true,mediaUrls:['synthetic-audio'],replyMarkup:undefined,singleUseReplyTo:true,
    text:'x'.repeat(long?1500:100),chatId:'synthetic',cfg:{},ownerAgentId:'test',account:{accountId:'synthetic'},
    opts:{signal:{aborted:signalAborted},promptContextProjectionPlan:{cursor:{invalidate:()=>events.push('invalidate')}}},
    buildThreadParams:include=>({reply:include}),probeVideoDimensions:async()=>undefined,
    sendChunkedText:async()=>{events.push('text');if(textFailure)throw textFailure;parts.push({messageId:++id,result:{message_id:id,chat:{id:'synthetic'}}});return {messageId:String(id),chatId:'synthetic',receipt:realReceipt({results:[{messageId:String(id),chatId:'synthetic'}],kind:'text'})};},
    sender:{parts,sendMedia:async()=>{events.push('voice');if(failure)throw failure;return media;},acceptMany:async(ps,observe)=>{parts.push(...ps);for(const p of ps)await observe(p);}},
    isTelegramPhotoLimitError:()=>false,isTelegramVoiceMessagesForbiddenError:e=>e.forbidden===true,
    isRecoverableTelegramNetworkError:realNetworkError,findTelegramRequestAuthorityError:()=>null,
    sendLogger:{warn:()=>events.push('audio-warning')},logVerbose:()=>{},
    resolveAcceptedReplyToMessageId:p=>p?.reply?99:undefined,toAcceptedThreadScopedParams:x=>x,
    recordDeliveredPromptContext:async()=>{},recordSentMessage:async()=>{},
    reportDelivery:async({messageId,fallbackChatId,meta,kind,onPrepared})=>onPrepared?.({messageId:String(messageId),chatId:fallbackChatId,meta,receipt:realReceipt({results:[{messageId:String(messageId),chatId:fallbackChatId}],kind})}),
    telegramCaptionDeliveryMetadata:new WeakSet(),logTelegramOutboundSendOk:()=>{},recordActivity:()=>{},
    resolveTelegramMessageIdOrThrow:r=>r.message_id,buildMediaReceipt:()=>({parts:[]}),
    createMessageReceiptFromOutboundResults:realReceipt,
  });
  vm.runInContext(slice(source,mediaStart,mediaEnd)+'\nglobalThis.run = sendMediaBatch;',scope);
  const plan={htmlCaption:long?undefined:'short',plainCaption:long?undefined:'short',followUpText:long?'x'.repeat(1500):undefined,deliveryKind:'audio'};
  const batch=[{index:0,media:{buffer:new Uint8Array()},mediaPlan:plan,mediaSender:{label:voice?'voice':'audio',operation:voice?'sendVoice':'sendAudio'}}];
  return {scope,events,run:()=>scope.run(batch)};
}
const networkFailure=()=>Object.assign(new Error('socket reset'),{code:'ECONNRESET'});
test('long voice sends text first and receipt retains both posts',async()=>{
  const h=mediaHarness();const r=await h.run();assert.deepEqual(h.events,['text','voice']);
  assert.equal(r.receipt.parts.length,2);assert.equal(r.receipt.parts[0].kind,'text');assert.equal(r.receipt.parts[1].kind,'media');
});
test('network failure after confirmed text keeps text; no second text or audio retry',async()=>{
  const h=mediaHarness({failure:networkFailure()});const r=await h.run();assert.equal(r.messageId,'101');
  assert.deepEqual(h.events,['text','voice','invalidate','audio-warning']);
});
test('voice-privacy rejection after confirmed text keeps text without a second text',async()=>{
  const h=mediaHarness({failure:Object.assign(new Error('VOICE_MESSAGES_FORBIDDEN'),{forbidden:true})});const r=await h.run();
  assert.equal(r.messageId,'101');assert.deepEqual(h.events,['text','voice','invalidate','audio-warning']);
});
test('short voice keeps caption path unchanged',async()=>{
  const h=mediaHarness({long:false});await h.run();assert.deepEqual(h.events,['voice']);
});
test('short voice network failure remains ambiguous, not silently accepted',async()=>{
  const h=mediaHarness({long:false,failure:networkFailure()});await assert.rejects(h.run());assert.deepEqual(h.events,['voice','invalidate']);
});
test('long audio (not voice) keeps the stock order: media first, text follow-up',async()=>{
  const h=mediaHarness({voice:false});await h.run();assert.deepEqual(h.events,['voice','text']); // sendMedia logs 'voice' for any label
});
test('text rejection stops before optional voice; no hidden partial text replay',async()=>{
  const h=mediaHarness({textFailure:new Error('text failed')});await assert.rejects(h.run(),/text failed/);assert.deepEqual(h.events,['text']);
});
test('cancellation/authority and non-network failures are never swallowed',async()=>{
  for(const options of [{failure:networkFailure(),signalAborted:true},{failure:new Error('permission failure')}]){
    const h=mediaHarness(options);await assert.rejects(h.run());assert(!h.events.includes('audio-warning'));
  }
});

const transportStart='\tconst resolvedFetch = (async (input, init) => {', transportEnd='\n\treturn {\n\t\tfetch: resolvedFetch,';
async function transportHarness(method,error,source=fetchSource) {
  const flags=[];let calls=0;
  const scope=vm.createContext({
    closed:false,Request,extractTelegramApiMethod:()=>method,
    shouldRetryTelegramTransportFallback:()=>true,isSafeToRetrySendError:realSafeRetry,
    bindTelegramTransportAuthority:source=>source,getTelegramRequestAuthority:()=>null,
    sourceFetch:async()=>{calls++;if(calls===1&&error)throw error;return new Response('{}');},
    stickyAttemptIndex:0,primaryProbeDue:false,getAttemptCooldownError:()=>null,
    transportAttempts:[0,1].map(()=>({exportAttempt:{},createDispatcher:f=>{flags.push(f);return {};}})),
    expectDefined:x=>x,promoteStickyAttempt:()=>{},recordAttemptFailure:()=>{},recordSuccessfulAttempt:()=>{},describeProxyTunnelFailure:()=>null,
    captureHttpExchangeAsync:async()=>{},resolveRequestUrl:()=> 'https://synthetic.invalid',randomUUID:()=> 'synthetic',log:{debug:()=>{}},
    TelegramRequestNotStartedError:Error,
  });
  vm.runInContext(slice(source,transportStart,transportEnd)+'\nglobalThis.run=resolvedFetch;',scope);
  let failed=false;try{await scope.run('https://synthetic.invalid',{});}catch{failed=true;}
  return {calls,flags,failed};
}
test('voice reset after possible acceptance is not replayed; fresh connection requested',async()=>{
  const r=await transportHarness('sendvoice',networkFailure());assert.equal(r.calls,1);assert.equal(r.failed,true);assert.deepEqual(r.flags,[true]);
});
test('proven pre-connect voice failure permits bounded fallback',async()=>{
  const r=await transportHarness('sendvoice',Object.assign(new Error('connect refused'),{code:'ECONNREFUSED'}));assert.equal(r.calls,2);assert.equal(r.failed,false);
});
test('audio hardened; control methods retain pooled behavior',async()=>{
  assert.deepEqual((await transportHarness('sendaudio')).flags,[true]);
  assert.deepEqual((await transportHarness('sendchataction')).flags,[false]);
  assert.deepEqual((await transportHarness('sendmessage')).flags,[true]);
});
test('negative control: unpatched installed send loses long text on audio failure',{skip:!stockDir && 'set OC_STOCK_DIST'},async()=>{
  const stock=fs.readFileSync(path.join(stockDir,SEND),'utf8');
  const h=mediaHarness({source:stock,failure:networkFailure()});
  await assert.rejects(h.run());assert.deepEqual(h.events,['voice','invalidate']);
});
test('negative control: unpatched transport replays ambiguous voice after socket reset',{skip:!stockDir && 'set OC_STOCK_DIST'},async()=>{
  const stock=fs.readFileSync(path.join(stockDir,FETCH),'utf8');
  const r=await transportHarness('sendvoice',networkFailure(),stock);
  assert.equal(r.calls,2);assert.equal(r.failed,false);assert.deepEqual(r.flags,[false,false]);
});
