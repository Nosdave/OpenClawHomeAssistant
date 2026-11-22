// Regression tests for the Telegram hotfix VOLT-TG-20261023 on OpenClaw 2026.11.4 (oc-patches/2026.11.4).
// Copy of telegram_hotfix_2026.11.3.test.mjs (removed with that patch set in 0.5.94-full6; itself a copy of the
// 2026.11.1 and 2026.10.10 ports, also removed, of the 2026.10.4 test written by Volt, exported 2026-10-25).
// Changes for 2026.11.4: the version and the chunk names; the notice code is read from its own chunk
// (src/channels/turn/pending-delivery-notice.ts moved out of the execution chunk, together with the new
// src/channels/turn/direct-delivery-active.ts), and the notice cases run with that real upstream guard
// (hasActiveDirectPendingFinalDelivery, commit cf9a023c222a in v2026.11.3..v2026.11.4); four cases are new: the
// upstream guard still defers, the add-on's live custody covers the gap from the upstream custody release to the
// canonical settlement, a negative control for that gap, and the queue recovery's own hand-over (the expectedIntentId
// that cf9a023c222a also added) is sent while the live custody is held. extensions/telegram/src/send-message.ts and fetch.ts are
// unchanged from 2026.11.3 (no commit in v2026.11.3..v2026.11.4 touches them); src/channels/turn/lifecycle.ts is
// unchanged too, its chunk also carries direct-delivery-custody.ts, which now tracks the live direct send.
// They exercise the patched function bodies with synthetic fake transports (no bot token, no gateway).
// Run in a container of the image built with OPENCLAW_VERSION=2026.11.4 (needs Node 24: the modules use
// `using` declarations):
//   node --test tests/oc_patches/telegram_hotfix_2026.11.4.test.mjs
// or against an unpacked package patched by oc_dist_patch.py whose runtime dependencies resolve:
//   OC_DIST=<copy>/dist OC_STOCK_DIST=<package>/dist node --test tests/oc_patches/telegram_hotfix_2026.11.4.test.mjs
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

const OPENCLAW_VERSION = '2026.11.4';
// Patched chunks (tests/test_dist_patch.py checks these names against oc-patches/2026.11.4/manifest.json).
const LIFECYCLE = 'lifecycle-BZUtlfJ8.mjs';
const NOTICE = 'pending-delivery-notice-C9L5X9zk.mjs';
const SEND = 'send-CvWi3zfv.mjs';
const FETCH = 'fetch-CbMOee_S.mjs';

// OC_DIST: the patched dist of the image (default: $(npm root -g)/openclaw/dist).
// OC_STOCK_DIST: a directory with the unpatched 2026.11.4 modules for the three negative controls
// (skipped when unset), e.g. package/dist of `npm pack openclaw@2026.11.4`.
const distDir = process.env.OC_DIST || path.join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'openclaw', 'dist');
const stockDir = process.env.OC_STOCK_DIST || '';
const pkgJson = path.join(distDir, '..', 'package.json');
if (fs.existsSync(pkgJson)) {
  const version = JSON.parse(fs.readFileSync(pkgJson, 'utf8')).version;
  assert.equal(version, OPENCLAW_VERSION, `these tests are for OpenClaw ${OPENCLAW_VERSION}; OC_DIST belongs to ${version}`);
}
const read = name => fs.readFileSync(path.join(distDir, name), 'utf8');
const life = read(LIFECYCLE);
const notice = read(NOTICE);
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
const guard = slice(notice,'function voltHasLiveDelivery','const PENDING_DELIVERY_NOTICE');
const noticeCode = slice(notice,'const PENDING_DELIVERY_NOTICE =','//#endregion');
// Upstream guard of 2026.11.4 (direct-delivery-active.ts): live from onPlatformSendDispatch to the custody release.
const upstreamActive = source => slice(source,'const activeDeliveries =','//#endregion');
const defer = () => { let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject}; };
const completion = {sessionId:'session',intentId:'intent'};

function liveHarness() {
  const scope=vm.createContext({Map,Set,Symbol,JSON,globalThis:{},resolvePendingFinalCompletion:p=>p.completion});
  vm.runInContext(registry+guard+upstreamActive(notice),scope);
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

test('upstream 2026.11.4 guard still defers the notice while the direct send is dispatched',async()=>{
  const s=liveHarness();const counter={notices:0};
  Object.assign(s,noticeStubs(owedEntry(),counter));
  vm.runInContext(noticeCode,s);
  const releaseUpstream=s.trackActiveDirectPendingFinalDelivery({...completion});
  await s.deliverPendingDeliveryNotice('synthetic','store');assert.equal(counter.notices,0);
  releaseUpstream();await s.deliverPendingDeliveryNotice('synthetic','store');assert.equal(counter.notices,1);
});
test('live custody covers the gap from the upstream custody release to the canonical settlement',async()=>{
  // 2026.11.4 releases its custody in deliverReply's finally (or when result.finalization settles); the canonical
  // settlement (settleChannelDeliveryAttempt) writes "delivered" only after that, for deferred finalization at the
  // end of the dispatch. The add-on's live custody is released only after that settlement.
  const tail=slice(life,'    async function voltDeliverReply(','\n\t\treturn result;\n\t}');
  const release=tail.indexOf('\t\t\telse releaseCustody?.();'), settle=tail.indexOf('else await settleChannelDeliveryAttempt(attempt, delivery.onDelivered);');
  assert(release>0 && settle>release,'2026.11.4 no longer releases its custody before the canonical settlement: re-check this patch');
  assert(tail.includes('if (releaseCustody && result?.finalization) result.finalization.then(releaseCustody, releaseCustody);'));
  const s=liveHarness();const counter={notices:0};
  Object.assign(s,noticeStubs(owedEntry(),counter));
  vm.runInContext(noticeCode,s);
  const releaseLive=s.voltAcquireDelivery(completion);
  s.trackActiveDirectPendingFinalDelivery({...completion})();
  await s.deliverPendingDeliveryNotice('synthetic','store');assert.equal(counter.notices,0);
  releaseLive();await s.deliverPendingDeliveryNotice('synthetic','store');assert.equal(counter.notices,1);
});
test('queue recovery hand-over (expectedIntentId) sends the notice once during the live delivery; other calls still defer',async()=>{
  // 2026.11.4 (cf9a023c222a): settleFailedQueuedDeliveryCompletion passes the intent once a queued pending final settles
  // "unknown" after exhausted retries. On Telegram that runs inside the live delivery (sendPayload durable, deliver-queue,
  // recoverLiveFinalDelivery, settleQueuedFailure), while the add-on's live custody for that intent is still held.
  const s=liveHarness();const counter={notices:0};const entry=owedEntry();
  Object.assign(s,noticeStubs(entry,counter));
  s.updateSessionEntry=async(_target,update)=>{const next=update(entry);if(next)Object.assign(entry,next);}; // the real updater
  vm.runInContext(noticeCode,s);
  const releaseLive=s.voltAcquireDelivery(completion);
  await s.deliverPendingDeliveryNotice('synthetic','store');assert.equal(counter.notices,0); // next-message path: deferred
  await s.deliverPendingDeliveryNotice('synthetic','store','other');assert.equal(counter.notices,0); // another intent's hand-over
  await s.deliverPendingDeliveryNotice('synthetic','store','intent');assert.equal(counter.notices,1); // the hand-over
  assert.equal(entry.pendingDeliveryNotice.state,'acknowledged');
  await s.deliverPendingDeliveryNotice('synthetic','store','intent');
  releaseLive();await s.deliverPendingDeliveryNotice('synthetic','store');assert.equal(counter.notices,1); // no second notice
});
test('negative control: unpatched 2026.11.4 notice is sent after the custody release, before the settlement',{skip:!stockDir && 'set OC_STOCK_DIST'},async()=>{
  const stock=fs.readFileSync(path.join(stockDir,NOTICE),'utf8');
  assert(!stock.includes('voltHasLiveDelivery'));
  const s=vm.createContext({Set,JSON});const counter={notices:0};
  Object.assign(s,noticeStubs(owedEntry(),counter));
  vm.runInContext(upstreamActive(stock)+slice(stock,'const PENDING_DELIVERY_NOTICE =','//#endregion'),s);
  s.trackActiveDirectPendingFinalDelivery({...completion})();
  await s.deliverPendingDeliveryNotice('synthetic','store');assert.equal(counter.notices,1);
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
    isRecoverableTelegramNetworkError:realNetworkError,findTelegramRequestAuthorityError:e=>e?.authority?e:null,
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
  // authority: a network-shaped failure (ECONNRESET) that carries a request-authority rejection (OpenClaw revoked
  // the send authority): it must reject, not be kept as delivered text.
  for(const options of [{failure:networkFailure(),signalAborted:true},{failure:Object.assign(networkFailure(),{authority:true})},
    {failure:new Error('permission failure')}]){
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
