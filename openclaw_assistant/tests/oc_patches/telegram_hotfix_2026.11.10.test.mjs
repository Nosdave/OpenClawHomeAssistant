// Regression tests for the Telegram hotfix TG-20261023 on OpenClaw 2026.11.10 (oc-patches/2026.11.10:
// telegram-voice-text-first, telegram-fetch-fresh-audio). Derived from telegram_hotfix_2026.11.4.test.mjs by way of
// the 2026.11.8 harness (that set was never shipped and is removed). What differs from 2026.11.4:
//  - the former parts telegram-delivery-live-custody and telegram-notice-live-guard are gone: OpenClaw fixes the
//    "couldn't confirm" notice for a reply that is still being sent itself (openclaw/openclaw#154417, commit
//    f6f7252001c1: the custody is released only after the canonical settlement, and pending-delivery-notice.ts checks
//    hasActiveDirectPendingFinalDelivery; e2a180733f7d, #195400, hands an owed notice to lifecycle delivery), so no
//    lifecycle or notice chunk is tested here.
//  - the dist is minified: function-local variables are single letters (module-level names, imports and named
//    function expressions keep their names). The vm contexts below therefore provide the minified outer names of
//    sendMessageTelegram (send chunk) and resolveTelegramTransport (fetch chunk); LOCALS lists them.
//  - each source module sits on one line after a '//!<source path>' marker line (no '//#region' lines, no
//    indentation, no final newline), and the static imports are all on line 1 as `import{...}from"./x.mjs";`. The
//    slice anchors below are minified code; each is checked to occur exactly once, so a re-packed chunk fails loudly
//    (oc_dist_patch.py also pins the stock sha256).
//  - sendChunkedText is E (on 2026.11.8 it was T, which is now the media parts inside sendMediaBatch). The other
//    names match 2026.11.8: text t, opts n, mediaUrls h, finalMediaBatch m, replyMarkup _, singleUseReplyTo v,
//    sender w, chatId l, cfg i, account a, ownerAgentId s, api o; resolvedFetch reads closed x, sourceFetch u,
//    stickyAttemptIndex _, transportAttempts g, primaryProbeDue y.
//  - the send chunk does not bundle send-context.ts; the patch imports findTelegramRequestAuthorityError from the
//    fetch chunk (export letter o), checked below like the other imports.
//  - sendMediaBatch reads pendingMessageEffectParams (Telegram message effects, c1be284382d / #191646: an effect
//    goes on the first message Telegram accepts); the harness provides it and checks that with text-first the effect
//    and the inline keyboard go with the text, not with the voice.
// Run in a container of the image built with OPENCLAW_VERSION=2026.11.10:
//   node --test tests/oc_patches/telegram_hotfix_2026.11.10.test.mjs
// or against an unpacked package patched by oc_dist_patch.py whose runtime dependencies resolve:
//   OC_DIST=<copy>/dist OC_STOCK_DIST=<package>/dist node --test tests/oc_patches/telegram_hotfix_2026.11.10.test.mjs
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const OPENCLAW_VERSION = '2026.11.10';
// Patched chunks (tests/test_dist_patch.py checks these names against oc-patches/2026.11.10/manifest.json).
const SEND = 'send-BcsDv8XI.mjs';
const FETCH = 'fetch-CpqTTyCO.mjs';
// Minified outer locals the sliced code reads (send: sendMessageTelegram; fetch: resolveTelegramTransport).
const LOCALS = {
  send: { text: 't', opts: 'n', mediaUrls: 'h', finalMediaBatch: 'm', replyMarkup: '_', singleUseReplyTo: 'v',
    sender: 'w', chatId: 'l', cfg: 'i', account: 'a', ownerAgentId: 's', api: 'o', sendChunkedText: 'E' },
  fetch: { closed: 'x', sourceFetch: 'u', stickyAttemptIndex: '_', transportAttempts: 'g', primaryProbeDue: 'y' },
};

const distDir = process.env.OC_DIST || path.join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'openclaw', 'dist');
const stockDir = process.env.OC_STOCK_DIST || '';
const pkgJson = path.join(distDir, '..', 'package.json');
if (fs.existsSync(pkgJson)) {
  const version = JSON.parse(fs.readFileSync(pkgJson, 'utf8')).version;
  assert.equal(version, OPENCLAW_VERSION, `these tests are for OpenClaw ${OPENCLAW_VERSION}; OC_DIST belongs to ${version}`);
}
const read = name => fs.readFileSync(path.join(distDir, name), 'utf8');
const send = read(SEND);
const fetchSource = read(FETCH);
// minified static imports, all on the chunk's first line: import{a as b,c as d}from"./x-HASH.mjs";
const importOf = (source, local) => {
  for (const m of source.split('\n', 1)[0].matchAll(/import\{([^}]*)\}from"\.\/([^"]+)";/g)) {
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
const sliceOnce = (s, a, b) => {
  const start = s.indexOf(a); assert(start >= 0 && s.indexOf(a, start + 1) < 0, `not exactly once: ${a}`);
  const end = s.indexOf(b, start + a.length); assert(end >= 0, b); return s.slice(start, end);
};
const named = (map, values) => Object.fromEntries(Object.entries(values).map(([k, v]) => [map[k] ?? assert.fail(`no local for ${k}`), v]));

// sendMediaBatch is one statement of the one-line send-message module; the slice ends with its ';'.
const mediaStart = 'const sendMediaBatch=async e=>{', mediaEnd = 'if(h.length>0){';
// The destructuring the patch edits, with the minified names LOCALS relies on (fails if the build renames them).
const mediaShape = 'const r=e[0];const{media:c,mediaPlan:u,mediaSender:d,documentSender:f}=r;const p=r.index===0?_:void 0;m=r.index+e.length===h.length;';
const EFFECT = { message_effect_id: 'synthetic-effect' };
const KEYBOARD = { inline_keyboard: [[{ text: 'synthetic', callback_data: 'x' }]] };
function mediaHarness({ long = true, voice = true, failure, signalAborted = false, textFailure, replyMarkup, source = send } = {}) {
  const events = [], parts = [], mediaRequests = []; let id = 100;
  const media = { result: { message_id: 200, chat: { id: 'synthetic' } }, messageId: 200, acceptedParams: {}, plainText: '', hasInlineKeyboard: false, sender: { operation: voice ? 'sendVoice' : 'sendAudio', label: voice ? 'voice' : 'audio' } };
  const scope = vm.createContext({
    ...named(LOCALS.send, {
      finalMediaBatch: true, mediaUrls: ['synthetic-audio'], replyMarkup, singleUseReplyTo: true,
      text: 'x'.repeat(long ? 1500 : 100), chatId: 'synthetic', cfg: {}, ownerAgentId: 'test', account: { accountId: 'synthetic' },
      opts: { signal: { aborted: signalAborted }, promptContextProjectionPlan: { cursor: { invalidate: () => events.push('invalidate') } } },
      api: {},
      sendChunkedText: async () => { events.push('text'); if (textFailure) throw textFailure; parts.push({ messageId: ++id, result: { message_id: id, chat: { id: 'synthetic' } } }); return { messageId: String(id), chatId: 'synthetic', receipt: realReceipt({ results: [{ messageId: String(id), chatId: 'synthetic' }], kind: 'text' }) }; },
      sender: { parts, sendMedia: async ({ requestParams }) => { events.push('voice'); mediaRequests.push(requestParams); if (failure) throw failure; return media; }, acceptMany: async (ps, observe) => { parts.push(...ps); for (const p of ps) await observe(p); } },
    }),
    // send-message.ts: one effect per delivery, only until Telegram accepts the first message
    pendingMessageEffectParams: () => (parts.length === 0 ? EFFECT : undefined),
    buildThreadParams: include => ({ reply: include }), probeVideoDimensions: async () => undefined,
    isTelegramPhotoLimitError: () => false, isTelegramVoiceMessagesForbiddenError: e => e.forbidden === true,
    isRecoverableTelegramNetworkError: realNetworkError, findTelegramRequestAuthorityError: e => e?.authority ? e : null,
    sendLogger: { warn: () => events.push('audio-warning') }, logVerbose: () => {},
    resolveAcceptedReplyToMessageId: p => p?.reply ? 99 : undefined, toAcceptedThreadScopedParams: x => x,
    recordDeliveredPromptContext: async () => {}, recordSentMessage: async () => {},
    reportDelivery: async ({ messageId, fallbackChatId, meta, kind, onPrepared }) => onPrepared?.({ messageId: String(messageId), chatId: fallbackChatId, meta, receipt: realReceipt({ results: [{ messageId: String(messageId), chatId: fallbackChatId }], kind }) }),
    telegramCaptionDeliveryMetadata: new WeakSet(), recordActivity: () => {},
    resolveTelegramMessageIdOrThrow: r => r.message_id, buildMediaReceipt: () => ({ parts: [] }),
    createMessageReceiptFromOutboundResults: realReceipt,
    // read only when the follow-up text fails in the stock order (media first); no test takes that path, so a test
    // that does fails here by name instead of with a ReferenceError
    ...Object.fromEntries(['isChannelPartialDeliveryError', 'isTelegramEmptyContentError', 'createChannelPartialDeliveryError']
      .map(name => [name, () => { throw new Error(`harness: ${name} is not provided`); }])),
  });
  const code = sliceOnce(source, mediaStart, mediaEnd);
  assert(code.includes(mediaShape), `${SEND}: sendMediaBatch no longer has the expected minified names`);
  vm.runInContext(code + '\nglobalThis.run = sendMediaBatch;', scope);
  const plan = { htmlCaption: long ? undefined : 'short', plainCaption: long ? undefined : 'short', followUpText: long ? 'x'.repeat(1500) : undefined, deliveryKind: 'audio' };
  const batch = [{ index: 0, media: { buffer: new Uint8Array() }, mediaPlan: plan, mediaSender: { label: voice ? 'voice' : 'audio', operation: voice ? 'sendVoice' : 'sendAudio' } }];
  return { scope, events, mediaRequests, run: () => scope.run(batch) };
}
const networkFailure = () => Object.assign(new Error('socket reset'), { code: 'ECONNRESET' });
// A test, not a load-time check, so that a stock dist (OC_DIST=<stock>/dist) fails case by case.
test('the patch imports findTelegramRequestAuthorityError from the fetch chunk (that function, not another export)', async () => {
  const authority = importOf(send, 'findTelegramRequestAuthorityError'); // added by the patch
  assert.equal(authority.file, FETCH);
  assert.equal((await load(authority)).name, 'findTelegramRequestAuthorityError');
});
test('long voice sends text first and receipt retains both posts', async () => {
  const h = mediaHarness(); const r = await h.run(); assert.deepEqual(h.events, ['text', 'voice']);
  assert.equal(r.receipt.parts.length, 2); assert.equal(r.receipt.parts[0].kind, 'text'); assert.equal(r.receipt.parts[1].kind, 'media');
});
test('text-first: the message effect and the inline keyboard stay with the text; the voice carries neither', async () => {
  const h = mediaHarness({ replyMarkup: KEYBOARD }); await h.run(); assert.deepEqual(h.events, ['text', 'voice']);
  assert.equal(h.mediaRequests[0].message_effect_id, undefined); assert.equal(h.mediaRequests[0].reply_markup, undefined);
  const short = mediaHarness({ long: false, replyMarkup: KEYBOARD }); await short.run(); // stock caption path
  assert.equal(short.mediaRequests[0].message_effect_id, EFFECT.message_effect_id); assert.deepEqual(short.mediaRequests[0].reply_markup, KEYBOARD);
});
test('network failure after confirmed text keeps text; no second text or audio retry', async () => {
  const h = mediaHarness({ failure: networkFailure() }); const r = await h.run(); assert.equal(r.messageId, '101');
  assert.deepEqual(h.events, ['text', 'voice', 'invalidate', 'audio-warning']);
});
test('voice-privacy rejection after confirmed text keeps text without a second text', async () => {
  const h = mediaHarness({ failure: Object.assign(new Error('VOICE_MESSAGES_FORBIDDEN'), { forbidden: true }) }); const r = await h.run();
  assert.equal(r.messageId, '101'); assert.deepEqual(h.events, ['text', 'voice', 'invalidate', 'audio-warning']);
});
test('short voice keeps caption path unchanged', async () => {
  const h = mediaHarness({ long: false }); await h.run(); assert.deepEqual(h.events, ['voice']);
});
test('short voice network failure remains ambiguous, not silently accepted', async () => {
  const h = mediaHarness({ long: false, failure: networkFailure() }); await assert.rejects(h.run()); assert.deepEqual(h.events, ['voice', 'invalidate']);
});
test('long audio (not voice) keeps the stock order: media first, text follow-up', async () => {
  const h = mediaHarness({ voice: false }); await h.run(); assert.deepEqual(h.events, ['voice', 'text']); // sendMedia logs 'voice' for any label
});
test('text rejection stops before optional voice; no hidden partial text replay', async () => {
  const h = mediaHarness({ textFailure: new Error('text failed') }); await assert.rejects(h.run(), /text failed/); assert.deepEqual(h.events, ['text']);
});
test('cancellation/authority and non-network failures are never swallowed', async () => {
  for (const options of [{ failure: networkFailure(), signalAborted: true }, { failure: Object.assign(networkFailure(), { authority: true }) },
    { failure: new Error('permission failure') }]) {
    const h = mediaHarness(options); await assert.rejects(h.run()); assert(!h.events.includes('audio-warning'));
  }
});

// resolvedFetch is one statement of the one-line fetch module; the slice ends with its ';'.
const transportStart = 'const resolvedFetch=(async(e,t)=>{', transportEnd = 'return{fetch:resolvedFetch,';
async function transportHarness(method, error, source = fetchSource) {
  const flags = []; let calls = 0;
  const scope = vm.createContext({
    ...named(LOCALS.fetch, {
      closed: false, stickyAttemptIndex: 0, primaryProbeDue: false,
      sourceFetch: async () => { calls++; if (calls === 1 && error) throw error; return new Response('{}'); },
      transportAttempts: [0, 1].map(() => ({ exportAttempt: {}, createDispatcher: f => { flags.push(f); return {}; } })),
    }),
    Request, extractTelegramApiMethod: () => method,
    shouldRetryTelegramTransportFallback: () => true, isSafeToRetrySendError: realSafeRetry,
    bindTelegramTransportAuthority: source => source, getTelegramRequestAuthority: () => null,
    getAttemptCooldownError: () => null,
    expectDefined: x => x, promoteStickyAttempt: () => {}, recordAttemptFailure: () => {}, recordSuccessfulAttempt: () => {}, describeProxyTunnelFailure: () => null,
    captureHttpExchangeAsync: async () => {}, resolveRequestUrl: () => 'https://synthetic.invalid', randomUUID: () => 'synthetic',
    TelegramRequestNotStartedError: Error,
  });
  vm.runInContext(sliceOnce(source, transportStart, transportEnd) + '\nglobalThis.run=resolvedFetch;', scope);
  let failed = false; try { await scope.run('https://synthetic.invalid', {}); } catch { failed = true; }
  return { calls, flags, failed };
}
test('voice reset after possible acceptance is not replayed; fresh connection requested', async () => {
  const r = await transportHarness('sendvoice', networkFailure()); assert.equal(r.calls, 1); assert.equal(r.failed, true); assert.deepEqual(r.flags, [true]);
});
test('proven pre-connect voice failure permits bounded fallback', async () => {
  const r = await transportHarness('sendvoice', Object.assign(new Error('connect refused'), { code: 'ECONNREFUSED' })); assert.equal(r.calls, 2); assert.equal(r.failed, false);
});
test('audio hardened; control methods retain pooled behavior', async () => {
  assert.deepEqual((await transportHarness('sendaudio')).flags, [true]);
  assert.deepEqual((await transportHarness('sendchataction')).flags, [false]);
  assert.deepEqual((await transportHarness('sendmessage')).flags, [true]);
});
test('negative control: unpatched installed send loses long text on audio failure', { skip: !stockDir && 'set OC_STOCK_DIST' }, async () => {
  const stock = fs.readFileSync(path.join(stockDir, SEND), 'utf8');
  const h = mediaHarness({ source: stock, failure: networkFailure() });
  await assert.rejects(h.run()); assert.deepEqual(h.events, ['voice', 'invalidate']);
});
test('negative control: unpatched transport replays ambiguous voice after socket reset', { skip: !stockDir && 'set OC_STOCK_DIST' }, async () => {
  const stock = fs.readFileSync(path.join(stockDir, FETCH), 'utf8');
  const r = await transportHarness('sendvoice', networkFailure(), stock);
  assert.equal(r.calls, 2); assert.equal(r.failed, false); assert.deepEqual(r.flags, [false, false]);
});
