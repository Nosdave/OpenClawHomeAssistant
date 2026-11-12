// Regression tests for the Telegram hotfix VOLT-TG-20261112 (patch telegram-reply-self-audio in
// oc-patches/<OpenClaw version>/): when the user replies to (or quotes) one of the bot's own messages, the bot's
// voice or audio no longer becomes the user's turn media; the bot's other media (images, documents, stickers,
// video), every other sender's media and the reply text stay as in stock OpenClaw.
// They run the real statements of the installed bot-message chunk (buildTelegramInboundContextPayload, from
// `const replyHead =` up to `const telegramFrom =`, plus the chunk's own media-kind helpers) in a vm with synthetic
// reply chains (no bot token, no network, no gateway). No runtime dependencies; Node 22 or 24.
// In a container of the image (the version is read from the package):
//   node --test tests/oc_patches/telegram_reply_self_audio.test.mjs
// or against an unpacked package (2026.10.4, 2026.10.10, 2026.11.1 or 2026.11.3) patched by oc_dist_patch.py:
//   OC_DIST=<copy>/dist node --test tests/oc_patches/telegram_reply_self_audio.test.mjs
// Negative control: OC_DIST=<stock package>/dist makes the bot-audio cases fail (stock merges the bot's audio).
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

// Patched chunk per OpenClaw version (tests/test_dist_patch.py checks these names against the manifests).
const CHUNKS = {
  '2026.10.4': 'bot-message-CpKgMHf_.mjs',
  '2026.10.10': 'bot-message-B569oFnK.mjs',
  '2026.11.1': 'bot-message-D8YOSV-y.mjs',
  '2026.11.3': 'bot-message-zuOD8Xt7.mjs',
};

// OC_DIST: the dist to test (default: the image's $(npm root -g)/openclaw/dist).
const distDir = process.env.OC_DIST || path.join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'openclaw', 'dist');
const version = JSON.parse(fs.readFileSync(path.join(distDir, '..', 'package.json'), 'utf8')).version;
assert.ok(CHUNKS[version], `no telegram-reply-self-audio chunk known for OpenClaw ${version}`);
const chunk = fs.readFileSync(path.join(distDir, CHUNKS[version]), 'utf8');

const once = (from, to) => {
  const start = chunk.indexOf(from);
  assert.ok(start >= 0 && chunk.indexOf(from, start + 1) < 0, `${from.trim()} is not in ${CHUNKS[version]} exactly once`);
  const end = chunk.indexOf(to, start + from.length);
  assert.ok(end > start, `${to.trim()} does not follow ${from.trim()}`);
  return chunk.slice(start, end);
};
// TELEGRAM_MEDIA_KINDS with isTelegramMediaKind (2026.10.4) or resolveReplyChainMediaType (2026.10.10 and later)
const helpers = once('const TELEGRAM_MEDIA_KINDS = ', 'async function buildTelegramInboundContextPayload(');
// replyHead, toInboundMedia, currentMediaFacts, toReplyChainMediaFact, (patch,) replyMediaFacts, replyTargetMedia, replyBody
const statements = once('\tconst replyHead = visibleReplyChain[0];\n', '\tconst telegramFrom = ');
const script = new vm.Script(`${helpers}\n${statements}\nglobalThis.result = { media: replyMediaFacts, replyBody };`);

const BOT_ID = 7000001; // ctx.me.id is a number; reply-chain sender ids are strings
function build(opts) {
  const { chain = [], target, replyMedia = [] } = opts;
  // primaryCtx / me may be passed as undefined on purpose (no default then)
  const primaryCtx = 'primaryCtx' in opts ? opts.primaryCtx : { me: 'me' in opts ? opts.me : { id: BOT_ID } };
  const context = vm.createContext({
    primaryCtx, visibleReplyChain: chain, visibleReplyTarget: target, replyMedia, allMedia: [],
    audioTranscribedMediaIndex: undefined,
    formatMediaPlaceholderText: (media) => media.map((m) => `<media:${m.kind ?? m.contentType}>`).join(' '),
  });
  script.runInContext(context);
  return JSON.parse(JSON.stringify(context.result));
}
const paths = (r) => r.media.map((m) => m.path ?? `(no file: ${m.kind ?? m.contentType})`);

// Reply-chain entries as the Telegram runtime builds them (toReplyChainEntry: a downloaded file sets mediaPath,
// mediaKind = the saved kind, mediaType = its content type; a message that was not downloaded keeps its Telegram
// kind in mediaType). Sender "Volt (you)" with the bot's id = the bot's own messages.
const bot = (id, extra) => ({ messageId: id, sender: 'Volt (you)', senderId: String(BOT_ID), ...extra });
const david = (id, extra) => ({ messageId: id, sender: 'David', senderId: '4242', ...extra });
const BOT_VOICE = bot('502', { mediaPath: '/m/bot-voice.ogg', mediaKind: 'audio', mediaType: 'audio/ogg' });
const BOT_VOICE_NOT_DOWNLOADED = bot('503', { mediaType: 'audio', mediaRef: 'telegram:file/BOT_VOICE' });
const BOT_AUDIO_FILE = bot('504', { mediaPath: '/m/bot-song.mp3', mediaKind: 'audio', mediaType: 'audio/mpeg' });
const BOT_AUDIO_TYPE_ONLY = bot('505', { mediaPath: '/m/bot-x.oga', mediaType: 'Audio/OGG; codecs=opus' });
const BOT_IMAGE = bot('510', { mediaPath: '/m/bot.jpg', mediaKind: 'image', mediaType: 'image/jpeg' });
const BOT_DOCUMENT = bot('511', { mediaPath: '/m/bot.pdf', mediaKind: 'document', mediaType: 'application/pdf' });
const BOT_STICKER = bot('512', { mediaPath: '/m/bot.webp', mediaKind: 'sticker', mediaType: 'image/webp' });
const BOT_VIDEO = bot('513', { mediaPath: '/m/bot.mp4', mediaKind: 'video', mediaType: 'video/mp4' });
const BOT_IMAGE_NOT_DOWNLOADED = bot('514', { mediaType: 'image', mediaRef: 'telegram:file/BOT_IMAGE' });
const DAVID_VOICE = david('300', { mediaPath: '/m/david-voice.ogg', mediaKind: 'audio', mediaType: 'audio/ogg' });
const DAVID_IMAGE = david('301', { mediaPath: '/m/david.jpg', mediaKind: 'image', mediaType: 'image/jpeg' });

test(`${version}: the bot's own voice in the reply chain is not the user's media; the reply still names it`, () => {
  const r = build({ chain: [BOT_VOICE] });
  assert.deepEqual(r.media, []);
  assert.equal(r.replyBody, '<media:audio>'); // the quote text (and the reply chain) still show the bot's voice
  assert.deepEqual(build({ chain: [BOT_VOICE_NOT_DOWNLOADED] }).media, []);
});

test(`${version}: the bot's audio files count as audio too (kind audio, or an audio content type)`, () => {
  assert.deepEqual(build({ chain: [BOT_AUDIO_FILE] }).media, []);
  assert.deepEqual(build({ chain: [BOT_AUDIO_TYPE_ONLY] }).media, []);
});

test(`${version}: the bot's images, documents, stickers and video stay quote media as in stock`, () => {
  const r = build({ chain: [BOT_IMAGE, BOT_DOCUMENT, BOT_STICKER, BOT_VIDEO, BOT_IMAGE_NOT_DOWNLOADED] });
  assert.deepEqual(r.media.map((m) => [m.path, m.kind, m.contentType]), [
    ['/m/bot.jpg', 'image', 'image/jpeg'],
    ['/m/bot.pdf', 'document', 'application/pdf'],
    ['/m/bot.webp', 'sticker', 'image/webp'],
    ['/m/bot.mp4', 'video', 'video/mp4'],
    [undefined, 'image', undefined],
  ]);
});

test(`${version}: the user's own voice stays the user's; a mixed chain loses only the bot's audio`, () => {
  assert.deepEqual(build({ chain: [DAVID_VOICE] }).media, [
    { path: '/m/david-voice.ogg', url: '/m/david-voice.ogg', kind: 'audio', contentType: 'audio/ogg' },
  ]);
  const mixed = build({ chain: [BOT_VOICE, DAVID_VOICE, BOT_IMAGE, BOT_AUDIO_FILE] });
  assert.deepEqual(paths(mixed), ['/m/david-voice.ogg', '/m/bot.jpg']);
  assert.equal(mixed.replyBody, '<media:audio>'); // the quote still shows the bot's voice at the head of the chain
});

test(`${version}: reply target without a visible chain - the same rule`, () => {
  const botTarget = { id: '502', sender: 'Volt (you)', senderId: String(BOT_ID), mediaType: 'audio' };
  assert.deepEqual(build({ target: botTarget, replyMedia: [{ path: '/m/bot-voice.ogg', kind: 'audio', contentType: 'audio/ogg' }] }).media, []);
  assert.deepEqual(build({ target: botTarget }).media, []);
  const botPhoto = { ...botTarget, id: '510', mediaType: 'image' };
  assert.deepEqual(paths(build({ target: botPhoto, replyMedia: [{ path: '/m/bot.jpg', kind: 'image', contentType: 'image/jpeg' }] })), ['/m/bot.jpg']);
  assert.deepEqual(paths(build({ target: botPhoto })), ['(no file: image)']);
  const davidTarget = { id: '300', sender: 'David', senderId: '4242', mediaType: 'audio' };
  assert.deepEqual(paths(build({ target: davidTarget, replyMedia: [{ path: '/m/david-voice.ogg', kind: 'audio', contentType: 'audio/ogg' }] })), ['/m/david-voice.ogg']);
});

test(`${version}: without the bot's id on the update nothing is dropped (stock behaviour), no exception`, () => {
  for (const ctx of [{ me: null }, { me: undefined }, { primaryCtx: {} }, { primaryCtx: undefined }, { me: {} }]) {
    assert.deepEqual(paths(build({ ...ctx, chain: [BOT_VOICE, DAVID_VOICE] })), ['/m/bot-voice.ogg', '/m/david-voice.ogg'], JSON.stringify(ctx));
  }
});

test(`${version}: replies that involve no bot message are unchanged`, () => {
  assert.deepEqual(build({ chain: [DAVID_VOICE, DAVID_IMAGE] }).media, [
    { path: '/m/david-voice.ogg', url: '/m/david-voice.ogg', kind: 'audio', contentType: 'audio/ogg' },
    { path: '/m/david.jpg', url: '/m/david.jpg', kind: 'image', contentType: 'image/jpeg' },
  ]);
  assert.deepEqual(build({}).media, []);
  // another bot's voice (a different sender id) is not this bot's own
  assert.deepEqual(paths(build({ chain: [{ ...BOT_VOICE, sender: 'Other bot', senderId: '7000002' }] })), ['/m/bot-voice.ogg']);
});
