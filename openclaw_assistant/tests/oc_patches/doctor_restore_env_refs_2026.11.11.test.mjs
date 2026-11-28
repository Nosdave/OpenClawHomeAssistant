// Regression tests for the add-on patch doctor-restore-env-refs-deferral on OpenClaw 2026.11.11
// (oc-patches/2026.11.11, openclaw/openclaw#205695). planConfigRepair prepares the plugins' configRepair contracts,
// migrates and validates inside withPluginContracts (the deferral set of the config snapshot); stock 2026.11.11
// restores the ${VAR} templates (restoreDoctorConfigEnvRefs) outside it, under the doctor-wide set. After doctor's
// codex refresh the two differ (snapshot [codex], doctor-wide []), so the restore loads codex's unprepared contract and
// doctor fails with "Plugin codex Doctor source must be prepared before loading". The patch runs the restore in the
// same scope.
// The tests slice the real planConfigRepair from the one-line minified module after the marker line
// '//!src/commands/doctor/shared/automatic-config-repair.ts' and run it in a vm with synthetic stubs for its imports
// (no doctor, no plugins, no config files, no network). The deferral scope is simulated like OpenClaw's
// AsyncLocalStorage: withDeferredPluginDoctorMigrations(ids, fn) replaces the active set while fn runs. The stub
// restore records the active set and throws OpenClaw's error when codex is not deferred (its contract unprepared).
// Node 22 or 24. In a container of the image built with OPENCLAW_VERSION=2026.11.11:
//   node --test tests/oc_patches/doctor_restore_env_refs_2026.11.11.test.mjs
// or against an unpacked package patched by oc_dist_patch.py:
//   OC_DIST=<package>/dist node --test tests/oc_patches/doctor_restore_env_refs_2026.11.11.test.mjs
// Against the stock package the first test fails (the restore throws); the negative control rebuilds the stock
// statement from the patched one and expects the throw.
import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import path from 'node:path';
import util from 'node:util';
import { execFileSync } from 'node:child_process';

const OPENCLAW_VERSION = '2026.11.11';
const CHUNK = 'automatic-config-repair-DirHmWYF.mjs';
const PATCHED = 'const d=t?withPluginContracts(()=>restoreDoctorConfigEnvRefs(u,prepareDoctorConfigReferenceSource(e))):u;';
const STOCK = 'const d=t?restoreDoctorConfigEnvRefs(u,prepareDoctorConfigReferenceSource(e)):u;';
const ERROR = 'Plugin codex Doctor source must be prepared before loading';

const distDir = process.env.OC_DIST || path.join(execFileSync('npm', ['root', '-g'], { encoding: 'utf8' }).trim(), 'openclaw', 'dist');
const version = JSON.parse(fs.readFileSync(path.join(distDir, '..', 'package.json'), 'utf8')).version;
assert.equal(version, OPENCLAW_VERSION, `these tests are for OpenClaw ${OPENCLAW_VERSION}; OC_DIST belongs to ${version}`);
const chunk = fs.readFileSync(path.join(distDir, CHUNK), 'utf8');
assert.ok(chunk.split('\n').includes('//!src/commands/doctor/shared/automatic-config-repair.ts'),
  `${CHUNK} does not hold src/commands/doctor/shared/automatic-config-repair.ts`);
const once = (from, to) => {
  const start = chunk.indexOf(from);
  assert.ok(start >= 0 && chunk.indexOf(from, start + 1) < 0, `${from.trim()} is not in ${CHUNK} exactly once`);
  const end = chunk.indexOf(to, start + from.length);
  assert.ok(end > start, `${to.trim()} does not follow ${from.trim()}`);
  return chunk.slice(start, end);
};
const plan = once('async function planConfigRepair(', 'async function planAutomaticConfigRepair(');

// A world of synthetic stubs. `outer` is the doctor-wide deferral set when planConfigRepair starts (after the codex
// refresh: []); `snapshotSet` is what the snapshot's deferral facts name (null: none).
function world(source, { outer = [], snapshotSet = ['codex'] } = {}) {
  let active = [...outer];
  const seen = { prepare: [], restore: [], validate: [] };
  const sourceConfig = { agents: { defaults: { heartbeat: { every: '30m' } } }, plugins: { entries: { codex: { enabled: true } } } };
  const context = vm.createContext({
    canPlanAutomaticConfigRepair: () => true,
    getDeferredPluginMigrationConfigFacts: (cfg) => (cfg === sourceConfig && snapshotSet
      ? snapshotSet.map((pluginId) => ({ pluginId })) : undefined),
    withDeferredPluginDoctorMigrations: (ids, fn) => {
      const prev = active;
      active = [...ids];
      let r;
      try { r = fn(); } catch (err) { active = prev; throw err; }
      if (r && typeof r.then === 'function') return r.finally(() => { active = prev; });
      active = prev;
      return r;
    },
    preparePluginDoctorContractModules: async () => { seen.prepare.push([...active]); },
    applyLegacyDoctorMigrations: (cfg) => {
      const next = structuredClone(cfg);
      delete next.agents.defaults.heartbeat;
      return { next, changes: ['Moved agents.defaults.heartbeat to the heartbeat jobs.'], warnings: [] };
    },
    preserveDeferredPluginMigrationConfig: ({ nextConfig }) => nextConfig,
    inheritLegacyDefaultAgentId: (_next, cfg) => cfg,
    tryProjectRetiredHeartbeatConfig: (cfg) => cfg,
    isDeepStrictEqual: util.isDeepStrictEqual,
    copyConfigResolutionFactsThroughRewrite: () => {},
    prepareDoctorConfigReferenceSource: (snap) => ({ authored: snap.parsed }),
    restoreDoctorConfigEnvRefs: (cfg) => {
      seen.restore.push([...active]);
      // codex (from 2026.11.10) declares doctorContract.configRepair: loading it unprepared throws
      // PluginSetupPreparationRequiredError (plugin-setup-module.ts) unless the scope defers codex
      if (!active.includes('codex')) throw new Error(ERROR);
      return { ...cfg, restoredTemplates: true };
    },
    omitDeferredPluginMigrationConfig: (cfg) => cfg,
    prepareAutomaticConfigRepairWrite: async (_snap, cfg) => cfg,
    validateConfigObjectWithPlugins: (cfg) => { seen.validate.push([...active]); return { ok: true, config: cfg, warnings: [] }; },
    validateConfigObjectRaw: (cfg) => ({ ok: true, config: cfg, issues: [] }),
    findDoctorLegacyConfigIssues: () => [],
    findLegacyConfigIssues: () => [],
    createConfigValidationFailedError: () => new Error('config validation failed'),
    dedupeByKey: (items) => items,
    setDeferredPluginMigrationConfigFacts: () => {},
  });
  vm.runInContext(`${source}\nglobalThis.plan = planConfigRepair;`, context);
  const snapshot = { exists: true, raw: '{}', parsed: { authored: true }, sourceConfig, valid: false, warnings: [] };
  return { run: (opts = { pluginContracts: true }) => context.plan(snapshot, opts), seen };
}

test(`${version}: the patched statement is in the module exactly once and the stock one is gone`, () => {
  assert.equal(plan.split(PATCHED).length, 2);
  assert.equal(plan.includes(STOCK), false);
  assert.match(plan, /const withPluginContracts=e=>a\?withDeferredPluginDoctorMigrations\(a\.map\(e=>e\.pluginId\),e\):e\(\);/);
});

test(`${version}: after the codex refresh the restore runs in the snapshot's deferral set and the repair is planned`, async () => {
  const w = world(plan);
  const r = await w.run();
  assert.deepEqual(w.seen.prepare, [['codex']]);
  assert.deepEqual(w.seen.restore, [['codex']]);
  assert.deepEqual(w.seen.validate, [['codex']]);
  assert.equal(r.writeConfig.restoredTemplates, true); // the restore's result, not a promise
  assert.equal(typeof r.writeConfig.then, 'undefined');
  assert.equal(r.config.agents.defaults.heartbeat, undefined);
  assert.deepEqual([...r.changes], ['Moved agents.defaults.heartbeat to the heartbeat jobs.']);
});

test(`${version}: negative control, the stock statement throws the doctor error of openclaw/openclaw#205695`, async () => {
  const w = world(plan.replace(PATCHED, STOCK));
  await assert.rejects(w.run(), (err) => err.message === ERROR);
  assert.deepEqual(w.seen.prepare, [['codex']]);
  assert.deepEqual(w.seen.restore, [[]]); // the doctor-wide set, which no longer defers codex
});

test(`${version}: the restore always uses the set preparation and validation use`, async () => {
  // no deferral facts: withPluginContracts calls through, the doctor-wide set stays (the patch changes nothing)
  let w = world(plan, { outer: ['acpx', 'codex'], snapshotSet: null });
  await w.run();
  assert.deepEqual([w.seen.prepare, w.seen.restore, w.seen.validate], [[['acpx', 'codex']], [['acpx', 'codex']], [['acpx', 'codex']]]);
  // both sets name codex (the first config read of the run): as in stock
  w = world(plan, { outer: ['codex'] });
  await w.run();
  assert.deepEqual(w.seen.restore, [['codex']]);
  // without plugin contracts there is no restore at all
  w = world(plan);
  const r = await w.run({ pluginContracts: false });
  assert.deepEqual([w.seen.prepare, w.seen.restore], [[], []]);
  assert.equal(r.writeConfig.restoredTemplates, undefined);
});
