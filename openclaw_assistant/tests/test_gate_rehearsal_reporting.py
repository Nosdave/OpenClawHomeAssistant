"""Reporting fixes from the host rehearsal (2026.10.4 state, gate on the patched 2026.10.10; facts re-checked on
OpenClaw 2026.11.1). Synthetic fixtures only.

- D3: PROPOSALS.md names a proposal by target.skillName (what 2026.10.4 stores), else its title.
- D6: a store registered for an agent openclaw.json does not configure gets a precheck info line; the cron
  inference-account report leaves out the jobs of such an agent (OpenClaw cancels them: "cron job agent is
  unavailable", the gateway's isAgentAvailable) and lists them in an info line.
- D8: OpenClaw's install work directories (.openclaw-install-stage-*, -rollback-*, .openclaw-install-backups;
  install-package-dir.ts) are no plugins: never "doctor installed new plugin package(s)"; reported as leftovers.
- D10: run_process also stops a descendant that left the child's session (OpenClaw starts npm detached).
- D11: what doctor did with a recorded orphan store (migrated / set aside as <file>.corrupt-<ms> / gone) is in the
  finalize output, the journal, the marker and `oc-upgrade status`; status lists every *.corrupt-* database copy.
  The add-on never deletes them.
- D12: the no-network reason says what accepting costs.
- tmp/plugin-captures: reported in status with its own size; never deleted by the add-on.
"""

import json
import os
import shutil
import signal
import sys
import tempfile
import textwrap
import time
import unittest
from datetime import timedelta
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
for _p in (str(ADDON), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_common as C  # noqa: E402
import oc_gate as G  # noqa: E402
import test_gate as T  # noqa: E402
import test_gate_cron_binding as CB  # noqa: E402

AGENT = "agents/{}/agent/openclaw-agent.sqlite"
CFG = {"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local"},
       "agents": {"defaults": {"model": {"primary": "vllm/qwen3.5-122b", "fallbacks": ["openai/gpt-5.5"]}},
                  "list": [{"id": "main", "default": True}]},
       "models": {"providers": {"vllm": {"baseUrl": "http://127.0.0.1:8000/v1"}}}}


class Bump1010(T.GateEnv):
    """A 2026.10.4 state (20/24) under the 2026.10.10 runtime (22/27)."""
    AGENTS = ("main",)

    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state, agents=self.AGENTS, content=True)
        self.write_cfg(CFG)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.10.10", 22, 27)
        self.hooks()

    def dry(self):
        lines = []
        rc = self.quiet(G.dry_run, emit=lines.append)
        return rc, "\n".join(lines)


# --- D3 ---------------------------------------------------------------------------------------------------------

class ProposalNameTests(unittest.TestCase):
    def doc(self, *records):
        return {"run_id": "r1", "exported_at": "2026-11-05T00:00:00Z", "openclaw_to": "2026.10.10",
                "proposals": [{"proposal_id": f"p{i}", "status": "applied", "kind": "create", "record_json": r,
                               "events": [], "files": [], "openclaw_doctor": "drops this proposal"}
                              for i, r in enumerate(records)]}

    def test_name_from_target_skill_name_then_title(self):
        # 2026.10.4 records carry title and target.skillName, no name/skillName (rehearsal proposals.json)
        rec_1004 = {"schema": "openclaw.skill-workshop.proposal.v1", "title": "Create wetter-kurz",
                    "description": "Short weather summary",
                    "target": {"skillName": "wetter-kurz", "skillKey": "wetter-kurz",
                               "skillDir": "/config/.openclaw/agents/main/agent/workshop-skills/wetter-kurz"}}
        only_title = {"title": "Update router-notes", "target": {"skillDir": "/x/router-notes"}}
        named = {"name": "tram-times", "title": "Create tram", "target": {"skillName": "other"}}
        md = G._sw_proposals_md(self.doc(rec_1004, only_title, named, {"target": "not a dict"}))
        rows = [ln for ln in md.splitlines() if ln.startswith("| p")]
        self.assertEqual([r.split(" | ")[3] for r in rows], ["wetter-kurz", "Update router-notes", "tram-times", ""])
        self.assertIn("## p0 (applied)\n\n- name: wetter-kurz\n- description: Short weather summary\n", md)
        self.assertIn("## p1 (applied)\n\n- name: Update router-notes\n- draft:", md)
        self.assertIn("## p3 (applied)\n\n- draft:", md)  # no name at all: no empty "- name:" line
        self.assertEqual(G._sw_name({"skillName": "s", "title": "t"}), "s")
        self.assertIsNone(G._sw_name({"title": "  "}))


# --- D6 ---------------------------------------------------------------------------------------------------------

class UnconfiguredAgentTests(Bump1010):
    AGENTS = ("main", "oldbot")  # both registered in agent_databases; openclaw.json configures main only

    def test_precheck_info_line_for_a_registered_store_without_agent(self):
        rc, text = self.dry()
        self.assertEqual(rc, 0, text)
        self.assertIn(f"[gate] 1/8 info: {AGENT.format('oldbot')} (agent oldbot, schema 24) is registered in "
                      "OpenClaw's state, but the agent is not configured in openclaw.json: the gate checks it with the "
                      "other agent databases (doctor migrates registered stores too); OpenClaw does not run an agent "
                      "that is not configured, and cancels the runs of its cron jobs ('cron job agent is "
                      "unavailable')", text)
        self.assertNotIn("(agent main, schema 24) is registered", text)
        # configured (also by entries, and in another case): no line
        cfg = json.loads(json.dumps(CFG))
        cfg["agents"]["list"].append({"id": "OldBot"})
        self.write_cfg(cfg)
        _rc, text = self.dry()
        self.assertNotIn("is registered in OpenClaw's state", text)

    def test_cron_jobs_of_an_unconfigured_agent_are_left_out_of_the_report(self):
        CB.add_jobs(self.state, [
            ("job-old", {"agentId": "oldbot", "sessionTarget": "isolated",
                         "payload": {"kind": "agentTurn", "message": CB.PROMPT, "model": "openai/gpt-5.5"}}),
            ("job-old-key", {"sessionKey": "agent:OldBot:cron:x", "sessionTarget": "isolated",
                             "payload": {"kind": "agentTurn", "message": CB.PROMPT}})], start=40)
        rec = G.cron_account_report(self.state, CFG, "2026.10.10")
        self.assertEqual([a["id"] for a in rec["affected"]], ["job-morning", "job-local"])
        self.assertEqual(rec["unconfigured"], [{"id": "job-old", "name": "Job Old", "agent": "oldbot"},
                                               {"id": "job-old-key", "name": "Job Old Key", "agent": "oldbot"}])
        self.assertEqual(rec["checked"], 2)
        line = ("2 enabled cron job(s) belong to agent(s) not configured in openclaw.json (oldbot): OpenClaw cancels "
                "their runs ('cron job agent is unavailable'), so the inference-account report leaves them out: "
                "'Job Old' (job-old), 'Job Old Key' (job-old-key)")
        self.assertEqual(G.cron_unconfigured_line(rec), line)
        rc, text = self.dry()
        self.assertEqual(rc, 0, text)
        self.assertIn("[gate] 1/8 info: " + line, text)
        self.assertNotIn("WARN [gate] cron job 'Job Old'", text)
        # the whole run: precheck, finalize and status
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual(self.out.count(line), 2, self.out)
        self.assertNotIn(CB.PROMPT, json.dumps(self.journal()))
        self.assertIn("  " + line, G.status_lines())
        # no job of an unconfigured agent: no line, no key (a record of an earlier add-on version has none)
        self.assertIsNone(G.cron_unconfigured_line({"affected": []}))
        rec = G.cron_account_report(self.state, dict(CFG, agents={"list": [{"id": "main"}, {"id": "oldbot"}]}),
                                    "2026.10.10")
        self.assertNotIn("unconfigured", rec)
        self.assertIn("job-old", [a["id"] for a in rec["affected"]])


# --- D8 ---------------------------------------------------------------------------------------------------------

class InstallLeftoverTests(Bump1010):
    def test_snapshot_skips_openclaw_work_directories(self):
        proj = self.state / "npm" / "projects"
        for name in ("openclaw-acpx-1a2b3c__openclaw-generation__g-0123456789abcdef", ".openclaw-install-stage-LceUSl",
                     ".openclaw-install-rollback-Ab12Cd", ".openclaw-install-backups", ".openclaw-retained-npm-installs"):
            (proj / name).mkdir(parents=True)
        self.assertEqual(G.plugin_snapshot(self.state), ["npm/projects/openclaw-acpx-1a2b3c"])
        self.assertEqual(G.plugin_install_leftovers(self.state),
                         [("npm/projects/.openclaw-install-rollback-Ab12Cd", "rollback"),
                          ("npm/projects/.openclaw-install-stage-LceUSl", "stage")])  # an empty backups dir: nothing
        (proj / ".openclaw-install-backups" / "openclaw-acpx-1a2b3c-0b1c").mkdir()
        self.assertIn(("npm/projects/.openclaw-install-backups", "backups"), G.plugin_install_leftovers(self.state))
        (self.state / "extensions").mkdir()
        (self.state / "extensions" / ".openclaw-install-stage-zz99ZZ").write_text("a file, not a directory")
        self.assertNotIn("extensions/.openclaw-install-stage-zz99ZZ",
                         [p for p, _k in G.plugin_install_leftovers(self.state)])

    def test_stage_dir_of_a_stopped_doctor_is_no_new_plugin(self):
        self.doctor_script(state_uv=22, agent_uv=27, app_version="2026.10.10",
                           write={"npm/projects/.openclaw-install-stage-LceUSl/package.json": "{}"})
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("doctor installed new plugin package(s)", self.out)
        self.assertIn("WARN [gate] plugin install leftovers: 1 staging/rollback director(ies) of an interrupted "
                      "OpenClaw plugin install or update (npm/projects/.openclaw-install-stage-LceUSl): no plugin; "
                      "OpenClaw does not use or remove them, delete them by hand while OpenClaw is not installing "
                      "plugins", self.out)
        self.assertTrue((self.state / "npm/projects/.openclaw-install-stage-LceUSl").is_dir())  # never deleted
        st = G.status_lines()
        self.assertTrue(any(x.startswith("Plugin install leftovers: 1 staging/rollback") for x in st), st)

    def test_a_real_new_plugin_is_still_reported(self):
        self.doctor_script(state_uv=22, agent_uv=27, app_version="2026.10.10",
                           write={"npm/projects/openclaw-brave-plugin-9f8e__openclaw-generation__g-00000000000000aa/"
                                  "package.json": "{}"})
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("WARN [gate] doctor installed new plugin package(s): npm/projects/openclaw-brave-plugin-9f8e "
                      "(left in place)", self.out)
        self.assertNotIn("plugin install leftovers", self.out)


# --- D10 --------------------------------------------------------------------------------------------------------

DETACHING_PARENT = textwrap.dedent('''
    import subprocess, sys, time
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], start_new_session=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    open(sys.argv[1], "w").write(str(child.pid))
    time.sleep(float(sys.argv[2]))
''')


# A2: like OpenClaw's doctor on SIGTERM ("settling admitted repairs"): it keeps waiting for its detached npm child
SETTLING_PARENT = textwrap.dedent('''
    import signal, subprocess, sys
    signal.signal(signal.SIGTERM, lambda *_a: None)
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"], start_new_session=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    open(sys.argv[1], "w").write(str(child.pid))
    child.wait()
    sys.exit(3)
''')


@unittest.skipUnless(os.path.isdir("/proc/self"), "needs /proc")
class DetachedDescendantTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="oc-d10-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "parent.py").write_text(DETACHING_PARENT)
        self.pidfile = self.tmp / "child.pid"
        self.child = None

    def tearDown(self):
        if self.child and self.alive(self.child):  # whatever the result: no sleeper is left behind
            os.kill(self.child, signal.SIGKILL)

    @staticmethod
    def alive(pid):
        """Running (not gone, not a zombie that nobody reaped), read without the code under test."""
        try:
            data = Path(f"/proc/{pid}/stat").read_bytes()
        except OSError:
            return False
        return data[data.rindex(b")") + 2:].split()[0] not in (b"Z", b"X")

    def run_parent(self, sleep_s, **kw):
        res = C.run_process([sys.executable, str(self.tmp / "parent.py"), str(self.pidfile), str(sleep_s)],
                            log_path=self.tmp / "log", cwd=str(self.tmp), **kw)
        self.child = int(self.pidfile.read_text())
        return res

    def test_detached_child_of_a_normally_ending_process_is_stopped(self):
        res = self.run_parent(2.5, timeout=60, tick=0.2)
        self.assertEqual(res.rc, 0)
        self.assertFalse(self.alive(self.child), "a detached child (own session) survived its parent")
        self.assertIn("[oc] stopped 1 leftover descendant process(es) outside its process group",
                      (self.tmp / "log").read_text())

    def test_detached_child_survives_neither_timeout_nor_kill(self):
        res = self.run_parent(60, timeout=1.5, kill_grace=1, tick=0.2)
        self.assertTrue(res.timed_out)
        self.assertFalse(self.alive(self.child))

    def test_stop_request(self):
        import threading
        ev = threading.Event()
        threading.Timer(1.5, ev.set).start()
        res = self.run_parent(60, timeout=None, stop_event=ev, kill_grace=1, tick=0.2)
        self.assertTrue(res.stopped)
        self.assertFalse(self.alive(self.child))

    def test_stop_request_reaches_the_detached_child_at_once(self):
        """Rehearsal A2: on a stop request doctor waited for its detached npm (own session), which killpg did not
        reach, so the gate waited the whole grace period (240 s) and killed doctor (rc -9). The detached descendants
        now get the SIGTERM at once: the child ends, the parent exits by itself long before its grace period."""
        import threading
        (self.tmp / "settling.py").write_text(SETTLING_PARENT)
        ev = threading.Event()
        timer = threading.Timer(1.5, ev.set)
        timer.start()
        self.addCleanup(timer.cancel)
        start = time.monotonic()
        res = C.run_process([sys.executable, str(self.tmp / "settling.py"), str(self.pidfile)], timeout=None,
                            stop_event=ev, stop_grace=30, log_path=self.tmp / "log", cwd=str(self.tmp), tick=0.2)
        self.child = int(self.pidfile.read_text())
        self.assertLess(time.monotonic() - start, 15)
        self.assertTrue(res.stopped)
        self.assertFalse(res.killed)
        self.assertEqual(res.rc, 3)  # it ended by itself
        self.assertFalse(self.alive(self.child))
        self.assertIn("[oc] SIGTERM also to 1 descendant process(es) outside its process group",
                      (self.tmp / "log").read_text())

    def test_killed_after_the_grace_period_is_reported(self):
        res = self.run_parent(60, timeout=1.0, kill_grace=0.5, tick=0.2)
        self.assertTrue(res.timed_out)
        self.assertEqual(res.rc, -signal.SIGTERM)  # the parent ends on SIGTERM: no SIGKILL needed
        self.assertFalse(res.killed)
        import threading
        (self.tmp / "stubborn.py").write_text("import signal, time\nsignal.signal(signal.SIGTERM, lambda *a: None)\n"
                                              "time.sleep(60)\n")
        ev = threading.Event()
        ev.set()
        res = C.run_process([sys.executable, str(self.tmp / "stubborn.py")], timeout=None, stop_event=ev,
                            stop_grace=1, log_path=self.tmp / "log2", cwd=str(self.tmp), tick=0.2)
        self.assertTrue(res.stopped and res.killed)
        self.assertEqual(res.rc, -signal.SIGKILL)

    def test_proc_helpers(self):
        st = C._proc_stat(os.getpid())
        self.assertEqual(st[1], os.getppid())
        self.assertEqual((st[2], st[3]), (os.getpgrp(), os.getsid(0)))
        self.assertIsNone(C._proc_stat(2 ** 22 + 7))
        table = {10: ("S", 1, 10, 10, 5), 11: ("S", 10, 11, 11, 6), 12: ("Z", 10, 10, 10, 7), 13: ("S", 11, 11, 11, 8)}
        self.assertEqual(C._descendants(10, table), {11: 6, 13: 8})
        self.assertEqual(C._kill_strays({}), [])


# --- D11 --------------------------------------------------------------------------------------------------------

# What 2026.10.10/2026.11.1 doctor does with an unregistered store that is a byte-identical copy of another agent's
# database (state-migrations.agent-owner-recovery.ts + sqlite-recovery-files.ts): rename it (and its -wal/-shm) to
# <file>.corrupt-<Date.now()>, then the scriptable fake doctor migrates whatever is left under agents/.
SET_ASIDE_DOCTOR = r'''#!/usr/bin/env python3
import json, os, sys, time
with open(sys.argv[1], encoding="utf-8") as f:
    cfg = json.load(f)
state = os.environ["OPENCLAW_STATE_DIR"]
suffix = ".corrupt-%d" % int(time.time() * 1000)
for rel in cfg.get("set_aside") or []:
    for ext in ("", "-wal", "-shm"):
        p = os.path.join(state, rel + ext)
        if os.path.exists(p):
            os.rename(p, p + suffix)
            if not ext:
                print("Recovered agent x: %s was a byte-identical copy of agent main's database. Preserved the "
                      "copy at %s." % (p, p + suffix))
os.execv(cfg["next"][0], cfg["next"])
'''


class OrphanOutcomeTests(Bump1010):
    def setUp(self):
        super().setUp()
        T.make_1004_agent_db(self.state, "ghost")  # neither configured nor registered: orphan-agent-db
        T.make_1004_agent_db(self.state, "spare")
        (self.state / AGENT.format("ghost")).with_name("openclaw-agent.sqlite-wal").write_bytes(b"")
        wrapper = self.bin / "set-aside-doctor"
        wrapper.write_text(SET_ASIDE_DOCTOR)
        wrapper.chmod(0o755)
        conf = self.tmp / "set-aside.json"
        conf.write_text(json.dumps({"set_aside": [AGENT.format("ghost")], "next": self.doctor_cmd}))
        self.doctor_cmd = [str(wrapper), str(conf)]
        self.hooks()

    def test_hold_text_no_longer_promises_the_migration_for_every_store(self):
        self.assertEqual(self.run_gate(), 20, self.out)
        hold = (self.upg / "hold.txt").read_text()
        self.assertIn("unless its deletion history holds it back, migrates it one-way to schema 27; a store that "
                      "records another agent as its owner is not migrated: doctor moves it aside as "
                      "<file>.corrupt-<time> only when it and its -wal/-shm files are byte-identical to that agent's "
                      "database (a plaintext copy that is kept), and otherwise refuses it, which stops doctor after "
                      "the other databases are migrated (hard HOLD doctor-migration-refused): move such a folder out "
                      "of agents/ instead of accepting", hold)
        self.assertIn("what doctor did is in the gate's final lines and oc-upgrade status", hold)

    def test_outcomes_in_finalize_journal_marker_and_status(self):
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertEqual(G.retry_cmd(["--accept", "orphan-agent-db"], emit=lambda s: None), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        aside = sorted(p.name for p in (self.state / "agents" / "ghost" / "agent").iterdir())
        self.assertEqual(len(aside), 2, aside)  # the renamed DB and its -wal; nothing else
        db_aside = next(n for n in aside if n.startswith("openclaw-agent.sqlite.corrupt-"))
        rel = f"agents/ghost/agent/{db_aside}"
        j = self.journal()
        self.assertEqual([(o["id"], o["outcome"], o["uv"], o["uv_after"], o["set_aside"]) for o in j["orphan_outcomes"]],
                         [("ghost", "set-aside", 24, None, [rel]), ("spare", "migrated", 24, 27, [])])
        ghost = ("orphan agent database agents/ghost/agent/openclaw-agent.sqlite (agent ghost, schema 24 before): "
                 f"doctor found it to be a byte-identical copy of another agent's database and set it aside as {rel}: "
                 "the renamed original, a complete plaintext database that OpenClaw and the add-on keep; delete it by "
                 "hand once you are satisfied (oc-upgrade status lists such files)")
        spare = ("orphan agent database agents/spare/agent/openclaw-agent.sqlite (agent spare, schema 24 before): "
                 "doctor migrated it to schema 27; the gateway does not open it")
        self.assertIn("WARN [gate] " + ghost, self.out)
        self.assertIn("[gate] info: " + spare, self.out)
        self.assertLess(self.out.index(ghost), self.out.index("[gate] done: MIGRATED"))
        marker = json.loads((self.upg / "gate" / "migrated.json").read_text())
        self.assertEqual([(o["id"], o.get("after")) for o in marker["orphans"]],
                         [("ghost", "set-aside"), ("spare", "migrated")])
        st = G.status_lines()
        self.assertIn("  " + ghost, st)
        self.assertIn("  " + spare, st)
        line = next(x for x in st if x.startswith("Databases OpenClaw set aside"))
        self.assertTrue(line.startswith("Databases OpenClaw set aside (<file>.corrupt-<time>): 2 file(s), "), line)
        self.assertIn(rel, line)
        self.assertIn("OpenClaw and the add-on keep them: delete them by hand once you are satisfied", line)
        # the cleanup (gate_cleanup_hours) never deletes them, also long after the run
        G.cleanup_pass(now=C.utc_now() + timedelta(days=365), emit=lambda s: None)
        self.assertTrue((self.state / rel).is_file())

    def test_outcome_rules(self):
        st = self.state
        orphans = [{"id": "ghost", "path": AGENT.format("ghost"), "uv": 24},
                   {"id": "spare", "path": AGENT.format("spare"), "uv": 24},
                   {"id": "gone", "path": AGENT.format("gone"), "uv": 24},
                   {"id": "kept", "path": AGENT.format("kept"), "uv": 24, "held": True}]
        old = st / "agents" / "ghost" / "agent" / "openclaw-agent.sqlite.corrupt-1700000000000"
        old.write_bytes(b"older set-aside copy")
        res = G.orphan_outcomes(st, orphans, 27, since="2026-11-05T00:00:00Z")
        self.assertEqual([(o["id"], o["outcome"], o["uv_after"], o["set_aside"]) for o in res],
                         [("ghost", "not-migrated", 24, []), ("spare", "not-migrated", 24, []),
                          ("gone", "gone", None, [])])
        self.assertIn("still at schema 24 (target 27): doctor did not migrate it (refused or held back; oc-upgrade "
                      "log says why)", G.orphan_outcome_text(res[0], 27))
        self.assertEqual(G.orphan_outcomes(st, orphans[:1], 27)[0]["set_aside"],  # no run start: every copy
                         [f"agents/ghost/agent/{old.name}"])
        self.assertEqual(G.orphan_outcomes(st, None, 27), [])


class SetAsideStatusTests(T.GateEnv):
    def test_listing(self):
        T.make_1004_state(self.state)
        d = self.state / "agents" / "main" / "agent"
        (d / "openclaw-agent.sqlite.corrupt-1793904458234").write_bytes(b"x" * 10)
        (d / "openclaw-agent.sqlite-wal.corrupt-1793904458234").write_bytes(b"y" * 5)
        (d / "openclaw-agent.sqlite.corrupt-1793904458234.1").write_bytes(b"z")
        (d / "notes.corrupt-1").write_bytes(b"no database")
        (self.state / "state" / "openclaw.sqlite.corrupt-1793904458000").write_bytes(b"s")
        os.symlink("/etc/hostname", d / "openclaw-agent.sqlite.corrupt-1793904458999")
        self.assertEqual(G.sqlite_set_aside(self.state), {
            "agents/main/agent/openclaw-agent.sqlite.corrupt-1793904458234": 10,
            "agents/main/agent/openclaw-agent.sqlite-wal.corrupt-1793904458234": 5,
            "agents/main/agent/openclaw-agent.sqlite.corrupt-1793904458234.1": 1,
            "state/openclaw.sqlite.corrupt-1793904458000": 1})
        self.assertFalse(G.DOCTOR_COPY_RE.fullmatch("openclaw-agent.sqlite.corrupt-1793904458234"))


# --- D12 --------------------------------------------------------------------------------------------------------

class NoNetworkTextTests(Bump1010):
    def test_reason_and_advice(self):
        npm = self.bin / "npm"
        npm.write_text("#!/bin/sh\necho 'npm error code ENOTFOUND' >&2\nexit 1\n")
        npm.chmod(0o755)
        self.hooks(skip_network_check=False)
        self.assertEqual(self.run_gate(), 20, self.out)
        hold = (self.upg / "hold.txt").read_text()
        self.assertIn("Reason [no-network]: npm registry not reachable (rc 1); doctor installs/updates official "
                      "plugins from it. Accepted, doctor keeps retrying npm for many minutes per plugin (over 10 "
                      "minutes were seen) and can run into its time budget per pass (1h00m; then the gate holds with "
                      "doctor-timeout); prefer fixing the network", hold)
        self.assertIn("Next: make the npm registry reachable (network, DNS, proxy), then oc-upgrade retry; accepting "
                      "it makes doctor retry npm for a long time (see the reason), or accept: oc-upgrade retry "
                      "--accept no-network (then restart the add-on)", hold)


# --- tmp/plugin-captures ----------------------------------------------------------------------------------------

class PluginCaptureStatusTests(T.GateEnv):
    def test_status_counts_own_bytes_and_hard_links_once(self):
        T.make_1004_state(self.state)
        self.assertIsNone(G.plugin_captures_usage(self.state))
        inst = self.state / "npm" / "projects" / "openclaw-codex-1a__openclaw-generation__g-00000000000000ab"
        inst.mkdir(parents=True)
        (inst / "codex").write_bytes(b"b" * 4000)
        cap = self.state / "tmp" / "plugin-captures" / "1295ca4c-0000-4000-8000-000000000001"
        (cap / "native").mkdir(parents=True)
        self.assertIsNone(G.plugin_captures_usage(self.state.parent / "nowhere"))
        os.link(inst / "codex", cap / "native" / "codex")
        os.link(inst / "codex", cap / "native" / "codex-again")  # an overlapping namespace: the same inode
        (cap / "owner.sqlite").write_bytes(b"o" * 100)
        u = G.plugin_captures_usage(self.state)
        self.assertEqual((u["captures"], u["files"], u["own"], u["linked"], u["partial"]), (1, 3, 100, 4000, False))
        line = next(x for x in G.status_lines() if x.startswith("OpenClaw plugin captures: "))
        self.assertIn("(1 capture(s), 3 files; 100 B of their own, 3.9 KiB in hard links that share the installed "
                      "plugins' disk space): OpenClaw's live copy of the native plugin files, removed by OpenClaw once "
                      "no plugin install refers to it; the add-on does not delete it", line)
        # the cleanup (gate_cleanup_hours) leaves it alone
        G.cleanup_pass(now=C.utc_now() + timedelta(days=365), emit=lambda s: None)
        self.assertTrue((cap / "owner.sqlite").is_file())

    def test_backup_exclude_keeps_the_captures(self):
        # a referenced capture that is missing is not re-admitted (plugin-native-admission.ts: only retired,
        # entirely missing captures may be), so a restore needs it: config.yaml must not exclude it
        conf = (ADDON / "config.yaml").read_text(encoding="utf-8")
        block = conf.split("backup_exclude:", 1)[1].split("\n\n", 1)[0]
        for word in ("plugin-captures", "tmp", ".openclaw"):
            self.assertNotIn(word, block)


if __name__ == "__main__":
    unittest.main()
