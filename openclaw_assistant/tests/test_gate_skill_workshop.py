"""Skill Workshop proposals and doctor's SQLite copies (full5 prep, OpenClaw 2026.10.10+).

OpenClaw 2026.10.10 doctor keeps only the current drafts of pending/quarantined Skill Workshop proposals and drops the
rest (doctor-skill-workshop-retire-proposals.ts). The gate counts the proposals in the precheck, exports every proposal
(all states, events, undo records, all draft generations; redacted) to runs/<id>/skill-workshop/ before doctor pass 1,
and warns when doctor keeps the storage. Doctor's own plaintext SQLite copies (*.pre-startup-migration-*.bak /
.scoped.bak) are counted per pass and deleted gate_cleanup_hours after their gate run, like the doctor captures.

Synthetic fixtures only (no real prompts, ids or tokens). Gate-level runs use the 10.4 DDL (test_gate.make_1004_state)
and the scriptable fake doctor; this module's SW_DOCTOR wrapper adds what doctor does to the proposal files.
"""

import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
for _p in (str(ADDON), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_common as C  # noqa: E402
import oc_gate as G  # noqa: E402
import test_gate as T  # noqa: E402

GEN1 = "0a1b2c3d-1111-4222-8333-444455556666"
GEN2 = "9f8e7d6c-5555-4666-8777-888899990000"
SK_SECRET = "sk-ABCDEFGHIJKLMNOP1234"
BOT_SECRET = "123456:" + "A" * 34
BEARER_SECRET = "Bearer abcdefgh12345678secret"
DRAFT_HASH = "ab" * 32
SW_TABLES = ("skill_workshop_proposals", "skill_workshop_proposal_events", "skill_workshop_proposal_rollbacks",
             "skill_workshop_collection_reviews")

# What doctor does to the proposal files (the scriptable fake doctor does the tables): optionally refuse to run
# before the gate's export exists, remove skill-workshop/proposals and proposals.json, then run the next doctor.
SW_DOCTOR = r'''#!/usr/bin/env python3
import glob, json, os, shutil, sys
with open(sys.argv[1], encoding="utf-8") as f:
    cfg = json.load(f)
state = os.environ["OPENCLAW_STATE_DIR"]
if cfg.get("require_export") and not glob.glob(os.path.join(cfg["upg"], "gate", "runs", "*", "skill-workshop",
                                                            "MANIFEST.json")):
    print("fake doctor: no Skill Workshop export before doctor")
    sys.exit(1)
if cfg.get("retire"):
    shutil.rmtree(os.path.join(state, "skill-workshop", "proposals"), ignore_errors=True)
    p = os.path.join(state, "skill-workshop", "proposals.json")
    if os.path.lexists(p):
        os.remove(p)
os.execv(cfg["next"][0], cfg["next"])
'''


def proposal(pid, kind, status, rec, owner="main", reason=None):
    return (pid, kind, status, owner, rec, reason)


def record(name, draft="PROPOSAL.md", **kw):
    rec = {"schema": "openclaw.skill-workshop.proposal.v1", "name": name, "description": f"{name} skill",
           "goal": f"help with {name}", "evidence": "synthetic", "draftFile": draft, "draftHash": DRAFT_HASH,
           "supportFiles": [], "target": {"skillDir": f"/config/clawd/skills/{name}",
                                          "skillFile": f"/config/clawd/skills/{name}/SKILL.md"},
           "origin": {"sessionKey": "agent:main:telegram:direct:42"}}
    rec.update(kw)
    return rec


FIVE = [
    proposal("wx-pending", "create", "pending",
             record("weather-brief", f"generations/{GEN1}/PROPOSAL.md",
                    supportFiles=[{"path": "notes.md", "hash": "cd" * 32}], apiKey="plain-api-key-value")),
    proposal("wx-quarantined", "update", "quarantined", record("shopping-list")),
    proposal("wx-applied", "update", "applied", record("tram-times")),
    proposal("wx-rejected", "create", "rejected", record("lights-off"), reason="not useful"),
    proposal("wx-stale-01", "update", "stale", record("old-skill")),
]


def add_sw_content(state, proposals=FIVE, files=True):
    """Rows in the four 10.4 Skill Workshop tables plus the draft files below <state>/skill-workshop/."""
    c = sqlite3.connect(str(state / "state" / "openclaw.sqlite"))
    for pid, kind, status, owner, rec, reason in proposals:
        c.execute("INSERT INTO skill_workshop_proposals (proposal_id, record_json, owner_agent_id, kind, status, "
                  "created_at, updated_at, draft_hash, origin_session_key, status_reason) VALUES "
                  "(?, ?, ?, ?, ?, '2026-10-01T00:00:00Z', '2026-10-02T00:00:00Z', ?, ?, ?)",
                  (pid, json.dumps(dict(rec, id=pid, status=status)) if isinstance(rec, dict) else rec, owner, kind,
                   status, "sha256:" + DRAFT_HASH, "agent:main:telegram:direct:42", reason))
        for i, ev in enumerate(("created", "evaluation_completed")):
            c.execute("INSERT INTO skill_workshop_proposal_events (event_id, proposal_id, proposed_version, "
                      "revision_hash, event_type, occurred_at, actor_json, payload_json) VALUES "
                      "(?, ?, '1', ?, ?, '2026-10-01T00:00:00Z', ?, ?)",
                      (f"{pid}-ev{i}", pid, DRAFT_HASH, ev, json.dumps({"kind": "agent", "agentId": "main"}),
                       json.dumps({"note": "synthetic", "token": "SECRET-EVENT-TOKEN"})))
    ids = {p[0] for p in proposals}
    if "wx-applied" in ids:
        c.execute("INSERT INTO skill_workshop_proposal_rollbacks VALUES ('wx-applied', '2026-10-02T00:00:00Z', "
                  "'/config/clawd/skills/tram-times/SKILL.md', 'update', ?, ?, '[]')",
                  (DRAFT_HASH, f"# tram\nbotToken: {BOT_SECRET}\n"))
    if "wx-pending" in ids:  # a rollback of a proposal that is not applied: an unfinished apply
        c.execute("INSERT INTO skill_workshop_proposal_rollbacks VALUES ('wx-pending', '2026-10-02T00:00:00Z', "
                  "'/config/clawd/skills/weather-brief/SKILL.md', 'create', NULL, NULL, '[]')")
    c.execute("INSERT INTO skill_workshop_collection_reviews VALUES ('rev-1', 'main', 'backup-1', 0, '[\"a\"]', "
              "'[\"b\"]', '[]')")
    c.commit()
    c.close()
    if not files:
        return
    sw = state / "skill-workshop"
    gen1 = sw / "proposals" / "wx-pending" / "generations" / GEN1
    gen2 = sw / "proposals" / "wx-pending" / "generations" / GEN2
    for d in (gen1, gen2, sw / "proposals" / "wx-quarantined", sw / "proposals" / "wx-applied", sw / "recovery"):
        d.mkdir(parents=True, exist_ok=True)
    (gen1 / "PROPOSAL.md").write_text(f"# weather-brief\nuse key {SK_SECRET} for the forecast\n")
    (gen1 / "notes.md").write_text("support notes\n")
    (gen2 / "PROPOSAL.md").write_text("# weather-brief (older draft)\n")
    (sw / "proposals" / "wx-quarantined" / "PROPOSAL.md").write_text("# shopping-list\n")
    (sw / "proposals" / "wx-applied" / "PROPOSAL.md").write_text("# tram-times\n")
    (sw / "proposals.json").write_text(json.dumps({"schema": "openclaw.skill-workshop.proposals-manifest.v1",
                                                   "proposals": [{"id": "wx-pending"}]}))
    (sw / "recovery" / "legacy.json").write_text(json.dumps({"evidence": f"curl -H 'Authorization: {BEARER_SECRET}'"}))


def all_bytes(root):
    out = b""
    for p, st in C.walk_lstat(root):
        if stat.S_ISREG(st.st_mode):
            out += p.read_bytes()
    return out


def tree_state(root):
    return {str(p): (st.st_mode, st.st_size, st.st_mtime_ns) for p, st in C.walk_lstat(root)}


class Base(T.GateEnv):
    def setUp(self):
        super().setUp()
        self.sdb = self.state / "state" / "openclaw.sqlite"
        self.cfg = {"meta": {"lastTouchedVersion": "2026.10.4"}, "gateway": {"mode": "local"},
                    "agents": {"list": [{"id": "main", "default": True}]}}

    def bump_1010(self, files=True, proposals=FIVE):
        """A 2026.10.4 state with Skill Workshop proposals and a 2026.10.10 runtime (a bump)."""
        T.make_1004_state(self.state)
        add_sw_content(self.state, proposals, files)
        self.write_cfg(self.cfg)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.10.10", 22, 27)
        self.hooks()

    def sw_doctor(self, passes=None, require_export=True, retire=True, **step):
        """The scriptable fake doctor (`passes` / `step`) behind SW_DOCTOR."""
        self.doctor_script(passes=passes, **step)
        wrapper = self.bin / "sw-doctor"
        if not wrapper.exists():
            wrapper.write_text(SW_DOCTOR)
            wrapper.chmod(0o755)
        cfgp = self.tmp / "sw-doctor.json"
        cfgp.write_text(json.dumps({"require_export": require_export, "retire": retire, "upg": str(self.upg),
                                    "next": list(self.doctor_cmd)}))
        self.doctor_cmd = [str(wrapper), str(cfgp)]
        self.hooks()

    def step_1010(self, retire=True, **kw):
        step = {"state_uv": 22, "agent_uv": 27, "app_version": "2026.10.10", "drop_tables": ["cron_run_logs"],
                "remove": ["identity/device.json"]}
        if retire:
            step["drop_tables"] = step["drop_tables"] + list(SW_TABLES)
            step["print"] = ["Exported 1 pending Skill Workshop proposal draft to "
                             f"{self.state}/agents/main/agent/workshop-skills/.archive/.retired-proposals/.",
                             "Retired the Skill Workshop proposal tables."]
        step.update(kw)
        return step

    def doctor_count(self):
        cnt = Path(str(self.tmp / "doctor-script.json") + ".count")
        return int(cnt.read_text()) if cnt.exists() else 0

    def export_dir(self, j=None):
        j = j or self.journal()
        return self.upg / "gate" / "runs" / j["run_id"] / "skill-workshop"


# --- inventory -----------------------------------------------------------------------------------

class InventoryTests(Base):
    def test_counts_by_status_tables_and_files_read_only(self):
        T.make_1004_state(self.state)
        add_sw_content(self.state)
        before = tree_state(self.state)
        sha = hashlib.sha256(self.sdb.read_bytes()).hexdigest()
        inv = G.skill_workshop_inventory(self.state, self.cfg)
        self.assertEqual(inv["by_status"], {s: 1 for s in ("pending", "quarantined", "applied", "rejected", "stale")})
        self.assertEqual((inv["proposals"], inv["events"], inv["rollbacks"], inv["reviews"]), (5, 10, 2, 1))
        self.assertEqual(inv["tables"], {"skill_workshop_proposals": 5, "skill_workshop_proposal_events": 10,
                                         "skill_workshop_proposal_rollbacks": 2,
                                         "skill_workshop_collection_reviews": 1})
        self.assertEqual(inv["files"], 7)
        self.assertGreater(inv["file_bytes"], 0)
        self.assertGreater(inv["bytes"], 1000)
        self.assertTrue(inv["legacy_manifest"] and inv["recovery"])
        self.assertEqual(len(inv["unfinished"]), 1)
        self.assertIn("proposal wx-pending has an unfinished apply", inv["unfinished"][0])
        self.assertIn("/config/clawd/skills/weather-brief", inv["unfinished"][0])
        self.assertEqual(inv["holdbacks"], [])
        self.assertEqual(G.sw_counts(inv)["by_status"]["pending"], 1)
        # read-only: same bytes, no -wal/-shm, nothing else touched
        self.assertEqual(hashlib.sha256(self.sdb.read_bytes()).hexdigest(), sha)
        self.assertEqual(tree_state(self.state), before)
        self.assertFalse(os.path.exists(f"{self.sdb}-wal") or os.path.exists(f"{self.sdb}-shm"))

    def test_absent_or_empty_storage(self):
        self.assertIsNone(G.skill_workshop_inventory(self.state, self.cfg))  # no state DB at all
        T.make_1004_state(self.state)
        inv = G.skill_workshop_inventory(self.state, self.cfg)  # 10.4 tables, no rows, no files
        self.assertTrue(G.sw_empty(inv))
        c = sqlite3.connect(str(self.sdb))
        for t in SW_TABLES:
            c.execute(f"DROP TABLE {t}")
        c.commit()
        c.close()
        self.assertIsNone(G.skill_workshop_inventory(self.state, self.cfg))  # a 10.10 state
        (self.state / "skill-workshop" / "recovery").mkdir(parents=True)  # doctor leaves recovery/ alone
        self.assertIsNone(G.skill_workshop_inventory(self.state, self.cfg))
        self.assertTrue(G.sw_empty(None))

    def test_predicted_holdbacks(self):
        T.make_1004_state(self.state)
        two = dict(self.cfg, agents={"list": [{"id": "main", "default": True}, {"id": "helper"}]})
        add_sw_content(self.state, [
            proposal("ghost-owned", "create", "pending", record("a"), owner="ghost"),
            proposal("no-owner-1", "create", "pending", record("b", origin={}), owner=None),
            proposal("bad-json-1", "create", "quarantined", "{not json", owner="main"),
            proposal("bad-draft-1", "create", "pending", record("c", draft="../x.md"), owner="main"),
            proposal("no-draft-1", "create", "pending", record("d"), owner="main"),
            proposal("applied-ghost", "create", "applied", record("e"), owner="ghost"),  # not exported: no holdback
        ], files=False)
        (self.state / "skill-workshop" / "proposals" / "no-draft-1").mkdir(parents=True)
        (self.state / "skill-workshop" / "proposals" / "orphan-bundle").mkdir(parents=True)
        (self.state / "skill-workshop" / "proposals" / "legacy-bundle").mkdir(parents=True)
        (self.state / "skill-workshop" / "proposals" / "legacy-bundle" / "proposal.json").write_text("{}")
        inv = G.skill_workshop_inventory(self.state, two)
        self.assertEqual(inv["holdbacks"], [
            "proposal bad-draft-1: its record has an invalid draft path",
            "proposal bad-json-1: its record cannot be read",
            'proposal ghost-owned belongs to agent "ghost", which is not configured',
            "proposal no-draft-1 has no draft file PROPOSAL.md",
            "proposal no-owner-1: its owner is unclear (doctor may still find it from the target skill directory)",
            "skill-workshop/proposals/orphan-bundle has no record"])
        self.assertEqual(inv["legacy_bundles"], 1)
        # with a single configured agent doctor takes it as the owner
        one = G.skill_workshop_inventory(self.state, self.cfg)
        self.assertNotIn("no-owner-1", " ".join(one["holdbacks"]))
        self.assertIn("ghost-owned", " ".join(one["holdbacks"]))


# --- export --------------------------------------------------------------------------------------

class ExportUnitTests(Base):
    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state)
        add_sw_content(self.state)
        self.dest = self.tmp / "out" / "skill-workshop"
        self.dest.parent.mkdir()

    def export(self, **meta):
        return G.export_skill_workshop(self.state, self.dest, dict({"run_id": "r1", "openclaw_to": "2026.10.10",
                                                                    "openclaw_from": "2026.10.4"}, **meta))

    def test_everything_exported_and_redacted(self):
        res = self.export()
        doc = json.loads((self.dest / "proposals.json").read_text())
        self.assertEqual(doc["schema"], G.SW_EXPORT_SCHEMA)
        self.assertEqual([p["proposal_id"] for p in doc["proposals"]],
                         ["wx-pending", "wx-quarantined", "wx-applied", "wx-rejected", "wx-stale-01"])
        self.assertEqual(doc["counts"]["by_status"],
                         {"pending": 1, "quarantined": 1, "applied": 1, "rejected": 1, "stale": 1})
        self.assertEqual((res["proposals"], res["events"], res["rollbacks"], res["collection_reviews"], res["files"]),
                         (5, 10, 2, 1, 7))
        pend = doc["proposals"][0]
        self.assertEqual(len(pend["events"]), 2)
        self.assertEqual(pend["rollback"]["target_skill_file"], "/config/clawd/skills/weather-brief/SKILL.md")
        self.assertEqual(pend["draft_export"], f"files/proposals/wx-pending/generations/{GEN1}/PROPOSAL.md")
        self.assertEqual(sorted(f["path"] for f in pend["files"]), [
            f"proposals/wx-pending/generations/{GEN1}/PROPOSAL.md", f"proposals/wx-pending/generations/{GEN1}/notes.md",
            f"proposals/wx-pending/generations/{GEN2}/PROPOSAL.md"])  # every draft generation
        self.assertIn(".retired-proposals/wx-pending/", pend["openclaw_doctor"])
        self.assertEqual(doc["proposals"][2]["openclaw_doctor"], "drops this proposal")
        self.assertEqual(doc["collection_reviews"][0]["kept_names_json"], ["a"])
        self.assertEqual(sorted(f["path"] for f in doc["other_files"]), ["proposals.json", "recovery/legacy.json"])
        for rel in (f"files/proposals/wx-pending/generations/{GEN2}/PROPOSAL.md", "files/proposals.json",
                    "files/proposals/wx-applied/PROPOSAL.md", "PROPOSALS.md", "MANIFEST.json"):
            self.assertTrue((self.dest / rel).is_file(), rel)
        md = (self.dest / "PROPOSALS.md").read_text()
        self.assertIn("| wx-rejected | rejected | create | lights-off |", md)
        self.assertIn("/learn", md)
        # redaction: no secret anywhere in the export; ids and session keys kept exactly
        blob = all_bytes(self.dest)
        for secret in (SK_SECRET, BOT_SECRET, "plain-api-key-value", "abcdefgh12345678secret", "SECRET-EVENT-TOKEN"):
            self.assertNotIn(secret.encode(), blob, secret)
        self.assertGreaterEqual(res["redactions"], 4)
        self.assertEqual(doc["redactions_total"], res["redactions"])
        self.assertEqual(pend["record_json"]["origin"]["sessionKey"], "agent:main:telegram:direct:42")
        self.assertEqual(pend["origin_session_key"], "agent:main:telegram:direct:42")
        self.assertEqual(pend["record_json"]["apiKey"], "***")
        self.assertIn("botToken: ***", doc["proposals"][2]["rollback"]["previous_content"])
        # hashes stay where nothing they could cover was redacted (wx-quarantined), and are hidden where they would
        # confirm a guess of a redacted text: wx-pending's draft (sk- key) and record (apiKey), wx-applied's undo
        # record (bot token), every event (a token in its payload)
        quar = doc["proposals"][1]
        self.assertEqual((quar["draft_hash"], quar["record_json"]["draftHash"]), ("sha256:" + DRAFT_HASH, DRAFT_HASH))
        self.assertEqual((pend["draft_hash"], pend["record_json"]["draftHash"],
                          pend["record_json"]["supportFiles"][0]["hash"]), ("***", "***", "***"))
        self.assertEqual(doc["proposals"][2]["rollback"]["previous_content_hash"], "***")
        self.assertEqual({e["revision_hash"] for p in doc["proposals"] for e in p["events"]}, {"***"})
        fl = {f["path"]: f for f in pend["files"]}
        self.assertNotIn("sha256_source", fl[f"proposals/wx-pending/generations/{GEN1}/PROPOSAL.md"])
        self.assertEqual(fl[f"proposals/wx-pending/generations/{GEN1}/PROPOSAL.md"]["redactions"], 1)
        gen2 = self.state / f"skill-workshop/proposals/wx-pending/generations/{GEN2}/PROPOSAL.md"
        self.assertEqual(fl[f"proposals/wx-pending/generations/{GEN2}/PROPOSAL.md"]["sha256_source"],
                         hashlib.sha256(gen2.read_bytes()).hexdigest())
        # modes, manifest
        for p, st in C.walk_lstat(self.dest):
            self.assertEqual(stat.S_IMODE(st.st_mode), 0o700 if stat.S_ISDIR(st.st_mode) else 0o600, p)
        self.assertEqual(stat.S_IMODE(os.stat(self.dest).st_mode), 0o700)
        man = json.loads((self.dest / "MANIFEST.json").read_text())
        self.assertTrue(man["complete"])
        for f in man["files"]:
            self.assertEqual(hashlib.sha256((self.dest / f["path"]).read_bytes()).hexdigest(), f["sha256"])
        self.assertEqual(G.sw_export_record({"RUNS": self.tmp}, "out")["proposals"], 5)
        self.assertFalse(os.path.lexists(str(self.dest) + ".partial"))

    def test_no_hash_confirms_a_guess_of_a_redacted_value(self):
        """Security review: a short secret that the rules redact cannot be recovered by trying candidates against a
        hash the export keeps: the source hash of a redacted file, the draft hash in the row and the record, the
        revision hash of the events built on it, and the content hashes beside a redacted undo record."""
        draft = b"# alarm\nUse the panel.\npassword: 4711\n"
        dh = hashlib.sha256(draft).hexdigest()
        rev = hashlib.sha256(b"revision over " + dh.encode()).hexdigest()
        prev = "password: 1234\n"
        ph = hashlib.sha256(prev.encode()).hexdigest()
        (self.state / "skill-workshop" / "proposals" / "wx-quarantined" / "PROPOSAL.md").write_bytes(draft)
        c = sqlite3.connect(str(self.sdb))
        c.execute("UPDATE skill_workshop_proposals SET draft_hash=?, record_json=json_set(record_json, '$.draftHash', "
                  "?, '$.evaluation', json_object('revisionHash', ?)) WHERE proposal_id='wx-quarantined'",
                  ("sha256:" + dh, dh, rev))
        c.execute("INSERT INTO skill_workshop_proposal_events (event_id, proposal_id, proposed_version, revision_hash, "
                  "event_type, occurred_at, actor_json, payload_json) VALUES ('wx-q-rev', 'wx-quarantined', '2', ?, "
                  "'revised', '2026-10-03T00:00:00Z', '{}', '{}')", (rev,))
        c.execute("UPDATE skill_workshop_proposal_rollbacks SET previous_content=NULL, previous_content_hash=NULL, "
                  "support_files_json=? WHERE proposal_id='wx-applied'",
                  (json.dumps([{"path": "notes.md", "previousContentHash": ph, "previousContent": prev}]),))
        c.commit()
        c.close()
        self.export()
        blob = all_bytes(self.dest)
        for value in (b"4711", b"1234\n", dh.encode(), rev.encode(), ph.encode()):
            self.assertNotIn(value, blob, value)
        doc = json.loads((self.dest / "proposals.json").read_text())
        quar = doc["proposals"][1]
        self.assertEqual((quar["draft_hash"], quar["record_json"]["draftHash"],
                          quar["record_json"]["evaluation"]["revisionHash"]), ("***", "***", "***"))
        self.assertEqual({e["event_id"]: e["revision_hash"] for e in quar["events"]}["wx-q-rev"], "***")
        self.assertEqual(doc["proposals"][2]["rollback"]["support_files_json"],
                         [{"path": "notes.md", "previousContentHash": "***", "previousContent": "password: ***\n"}])
        f = next(x for x in quar["files"] if x["path"] == "proposals/wx-quarantined/PROPOSAL.md")
        self.assertNotIn("sha256_source", f)
        self.assertEqual((self.dest / "files" / "proposals" / "wx-quarantined" / "PROPOSAL.md").read_text(),
                         "# alarm\nUse the panel.\npassword: ***\n")

    def test_target_hashes_of_a_redacted_undo_record_are_hidden(self):
        """Recheck: an applied update's record keeps the sha256 of the skill and support files it replaced
        (target.currentContentHash, supportFiles[].targetContentHash; OpenClaw applies only while they match), and its
        evaluation the same hash and the tree hash of the skill. That content is the undo record's previous content:
        once it is redacted these hashes, in the proposal's own rows, in another proposal for the same skill or
        wherever else the same sha256 is kept, would confirm a guess of the hidden value offline."""
        def sha(text):
            return hashlib.sha256(text.encode()).hexdigest()
        prev, sup = "# tram\npassword: 4711\n", "password: 0815\n"
        ph, sh, tree, tree2 = sha(prev), sha(sup), sha("synthetic skill tree"), sha("synthetic skill tree 2")
        tram = "/config/clawd/skills/tram-times/SKILL.md"

        def setup(prev, sup):
            c = sqlite3.connect(str(self.sdb))
            c.execute("UPDATE skill_workshop_proposal_rollbacks SET previous_content=?, previous_content_hash=?, "
                      "support_files_json=? WHERE proposal_id='wx-applied'",
                      (prev, sha(prev), json.dumps([{"path": "notes.md", "existed": True,
                                                     "previousContentHash": sha(sup), "previousContent": sup}])))
            c.execute("UPDATE skill_workshop_proposals SET record_json=json_set(record_json, "
                      "'$.target.currentContentHash', ?, '$.supportFiles', json(?)) WHERE proposal_id='wx-applied'",
                      (sha(prev), json.dumps([{"path": "notes.md", "hash": "cd" * 32, "targetContentHash": sha(sup)}])))
            c.execute("UPDATE skill_workshop_proposal_events SET payload_json=? WHERE event_id='wx-applied-ev1'",
                      (json.dumps({"outcome": {"targetCurrentSha256": sha(prev), "targetTreeSha256": tree}}),))
            # another proposal for the same skill, evaluated on another version of it
            c.execute("UPDATE skill_workshop_proposals SET record_json=json_set(record_json, '$.target.skillFile', ?) "
                      "WHERE proposal_id='wx-rejected'", (tram,))
            c.execute("UPDATE skill_workshop_proposal_events SET payload_json=? WHERE event_id='wx-rejected-ev1'",
                      (json.dumps({"outcome": {"targetTreeSha256": tree2}}),))
            # the same sha256 kept by a proposal for another skill
            c.execute("UPDATE skill_workshop_proposals SET record_json=json_set(record_json, "
                      "'$.target.currentContentHash', ?) WHERE proposal_id='wx-stale-01'", (sha(prev),))
            c.commit()
            c.close()

        setup(prev, sup)
        self.export()
        blob = all_bytes(self.dest)
        for value in (b"4711", b"0815", ph.encode(), sh.encode(), tree.encode(), tree2.encode()):
            self.assertNotIn(value, blob, value)
        doc = json.loads((self.dest / "proposals.json").read_text())
        app, rej, stale = doc["proposals"][2], doc["proposals"][3], doc["proposals"][4]
        self.assertEqual(app["rollback"]["previous_content"], "# tram\npassword: ***\n")
        self.assertEqual((app["record_json"]["target"]["currentContentHash"],
                          app["record_json"]["supportFiles"][0]["targetContentHash"]), ("***", "***"))
        ev = {e["event_id"]: e for e in app["events"]}["wx-applied-ev1"]
        self.assertEqual(ev["payload_json"], {"outcome": {"targetCurrentSha256": "***", "targetTreeSha256": "***"}})
        ev = {e["event_id"]: e for e in rej["events"]}["wx-rejected-ev1"]
        self.assertEqual((ev["payload_json"], rej["record_json"]["draftHash"]),
                         ({"outcome": {"targetTreeSha256": "***"}}, "***"))
        self.assertEqual(stale["record_json"]["target"]["currentContentHash"], "***")
        self.assertEqual(stale["record_json"]["draftHash"], DRAFT_HASH)  # another skill: covers nothing redacted
        # an undo record without a secret keeps them: they confirm only what the export shows anyway
        dest2 = self.tmp / "out2" / "skill-workshop"
        dest2.parent.mkdir()
        clean = "# tram\nfirst tram at 5:12\n"
        setup(clean, "no secret here\n")
        G.export_skill_workshop(self.state, dest2, {"run_id": "r2"})
        app = json.loads((dest2 / "proposals.json").read_text())["proposals"][2]
        self.assertEqual((app["record_json"]["target"]["currentContentHash"], app["rollback"]["previous_content_hash"],
                          app["record_json"]["draftHash"]), (sha(clean), sha(clean), DRAFT_HASH))

    def test_redaction_hides_whatever_the_log_rules_hide(self):
        """Security review: per JSON value the export hides at least what the log rules (oc_common.redact_text) hide
        in the JSON text of the same object: *key names (x-api-key, signingKey, hmacKey), a number under a secret
        key, a token under an id key, the formats OpenClaw's literal-secret check knows. Beyond that, an object or
        list under a secret key is hidden whole. Deliberate exceptions: hashes under hash keys with nothing redacted
        beside them, ids under id keys and OpenClaw's own identifiers (sessionKey, origin_session_key, skillKey)."""
        bot = "123456789:" + "AAH" + "x" * 32
        cases = [
            {"headers": {"x-api-key": "hv-0001"}}, {"api-key": "hv-0002"}, {"signingKey": "hv-0003"},
            {"webhook": {"hmacKey": "hv-0004"}}, {"encryptionKey": "hv-0005"}, {"secret": 31415926},
            {"id": bot}, {"chat_id": bot}, {"requestId": "sk-hv0011abcdefghij"}, {"note": "use API key: hv-0012 here"},
            {"evidence": "key AIza" + "B" * 35}, {"slack": "xoxb-1234567890-hv0014abcd"},
            {"evidence": "-----BEGIN PRIVATE KEY-----\nMIIEhv0013+abc/def\nZZ09==\n-----END PRIVATE KEY-----"},
            {"url": "https://user:hv-0015@example.com/x"}, {"password": "hv-0016", "previous_content_hash": "ab" * 32}]
        for x in cases:
            with self.subTest(x=json.dumps(x)[:50]):
                logged = C.redact_text(json.dumps(x))
                out = json.dumps(G._sw_redact(x, "", [0]))
                values, stack = [], [x]
                while stack:
                    v = stack.pop()
                    if isinstance(v, dict):
                        stack += list(v.values())
                    else:
                        values.append(json.dumps(v))
                # every word of a value that the log rules hide is hidden in the export too
                hidden = {w for v in values for w in re.findall(r"[A-Za-z0-9_+/=-]{4,}", v) if w not in logged}
                self.assertTrue(hidden, "the log rules hide something in every case")
                self.assertEqual(sorted(w for w in hidden if w in out), [])
        # stronger than the log rules: an object or list under a secret key is hidden whole
        for x, values in (({"apiKey": {"value": "hv-0006"}}, ["hv-0006"]),
                          ({"credentials": {"user": "hv-0007", "pass": "hv-0008"}}, ["hv-0007", "hv-0008"]),
                          ({"tokens": ["hv-0009", "hv-0010"]}, ["hv-0009", "hv-0010"])):
            with self.subTest(x=json.dumps(x)[:50]):
                counter = [0]
                out = json.dumps(G._sw_redact(x, "", counter))
                self.assertEqual((counter[0], [v for v in values if v in out]), (1, []))
        # what stays readable
        keep = {"id": "weather-brief-" + "a" * 60, "proposal_id": "x" * 121, "origin": {"sessionKey": "agent:main:m"},
                "origin_session_key": "agent:main:m", "target": {"skillKey": "weather-brief"}, "draftHash": "cd" * 32,
                "note": "plain words", "enabled": True, "count": 3, "empty_token": ""}
        counter = [0]
        self.assertEqual(G._sw_redact(keep, "", counter), keep)
        self.assertEqual(counter[0], 0)

    def test_partial_leftover_is_rebuilt_and_a_complete_export_is_never_replaced(self):
        part = Path(str(self.dest) + ".partial")
        (part / "files").mkdir(parents=True)
        (part / "junk").write_text("from an interrupted attempt")
        self.export()
        self.assertFalse(part.exists())
        self.assertFalse((self.dest / "junk").exists())
        with self.assertRaises(OSError):
            self.export()
        self.assertTrue((self.dest / "MANIFEST.json").is_file())

    def test_links_and_large_or_binary_files_are_listed_not_copied(self):
        bundle = self.state / "skill-workshop" / "proposals" / "wx-quarantined"
        (self.state / "openclaw.json").write_text('{"gateway": {"auth": {"token": "SECRET-GATEWAY-TOKEN"}}}')
        os.symlink(self.state / "openclaw.json", bundle / "linked.md")
        (bundle / "big.md").write_text("x" * 2048)
        (bundle / "image.bin").write_bytes(b"\xff\xfe\x00binary")
        with mock.patch.object(G, "SW_FILE_CAP", 1024):
            res = self.export()
        doc = json.loads((self.dest / "proposals.json").read_text())
        om = {o["path"]: o for o in doc["omitted"]}
        self.assertEqual(om["proposals/wx-quarantined/linked.md"]["type"], "symlink")
        self.assertNotIn("sha256", om["proposals/wx-quarantined/linked.md"])
        self.assertEqual(om["proposals/wx-quarantined/big.md"]["size"], 2048)
        self.assertEqual(om["proposals/wx-quarantined/big.md"]["sha256"], hashlib.sha256(b"x" * 2048).hexdigest())
        self.assertIn("binary", om["proposals/wx-quarantined/image.bin"]["omitted"])
        self.assertEqual(res["omitted"], 3)
        self.assertNotIn(b"SECRET-GATEWAY-TOKEN", all_bytes(self.dest))
        self.assertFalse((self.dest / "files" / "proposals" / "wx-quarantined" / "linked.md").exists())
        self.assertFalse((self.dest / "files" / "proposals" / "wx-quarantined" / "big.md").exists())

    def test_write_failure_leaves_no_export(self):
        with mock.patch.object(G.os, "rename", side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                self.export()
        self.assertFalse(self.dest.exists())


# --- gate runs -----------------------------------------------------------------------------------

class GateExportTests(Base):
    def test_bump_exports_all_states_before_doctor_pass_1(self):
        self.bump_1010()
        os.symlink(self.state / "openclaw.json", self.state / "skill-workshop" / "proposals" / "wx-applied" / "x.md")
        self.sw_doctor(**self.step_1010())
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        d = self.export_dir(j)
        doc = json.loads((d / "proposals.json").read_text())
        self.assertEqual(sorted((p["proposal_id"], p["status"]) for p in doc["proposals"]), sorted(
            (p[0], p[2]) for p in FIVE))
        self.assertEqual(doc["counts"]["events"], 10)
        self.assertEqual((doc["openclaw_from"], doc["openclaw_to"]), ("2026.10.4", "2026.10.10"))
        self.assertTrue((d / f"files/proposals/wx-pending/generations/{GEN2}/PROPOSAL.md").is_file())
        self.assertTrue((d / "PROPOSALS.md").is_file())
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        exp = j["skill_workshop"]["export"]
        self.assertTrue(exp["complete"])
        self.assertEqual(exp["dir"], f"runs/{j['run_id']}/skill-workshop")
        self.assertEqual(j["skill_workshop"]["inventory"]["proposals"], 5)
        self.assertNotIn("retained", j["skill_workshop"])
        self.assertNotIn("skill_workshop_proposals", G.table_names(self.sdb))
        lines = self.out.splitlines()

        def at(prefix):
            return next(i for i, x in enumerate(lines) if x.startswith(prefix))
        i_pre = at("[gate] 1/8 info: Skill Workshop proposals: 5 (pending 1, quarantined 1, applied 1, rejected 1, "
                   "stale 1; 10 events, 2 rollback records, 1 collection reviews, 7 files).")
        self.assertIn("OpenClaw 2026.10.10 doctor keeps only the 2 pending/quarantined drafts", lines[i_pre])
        self.assertIn("the gate exports all of them before doctor pass 1 (secrets redacted)", lines[i_pre])
        i_unf = at("WARN [gate] skill workshop: proposal wx-pending has an unfinished apply")
        i_exp = at("[gate] 4/8 skill workshop: exported 5 proposals (all states), 10 events, 2 rollback records, "
                   "1 collection reviews and 7 files (")
        self.assertTrue(lines[i_exp].endswith(f"-> {d}/"))
        i_omit = at("WARN [gate] skill workshop: skill-workshop/proposals/wx-applied/x.md not exported")
        i_doc = at("[gate] 4/8 doctor pass 1 started")
        i_pc = at("[gate] 7/8 postconditions OK:")
        self.assertIn(f"Skill Workshop proposals retired (export runs/{j['run_id']}/skill-workshop)", lines[i_pc])
        i_note = at("[gate] info: doctor: doctor archived 1 pending/quarantined Skill Workshop draft(s)")
        at("[gate] info: doctor: doctor retired the Skill Workshop proposal tables")
        i_fin = at(f"[gate] info: Skill Workshop export of this run: {d}/ (5 proposals, secrets redacted); it is "
                   "kept until you delete it")
        i_done = at("[gate] done: MIGRATED 2026.10.10")
        self.assertLess(i_pre, i_unf)
        self.assertLess(i_unf, i_exp)
        self.assertLess(i_exp, i_omit)
        self.assertLess(i_omit, i_doc)
        self.assertLess(i_doc, i_pc)
        self.assertLess(i_pc, i_note)
        self.assertLess(i_note, i_fin)
        self.assertLess(i_fin, i_done)
        self.assertNotIn("SECRET", self.out)
        self.assertNotIn(SK_SECRET, self.out)
        # status and the cleanup: the export is listed and never deleted
        st = G.status_lines()
        self.assertIn(f"Skill Workshop exports: 1 (newest {d}/, 5 proposals; secrets redacted; kept until you delete "
                      "them)", st)
        finished = G._parse_backup_date(j["finished_at"])
        G.cleanup_pass(now=finished + timedelta(days=30), hours=48, emit=lambda s: None)
        self.assertTrue((d / "MANIFEST.json").is_file())

    def test_write_once_per_run_after_an_interrupted_doctor(self):
        self.bump_1010()
        step = self.step_1010()
        self.sw_doctor(passes=[dict(step, rc=143, box=False, print=[]), step])
        self.assertEqual(self.run_gate(), 20, self.out)
        self.assertEqual(self.journal()["hold"]["code"], "doctor-interrupted")
        d = self.export_dir()
        ino, sha = os.stat(d).st_ino, hashlib.sha256((d / "MANIFEST.json").read_bytes()).hexdigest()
        self.assertEqual(G.retry_cmd([], emit=lambda s: None), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn(f"[gate] 4/8 skill workshop: export of this run already written ({d}/)", self.out)
        self.assertEqual((os.stat(d).st_ino, hashlib.sha256((d / "MANIFEST.json").read_bytes()).hexdigest()),
                         (ino, sha))

    def test_failure_holds_before_doctor_and_accept_continues_without_export(self):
        self.bump_1010()
        self.sw_doctor(require_export=False, **self.step_1010())
        with mock.patch.object(G, "export_skill_workshop", side_effect=OSError(28, "No space left on device")):
            self.assertEqual(self.run_gate(), 20, self.out)
            j = self.journal()
            self.assertEqual((j["hold"]["code"], j["phase"], j["hold"]["acceptable"]),
                             ("skill-workshop-export-failed", "doctor1", True))
            self.assertIn("could not export the Skill Workshop proposals before OpenClaw 2026.10.10 doctor drops "
                          "them: OSError: [Errno 28] No space left on device", self.out)
            self.assertIn("oc-upgrade retry --accept skill-workshop-export-failed", self.out)
            self.assertFalse(j["doctor_started"])
            self.assertIsNone(j.get("first_write_at"))
            self.assertEqual(self.doctor_count(), 0)
            self.assertIn("skill_workshop_proposals", G.table_names(self.sdb))
            G.retry_cmd(["--accept", "skill-workshop-export-failed"], emit=lambda s: None)
            self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("WARN [gate] accepted skill-workshop-export-failed: could not export", self.out)
        self.assertIn("no export: OpenClaw doctor keeps only the pending and quarantined drafts", self.out)
        self.assertFalse(self.export_dir().exists())
        self.assertEqual(self.journal()["skill_workshop"]["export"], {"accepted": True, "error": "OSError"})

    def test_resumed_run_whose_doctor_already_started_exports_before_the_next_pass(self):
        """A run held after doctor started (e.g. by an add-on version without the export) exports on resume."""
        self.bump_1010()
        self.sw_doctor(require_export=False, retire=False, box=False, rc=1, print=["Failing check core/doctor/x"])
        with mock.patch.object(G.Gate, "skill_workshop_export", lambda gate: None):
            self.assertEqual(self.run_gate(), 20, self.out)
        j = self.journal()
        self.assertTrue(j["doctor_started"])
        self.assertEqual(j["hold"]["code"], "doctor-failed")
        self.assertFalse(self.export_dir().exists())
        self.sw_doctor(**self.step_1010())  # refuses to run without an export
        self.assertEqual(G.retry_cmd(["--doctor"], emit=lambda s: None), 0)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertEqual(self.journal()["run_id"], j["run_id"])
        self.assertTrue((self.export_dir() / "MANIFEST.json").is_file())

    def test_no_export_and_no_lines_when_the_storage_is_gone(self):
        T.make_1004_state(self.state)
        c = sqlite3.connect(str(self.sdb))
        for t in SW_TABLES:
            c.execute(f"DROP TABLE {t}")
        c.commit()
        c.close()
        self.write_cfg(self.cfg)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.10.10", 22, 27)
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("skill workshop", self.out.lower())
        self.assertFalse(self.export_dir().exists())
        self.assertNotIn("skill_workshop", self.journal())

    def test_empty_tables_need_no_export(self):
        T.make_1004_state(self.state)  # 10.4 tables without rows; the fake doctor keeps them
        self.write_cfg(self.cfg)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.10.10", 22, 27)
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("skill workshop", self.out.lower())
        self.assertFalse(self.export_dir().exists())

    def test_retained_storage_warns_with_the_export_path(self):
        self.bump_1010()
        self.sw_doctor(retire=False, **self.step_1010(retire=False, print=[
            "No configured agent owns Skill Workshop proposal wx-quarantined; kept "
            f"{self.state}/skill-workshop/proposals/wx-quarantined. To keep it, add its agent back to your config "
            "and rerun openclaw doctor --fix."]))
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        d = self.export_dir(j)
        self.assertIn("WARN [gate] 7/8 doctor kept the Skill Workshop proposal storage (5 proposals, 7 files): OpenClaw "
                      "2026.10.10 ignores it; follow doctor's warning (oc-upgrade log), then oc-upgrade retry --doctor "
                      f"to retire it. This run's export holds every proposal: {d}/", self.out)
        self.assertEqual(j["skill_workshop"]["retained"]["proposals"], 5)
        self.assertIn("WARN [gate] doctor: doctor kept Skill Workshop proposal wx-quarantined: no configured agent "
                      "owns it", self.out)
        self.assertEqual(j["status"], "done")

    def test_readiness_line_and_dry_run(self):
        self.bump_1010()
        lines = []
        self.assertEqual(self.quiet(G.dry_run, emit=lines.append), 0, "\n".join(lines))
        text = "\n".join(lines) + self.out
        self.assertIn("[gate]   skill workshop: 5 proposals (pending 1, quarantined 1, applied 1, rejected 1, stale "
                      "1); OpenClaw 2026.10.10 doctor keeps only the 2 pending/quarantined drafts: the gate exports "
                      "all 5 first (secrets redacted)", text)
        self.assertFalse((self.upg / "gate" / "runs").exists() and any((self.upg / "gate" / "runs").iterdir()))

    def test_2026_10_4_target_is_unchanged(self):
        T.make_1004_state(self.state, s=19, a=24, app="2026.9.9")
        add_sw_content(self.state)
        self.write_cfg(dict(self.cfg, meta={"lastTouchedVersion": "2026.9.9"}))
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.9", "mode": "from-7x"}))
        self.set_runtime("2026.10.4", 20, 24)
        self.hooks()
        lines = []
        self.quiet(G.dry_run, emit=lines.append)
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertNotIn("skill workshop", (self.out + "\n".join(lines)).lower())
        self.assertFalse(self.export_dir().exists())
        self.assertNotIn("skill_workshop", self.journal())
        self.assertIn("skill_workshop_proposals", G.table_names(self.sdb))


    def test_pins_phase_skips_the_approval_policy_pin_on_2026_10_10(self):
        for version, schema, want in (("2026.10.10", (22, 27), None), ("2026.10.4", (20, 24), "pending")):
            with self.subTest(version=version):
                self.set_runtime(version, *schema, doctor=False)
                self.write_cfg({"gateway": {"mode": "local"}, "skills": {"workshop": {}}})
                g = G.Gate(emit=lambda s: None)
                g.pkg = C.runtime_package()
                g.j = {"run_id": "20261104T120000Z-abcdef", "mode": "from-7x"}
                G.ensure_dirs(g.gp)
                _p = g.gp["LEDGER"]
                if _p.exists():
                    _p.unlink()
                g.phase_pins()
                cfg = json.loads((self.state / "openclaw.json").read_text())
                self.assertEqual(cfg["skills"]["workshop"].get("approvalPolicy"), want)
                self.assertEqual(cfg["skills"]["workshop"]["autonomous"]["mode"], "off")

# --- doctor notes, advice --------------------------------------------------------------------------

class DoctorTextTests(unittest.TestCase):
    def test_skill_workshop_notes(self):
        long_root = "/config/.openclaw/agents/main/agent/workshop-skills/.archive/.retired-proposals"
        text = "\n".join([
            "┌  OpenClaw doctor", "│", "◇  Doctor changes ───────────────────────────────────────╮",
            f"│  Exported 2 pending Skill Workshop proposal drafts to {long_root[:40]}  │",
            f"│  {long_root[40:]}/.                                │",
            "│  Retired the Skill Workshop proposal tables.          │",
            "│  Restored /config/clawd/skills/x from the unfinished apply of Skill Workshop proposal wx-pend-1. │",
            "◇  Doctor warnings ──────────────────────────────────────╮",
            "│  No configured agent owns Skill Workshop proposal wx-ghost-1; kept       │",
            "│  /config/.openclaw/skill-workshop/proposals/wx-ghost-1. To keep it, add its agent back. │",
            "│  Skill Workshop proposal wx-nodraft has no draft; kept /x. Copy anything worth keeping.  │",
            "│  Skill Workshop proposal wx-gone-01 has no draft left to export; retired its record.  │",
            "│  Could not export Skill Workshop proposal wx-export-1 to /x: Error: EACCES.  │",
            "│  Could not undo the unfinished apply of Skill Workshop proposal wx-undo-01 in /y: boom. │",
            "│  Skill Workshop proposals changed during export; rerun openclaw doctor --fix.  │",
            "└  Doctor complete."])
        notes = G.doctor_notes(text)
        self.assertEqual(notes, [
            ["info", "doctor archived 2 pending/quarantined Skill Workshop draft(s) in the owner agent's "
                     "workshop-skills/.archive/.retired-proposals/"],
            ["info", "doctor retired the Skill Workshop proposal tables (OpenClaw no longer has the applied, rejected "
                     "and stale proposals, their history and undo records)"],
            ["warn", "doctor put back the pre-apply skill files of Skill Workshop proposal wx-pend-1 (its apply never "
                     "finished)"],
            ["warn", "doctor kept Skill Workshop proposal wx-ghost-1: no configured agent owns it (doctor's warning in "
                     "oc-upgrade log says what to do)"],
            ["warn", "doctor retired the record of Skill Workshop proposal wx-gone-01: its draft was already gone"],
            ["warn", "doctor kept Skill Workshop proposal wx-nodraft: it has no draft (doctor's warning in oc-upgrade "
                     "log says what to do)"],
            ["warn", "doctor could not export Skill Workshop proposal wx-export-1; it kept the proposal storage (see "
                     "oc-upgrade log)"],
            ["warn", "doctor could not undo the unfinished apply of Skill Workshop proposal wx-undo-01; it kept the "
                     "proposal storage (see oc-upgrade log)"],
            ["warn", "doctor did not finish retiring the Skill Workshop proposals (they changed during its export)"]])
        self.assertFalse([n for n in notes if "/config" in n[1]])
        self.assertEqual(G.doctor_notes(text, G._SW_NOTE_RES), notes)
        # these lines never make a doctor HOLD on rc 0
        self.assertIsNone(G.evaluate_doctor(0, text, final=True, retired_warning=True)["code"])

    def test_backup_unverifiable_advice(self):
        adv = G.ADVICE["doctor-backup-unverifiable"]
        self.assertIn("encrypted Home Assistant backup", adv)
        self.assertIn("never copy a .bak or .scoped.bak over a database", adv)
        for marker in ("Cannot verify pre-migration SQLite backup: /x.bak. boom",
                       "Completed pre-migration SQLite backup group is missing: /x.bak."):
            self.assertEqual(G.evaluate_doctor(1, marker)["code"], "doctor-backup-unverifiable")

    def test_copies_text(self):
        self.assertEqual(G.copies_text([]), "no new pre-migration SQLite copy by doctor")
        self.assertEqual(G.copies_text([{"size": 1024, "scope": "full"}]),
                         "1 full pre-migration SQLite copy by doctor, 1.0 KiB")
        self.assertEqual(G.copies_text([{"size": 1024, "scope": "full"}, {"size": 1024, "scope": "scoped"}]),
                         "1 full and 1 table-scoped pre-migration SQLite copies by doctor, 2.0 KiB")


# --- doctor's SQLite copies ----------------------------------------------------------------------------

ID_OLD = "11111111-2222-8333-8444-555555555555"
ID_NEW = "aaaaaaaa-bbbb-8ccc-8ddd-eeeeeeeeeeee"


class DoctorCopiesTests(Base):
    def setUp(self):
        super().setUp()
        T.make_1004_state(self.state)
        self.write_cfg(self.cfg)
        (self.upg / "gate").mkdir(parents=True, exist_ok=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.10.4", "mode": "bump"}))
        self.set_runtime("2026.10.10", 22, 27)
        self.old = self.state / "state" / f"openclaw.sqlite.pre-startup-migration-{ID_OLD}.bak"
        self.old.write_bytes(b"older copy from an earlier run")
        self.full = f"state/openclaw.sqlite.pre-startup-migration-{ID_NEW}.bak"
        self.scoped = f"agents/main/agent/openclaw-agent.sqlite.pre-startup-migration-{ID_NEW}.scoped.bak"
        self.doctor_script(passes=[
            dict(self.step_1010(retire=False), write={self.full: "full copy", self.scoped: "scoped copy"},
                 print=[f"Saved pre-migration SQLite backup: {self.state / self.full}",
                        f"Saved pre-migration SQLite backup: {self.state / self.scoped}"]),
            self.step_1010(retire=False)])
        self.hooks()

    def test_new_copies_counted_per_pass_and_deleted_with_the_run(self):
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertIn("[gate] 4/8 doctor pass 1 rc=0 in", self.out)
        self.assertIn("Doctor complete. (1 full and 1 table-scoped pre-migration SQLite copies by doctor, 20 B; not "
                      "the rollback point)", self.out)
        p1, p2 = j["doctor"][:2]
        self.assertEqual(p1["pre_migration_backups"], [
            {"path": self.scoped, "size": 11, "scope": "scoped"}, {"path": self.full, "size": 9, "scope": "full"}])
        self.assertEqual((p1["pre_migration_backups_older"], p2["pre_migration_backups"]), (1, []))
        self.assertEqual(j["doctor_copies_before"], [C.rel(self.old, self.state)])
        self.assertNotIn("saved another pre-migration SQLite copy", self.out)
        self.assertIn("[gate] info: this run's 1 full and 1 table-scoped pre-migration SQLite copies by doctor, 20 B "
                      "(plaintext, beside the databases; not the rollback point): deleted at the same time", self.out)
        st = G.status_lines()
        line = next(x for x in st if x.startswith("Doctor pre-migration SQLite copies:"))
        self.assertTrue(line.startswith("Doctor pre-migration SQLite copies: 2 full (.bak), 1 table-scoped "
                                        "(.scoped.bak)"), line)
        self.assertIn("not the rollback point", line)
        self.assertIn("restore-migration-backup", line)
        # the cleanup: due gate_cleanup_hours after the run; the older copy is not this run's
        finished = G._parse_backup_date(j["finished_at"])
        lines = []
        self.assertEqual(G.cleanup_pass(now=finished + timedelta(hours=47), hours=48, emit=lines.append), 0)
        self.assertTrue((self.state / self.full).exists())
        self.assertEqual(G.cleanup_pass(now=finished + timedelta(hours=48), hours=48, emit=lines.append), 2)
        self.assertFalse((self.state / self.full).exists() or (self.state / self.scoped).exists())
        self.assertTrue(self.old.exists())
        self.assertTrue(self.sdb.exists())
        self.assertIn(f"[cleanup] run {j['run_id']}: deleted 2 item(s)", "\n".join(lines))

    def test_later_pass_copy_warns(self):
        self.doctor_script(passes=[self.step_1010(retire=False), dict(self.step_1010(retire=False), write={
            self.full: "late copy"})])
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        self.assertIn("(no new pre-migration SQLite copy by doctor)", self.out)
        self.assertIn("WARN [gate] doctor pass 2 saved another pre-migration SQLite copy (doctor's own; not the rollback "
                      "point)", self.out)
        self.assertEqual(self.journal()["doctor"][1]["pre_migration_backups"],
                         [{"path": self.full, "size": 9, "scope": "full"}])

    def test_copies_of_an_earlier_version_run_from_its_log_and_what_is_never_deleted(self):
        """A run of 0.5.94-full1..full4 journaled every copy after pass 1 (no "scope"): the copies of the backup group
        its doctor log says it saved (also when the box wrapped the path) are deleted; other groups, links, paths
        outside the state dir and the databases themselves are not."""
        gp = G.gpaths()
        rid = "20261001T120000Z-abcdef"
        rd = gp["RUNS"] / rid
        rd.mkdir(parents=True)
        made = self.state / "agents" / "main" / "agent" / f"openclaw-agent.sqlite.pre-startup-migration-{ID_NEW}.bak"
        made.write_bytes(b"copy of that run")
        made2 = self.state / "state" / f"openclaw.sqlite.pre-startup-migration-{ID_NEW}.bak"
        made2.write_bytes(b"copy of that run, state")
        outside = self.tmp / f"openclaw.sqlite.pre-startup-migration-{ID_NEW}.bak"
        outside.write_bytes(b"outside")
        link = self.state / "state" / f"other.sqlite.pre-startup-migration-{ID_NEW}.bak"
        os.symlink(self.sdb, link)
        wrapped = str(made)
        (rd / "doctor-pass1.log").write_text("\n".join([
            "┌  OpenClaw doctor", "◇  Doctor changes ──────╮",
            f"\x1b[90m│\x1b[39m  Saved pre-migration SQLite backup: {wrapped[:50]}  │",
            f"│  {wrapped[50:90]}   │", f"│  {wrapped[90:]} │",
            f"│  Reused pre-migration SQLite backup: {made2} │",
            "└  Doctor complete."]) + "\n")
        (rd / "journal.json").write_text(json.dumps({
            "run_id": rid, "status": "done", "finished_at": "2026-10-01T12:00:00Z", "started_at": "2026-10-01T11:00:00Z",
            "doctor": [{"pass": 1, "pre_migration_backups": [{"path": C.rel(self.old, self.state), "size": 30}]}]}))
        self.assertEqual(G.doctor_copy_groups((rd / "doctor-pass1.log").read_text()), {ID_NEW})
        targets = {t[0]: t for t in G.cleanup_targets(gp, G._parse_backup_date("2026-11-01T00:00:00Z"), 48)}
        _rid, _label, _due, paths, kept = targets[rid]
        real = Path(os.path.realpath(self.state))
        self.assertEqual(paths, [real / C.rel(made, self.state), real / C.rel(made2, self.state)])
        self.assertEqual(kept, [])
        lines = []
        self.assertEqual(G.cleanup_pass(now=G._parse_backup_date("2026-11-01T00:00:00Z"), hours=48,
                                        emit=lines.append), 2, lines)
        self.assertFalse(made.exists() or made2.exists())
        for p in (self.old, outside, self.sdb):
            self.assertTrue(p.exists(), p)
        self.assertTrue(os.path.islink(link))

    def test_a_directory_vanishing_during_the_scan_is_skipped(self):
        """The cleanup loop walks the state dir beside the gateway: a directory removed between its parent's listing
        and its own scan (browser profiles, plugin installs) is skipped, and the run's copies are still listed and
        deleted (with Path.rglob the FileNotFoundError left the whole run, captures and archive included, out of
        that cleanup pass)."""
        gp = G.gpaths()
        rid = "20261001T120000Z-abcdef"
        rd = gp["RUNS"] / rid
        rd.mkdir(parents=True)
        made = self.state / "state" / f"openclaw.sqlite.pre-startup-migration-{ID_NEW}.bak"
        made.write_bytes(b"copy of that run")
        (rd / "doctor-pass1.log").write_text(f"Saved pre-migration SQLite backup: {made}\n")
        (rd / "journal.json").write_text(json.dumps({
            "run_id": rid, "status": "done", "finished_at": "2026-10-01T12:00:00Z",
            "started_at": "2026-10-01T11:00:00Z"}))
        (self.state / "browser" / "default" / "user-data" / "Default").mkdir(parents=True)
        real_scandir = os.scandir

        def vanishing(path="."):
            if os.fspath(path).endswith("/user-data"):
                raise FileNotFoundError(2, "No such file or directory", os.fspath(path))
            return real_scandir(path)

        now = G._parse_backup_date("2026-11-01T00:00:00Z")
        with mock.patch("os.scandir", vanishing):
            self.assertEqual(G.doctor_copies(self.state), {C.rel(self.old, self.state): (30, "full"),
                                                           C.rel(made, self.state): (16, "full")})
            targets = {t[0]: t for t in G.cleanup_targets(gp, now, 48)}
            lines = []
            self.assertEqual(G.cleanup_pass(now=now, hours=48, emit=lines.append), 1, lines)
        _rid, _label, _due, paths, kept = targets[rid]
        self.assertEqual((paths, kept), ([Path(os.path.realpath(self.state)) / C.rel(made, self.state)], []))
        self.assertFalse(made.exists())
        self.assertTrue(self.old.exists())

    def test_copies_beside_agent_databases_outside_the_state_dir_are_reported_not_deleted(self):
        """Security review: doctor also saves its full copy beside an agent database outside /config/.openclaw (an
        agent directory registered elsewhere in /config or in /share). The add-on never deletes there: the run
        journals the copies its doctor passes saved there, warns after the pass and at the end, `oc-upgrade status`
        lists them and the cleanup reports them as kept (before, nothing named them and the pass line said "no new
        pre-migration SQLite copy")."""
        ext = self.root / "agents-ext" / "ext" / "agent"
        T.make_1004_agent_db(self.state, "ext", uv=27, app="2026.10.10")
        ext.parent.mkdir(parents=True)
        os.rename(self.state / "agents" / "ext" / "agent", ext)
        os.rmdir(self.state / "agents" / "ext")
        c = sqlite3.connect(str(self.sdb))
        c.execute("INSERT INTO agent_databases VALUES ('ext', ?, 27, 0, NULL)", (str(ext / "openclaw-agent.sqlite"),))
        c.commit()
        c.close()
        real = Path(os.path.realpath(ext))
        older = real / f"openclaw-agent.sqlite.pre-startup-migration-{ID_OLD}.bak"
        older.write_bytes(b"older outside copy")
        made = real / f"openclaw-agent.sqlite.pre-startup-migration-{ID_NEW}.bak"
        self.doctor_script(passes=[
            dict(self.step_1010(retire=False), write={self.full: "full copy", str(made): "outside copy"},
                 print=[f"Saved pre-migration SQLite backup: {self.state / self.full}",
                        f"Saved pre-migration SQLite backup: {made}"]),
            self.step_1010(retire=False)])
        self.hooks()
        self.assertEqual(self.run_gate(), 0, self.out)
        j = self.journal()
        self.assertEqual(j["doctor_copies_outside_before"], [str(older)])
        self.assertEqual(j["doctor"][0]["pre_migration_backups_outside"],
                         [{"path": str(made), "size": 12, "scope": "full"}])
        self.assertNotIn("pre_migration_backups_outside", j["doctor"][1])
        text = (f"1 pre-migration SQLite copy by doctor beside agent databases outside {self.state} (plaintext, not "
                f"the rollback point; the add-on does not delete it): delete it yourself once the update is "
                f"confirmed: {made}")
        self.assertIn(f"WARN [gate] doctor pass 1: {text}", self.out)
        self.assertIn(f"WARN [gate] {text}", self.out.split("[gate] done: MIGRATED")[1])
        st = "\n".join(G.status_lines())
        self.assertIn(f"Doctor pre-migration SQLite copies beside agent databases outside {self.state}: 1, plaintext, "
                      f"not the rollback point; the add-on does not delete them, delete them yourself: {made}", st)
        # the cleanup deletes the copy below the state dir, reports the one outside once and leaves it (and the
        # older one) alone
        finished = G._parse_backup_date(j["finished_at"])
        targets = {t[0]: t for t in G.cleanup_targets(G.gpaths(), finished, 48)}
        self.assertEqual(targets[j["run_id"]][4], [
            (str(made), f"beside an agent database outside {self.state}: not deleted by the add-on, delete it "
                        "yourself")])
        lines = []
        self.assertEqual(G.cleanup_pass(now=finished + timedelta(hours=48), hours=48, emit=lines.append), 1, lines)
        self.assertEqual(G.cleanup_pass(now=finished + timedelta(hours=49), hours=48, emit=lines.append), 0, lines)
        self.assertFalse((self.state / self.full).exists())
        self.assertTrue(made.exists() and older.exists())
        self.assertEqual(sum(f"kept {made}: beside an agent database outside" in x for x in lines), 1, lines)

    def test_safe_delete_refuses_links_and_other_paths(self):
        gp = G.gpaths()
        real = Path(os.path.realpath(self.state))
        (self.state / "agents" / "evil").mkdir(parents=True)
        os.symlink(self.state / "state", self.state / "agents" / "evil" / "agent")
        via_link = real / "agents" / "evil" / "agent" / self.old.name
        with self.assertRaises(OSError):
            G._safe_delete(gp, via_link)
        self.assertTrue(self.old.exists())
        with self.assertRaises(OSError):
            G._safe_delete(gp, real / "state" / "openclaw.sqlite")
        self.assertTrue(self.sdb.exists())
        self.assertEqual(G._safe_delete(gp, real / C.rel(self.old, self.state)), 30)
        self.assertFalse(self.old.exists())


if __name__ == "__main__":
    unittest.main()
