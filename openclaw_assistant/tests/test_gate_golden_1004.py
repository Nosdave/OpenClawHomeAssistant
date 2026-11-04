"""Golden regression test: the gate output on the 2026.10.4 target (full5 prep).

The full5 work adds checks for OpenClaw 2026.10.5+ (retired files, Skill Workshop, held agent stores, cron
accounts) behind oc_common.runtime_caps. On the 2026.10.4 target the gate must keep printing and journaling
exactly what 0.5.94-full4 printed. This test runs a read-only preview (`gate --dry-run`, `oc-upgrade check`), a
bump run (state of 2026.9.9 -> runtime 2026.10.4), `oc-upgrade status`, then a maintenance run
(`oc-upgrade retry --doctor`), and compares every output with tests/fixtures/golden/gate-2026.10.4.txt.
Run ids, timestamps, durations, sizes and the temporary root are replaced by placeholders.

The golden file was captured from the gate code before the full5 hooks existed. A change to it must be a
deliberate, decided 10.4-visible change (named in the CHANGELOG), made in the same commit as the code:
    OC_GATE_GOLDEN_UPDATE=1 python3 -m pytest -q tests/test_gate_golden_1004.py
"""

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
for _p in (str(ADDON), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_gate as G  # noqa: E402
import test_gate as T  # noqa: E402

GOLDEN = TESTS / "fixtures" / "golden" / "gate-2026.10.4.txt"
SCRIPT = ADDON / "oc_upgrade.py"
SECTION_RE = re.compile(r"^### (.+)$", re.M)

CFG = {
    "meta": {"lastTouchedVersion": "2026.9.9"},
    "agents": {"defaults": {"model": {"primary": "vllm/qwen3.5-122b",
                                      "fallbacks": ["openai/gpt-5.5", "anthropic/claude-sonnet-4-6"]},
                            "models": {"vllm/qwen3.5-122b": {}, "openai/gpt-5.5": {"alias": "gpt"},
                                       "anthropic/claude-sonnet-4-6": {}}},
               "list": [{"id": "main", "default": True}]},
    "models": {"providers": {"vllm": {"baseUrl": "http://127.0.0.1:8000/v1", "models": [{"id": "qwen3.5-122b"}]}}},
    "gateway": {"mode": "local", "auth": {"token": "SECRET-GATEWAY-TOKEN"}},
    "channels": {"telegram": {"enabled": True, "botToken": "123456:SECRET-BOT-TOKEN"}},
}

# durations of C.fmt_duration ("0s", "1m05s", "1h00m"), sizes of C.human, ISO times, run ids
_DUR_RE = re.compile(r"\b\d+(?:h\d{2}m|m\d{2}s|s)\b")
_SIZE_RE = re.compile(r"\b\d+(?:\.\d+)? (?:B|KiB|MiB|GiB|TiB)\b")
_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b")
_CHECK_TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC\b")
_RUN_RE = re.compile(r"\b\d{8}T\d{6}Z-[0-9a-f]{6}\b")
_S_MIB_RE = re.compile(r"\bS=\d+ MiB\b")
# journal/marker values that depend on the SQLite page layout, the clock or the file system
_JOURNAL_NUMBERS = {"size", "s_mib", "doctor_pass_seconds", "duration_s", "dev", "ino"}


def parse_golden(text):
    names = SECTION_RE.findall(text)
    bodies = SECTION_RE.split(text)[2::2]
    return dict(zip(names, (b.strip("\n") for b in bodies)))


class Golden1004Tests(T.GateEnv):
    maxDiff = None

    def setUp(self):
        super().setUp()
        self.set_runtime("2026.10.4", 20, 24)
        # the image's build-time record as a 2026.10.4 image writes it (no 2026.10.10 capabilities)
        self.features(cron_refusal=False, cron_doctor_migration=False, retires_skill_proposals=False)
        T.make_1004_state(self.state, s=19, a=24, app="2026.9.9", content=True)
        self.write_cfg(CFG)
        (self.ws / "AGENTS.md").write_text("# agents\n")
        sess = self.state / "agents" / "main" / "sessions"
        sess.mkdir(parents=True)
        (sess / "sessions.json").write_text(json.dumps({
            "agent:main:main": {"sessionId": "s1", "updatedAt": 1, "model": "vllm/qwen3.5-122b"}}))
        (self.upg / "gate").mkdir(parents=True)
        (self.upg / "gate" / "migrated.json").write_text(json.dumps({"runtime": "2026.9.9", "mode": "from-7x"}))
        self.hooks()
        # pass 1 of the bump makes doctor's full pre-migration copy of the state DB; later passes make none
        step = {"state_uv": 20, "agent_uv": 24, "app_version": "2026.10.4", "drop_tables": ["cron_run_logs"],
                "remove": ["identity/device.json"]}
        self.doctor_script(passes=[dict(step, baks=["state/openclaw.sqlite"]), step])
        self.pylib = self.tmp / "pylib"
        self.pylib.mkdir()

    # ----- normalization -----
    def norm(self, text):
        text = text.replace(str(self.tmp), "<TMP>")
        for rx, sub in ((_RUN_RE, "<RUN>"), (_TS_RE, "<TS>"), (_CHECK_TIME_RE, "<TIME>"), (_S_MIB_RE, "S=<N> MiB"),
                        (_SIZE_RE, "<SIZE>"), (_DUR_RE, "<DUR>")):
            text = rx.sub(sub, text)
        return "\n".join(ln.rstrip() for ln in text.strip("\n").splitlines())

    def norm_json(self, obj):
        def walk(x):
            if isinstance(x, dict):
                return {k: ("<N>" if k in _JOURNAL_NUMBERS and isinstance(v, (int, float)) else walk(v))
                        for k, v in x.items()}
            if isinstance(x, list):
                return [walk(v) for v in x]
            return x
        return self.norm(json.dumps(walk(obj), indent=1, ensure_ascii=False))

    # ----- capture -----
    def check_output(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", OC_ADDON_PYLIB=str(self.pylib),
                   OPENCLAW_RUNTIME_VERSION=self.runtime)
        p = subprocess.run([sys.executable, "-B", str(SCRIPT), "check"], capture_output=True, text=True, env=env,
                           timeout=300)
        return f"rc={p.returncode}\n{p.stdout}" + (f"\nstderr:\n{p.stderr}" if p.stderr else "")

    def run_section(self, label, sections):
        rc = self.run_gate()
        self.assertEqual(rc, 0, self.out + self.err)
        j = self.journal()
        sections[f"{label}: gate output"] = self.norm(self.out + (f"\nstderr:\n{self.err}" if self.err else ""))
        sections[f"{label}: events.log"] = self.norm(
            (self.upg / "gate" / "runs" / j["run_id"] / "events.log").read_text(encoding="utf-8"))
        sections[f"{label}: journal"] = self.norm_json(j)
        sections[f"{label}: marker"] = self.norm_json(json.loads((self.upg / "gate" / "migrated.json").read_text()))
        sections[f"{label}: status"] = self.norm("\n".join(G.status_lines()))
        self.assertNotIn("SECRET", self.out)
        return j

    def capture(self):
        sections = {}
        lines = []
        rc = self.quiet(G.dry_run, emit=lines.append)
        sections["dry-run"] = self.norm(f"rc={rc}\n" + "\n".join(lines) + self.out)
        sections["check before the bump"] = self.norm(self.check_output())
        j1 = self.run_section("bump", sections)
        self.assertEqual(j1["mode"], "bump")
        sections["check after the bump"] = self.norm(self.check_output())
        self.assertEqual(G.retry_cmd(["--doctor"], emit=lambda s: None), 0)
        j2 = self.run_section("maintenance", sections)
        self.assertEqual(j2["mode"], "maintenance")
        return sections

    def test_gate_output_on_the_2026_10_4_target_is_unchanged(self):
        got = self.capture()
        if os.environ.get("OC_GATE_GOLDEN_UPDATE") == "1":
            GOLDEN.parent.mkdir(parents=True, exist_ok=True)
            GOLDEN.write_text("\n".join(f"### {k}\n{v}\n" for k, v in got.items()), encoding="utf-8")
        want = parse_golden(GOLDEN.read_text(encoding="utf-8"))
        self.assertEqual(list(got), list(want), "sections of the golden file")
        for name, text in got.items():
            with self.subTest(section=name):
                self.assertEqual(text, want[name])


if __name__ == "__main__":
    unittest.main()
