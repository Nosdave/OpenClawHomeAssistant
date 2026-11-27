"""Security review of the 2026.11.1 port (redaction and reporting). Synthetic data only.

- Log redaction: "pass" after another word ("smtp pass: x", "user=bob pass=x") except OpenClaw's own "<word> pass:"
  texts; a password word, a verb and a colon ("Das Passwort lautet: Sommer 2024") hide the whole value; private,
  secret, access, signing, encryption, master and client key names (AWS_SECRET_ACCESS_KEY: x, PrivateKey = x); a
  URL with an empty user (redis://:password@host); "Authorization: <any scheme> <credentials>"; a YAML block scalar
  under a secret key; YAML's '' inside a single-quoted value; the PEM rule in linear time.
- The add-on log's [doctor] lines and `oc-upgrade log` arrive line by line: oc_common.LineRedactor keeps what spans
  lines (a PEM block, a block scalar, a value alone on the next line).
- Doctor snippets in HOLD texts are redacted before the cut.
- Cron report: agent ids normalised as OpenClaw does ("Haus Agent" -> "haus-agent"); job names redacted.
"""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ADDON = TESTS.parent
for _p in (str(ADDON), str(TESTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import oc_common as C  # noqa: E402
import oc_gate as G  # noqa: E402
import oc_migrate as M  # noqa: E402
import test_gate as T  # noqa: E402
import test_gate_cron_binding as CB  # noqa: E402
import test_gate_rehearsal_reporting as RR  # noqa: E402

PEM_BODY = ("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7",
            "MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu")


class RedactionRuleTests(unittest.TestCase):
    def check(self, cases):
        for line, want in cases:
            with self.subTest(line=line):
                self.assertEqual(C.redact_text(line), want)

    def test_pass_after_a_word(self):
        self.check([("user=bob pass=abc def", "user=bob pass=***"),
                    ("Login admin pass: 1234", "Login admin pass: ***"),
                    ("smtp pass: Sommer2024", "smtp pass: ***"),
                    ("Router: user admin pass: Gartenhaus 7", "Router: user admin pass: ***")])
        # OpenClaw's own "<word> pass:" texts (2026.10.4 to 2026.11.1) and the gate's stay readable
        for line in ("before_agent_finalize requested one more pass: runId=1 attempt=2",
                     "True iff we are running the post-core convergence pass: the core package",
                     "Observe when a pre-stop replacement drain would pass: no retained work",
                     "Hold the frame under a held pass: every computed in the list", "First pass: collect data",
                     "doctor pass: 2", "One deletion pass: everything whose due time has passed"):
            with self.subTest(line=line):
                self.assertEqual(C.redact_text(line), line)
        self.assertIsNone(C.SECRET_NAME_RE.fullmatch("first pass"))

    def test_verb_and_colon_hide_the_whole_value(self):
        self.check([("Das Passwort lautet: Sommer 2024", "Das Passwort lautet: ***"),
                    ("Das WLAN-Kennwort heißt: Gartenhaus Nord.", "Das WLAN-Kennwort heißt: ***."),
                    ("the password is: correct horse battery", "the password is: ***"),
                    # without the colon only a quoted value or one word with a digit (unchanged)
                    ("Das Passwort ist 4711 und gilt", "Das Passwort ist *** und gilt"),
                    ("password is configured.", "password is configured.")])

    def test_key_names_that_end_in_key(self):
        self.check([("AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AWS_SECRET_ACCESS_KEY: ***"),
                    ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG+bPxRfi", "aws_secret_access_key = ***"),
                    ("secret_key: abc def", "secret_key: ***"), ("private_key: abc def", "private_key: ***"),
                    ("PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=", "PrivateKey = ***"),
                    ('  signing_key: "abc def"', '  signing_key: "***"'), ("master key: Gx7 hunter", "master key: ***")])
        for line in ("publicKey: AAAAC3Nza", "sessionKey: agent:main:main", "skillKey: weather-brief", "monkey: x",
                     "cache key: models/list"):
            with self.subTest(line=line):
                self.assertEqual(C.redact_text(line), line)

    def test_url_with_an_empty_user_and_authorization_schemes(self):
        self.check([("redis://:s3cretPass@redis.local:6379/0", "redis://***@redis.local:6379/0"),
                    ("redis://default:s3cretPass@redis.local", "redis://***@redis.local"),
                    ("Authorization: Token abc123def456", "Authorization: Token ***"),
                    ("Authorization: Bot MTk4NjIy.GxYz12.abcdefghij", "Authorization: Bot ***"),
                    ('"authorization": "Bot abc.def.ghijk",', '"authorization": "Bot ***",'),
                    ("Proxy-Authorization: Token abcdefgh1234", "Proxy-Authorization: Token ***"),
                    ("Authorization: Bearer abcdefghijk", "Authorization: Bearer ***")])
        for line in ("http://host:8080/path@x", "https://example.com:443/", "Authorization: required",
                     "authorization: missing header"):
            with self.subTest(line=line):
                self.assertEqual(C.redact_text(line), line)

    def test_yaml_block_scalar_and_doubled_quote(self):
        self.check([("password: |\n  correct horse\n  battery staple\nuser: bob", "password: ***\nuser: bob"),
                    ("  private_key: >-\n    MIIab+/c\n\n    def/+g\n  next: 1", "  private_key: ***\n  next: 1"),
                    ("- token: |2\n   abc def\n- name: x", "- token: ***\n- name: x"),
                    ("password: 'it''s secret' # home", "password: '***' # home")])
        for text in ("description: |\n  plain text\n  more\n", "notes: >\n  password is configured\n"):
            with self.subTest(text=text):
                self.assertEqual(C.redact_text(text), text)

    def test_pem_rule_is_linear(self):
        """Each BEGIN without its END line read to the end of the text: 232 kB took about 7 s, 16 MiB hours."""
        s = "-----BEGIN PRIVATE KEY-----\n-" * 8000  # 232 kB
        t = time.monotonic()
        C.redact_text_counted(s)
        self.assertLess(time.monotonic() - t, 2.0)
        body = "\n".join(PEM_BODY)
        self.check([(f"a -----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY----- b",
                     "a -----BEGIN PRIVATE KEY-----***-----END PRIVATE KEY----- b"),
                    (f"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n\n{body}\n-----END RSA PRIVATE KEY-----",
                     "-----BEGIN RSA PRIVATE KEY-----***-----END RSA PRIVATE KEY-----"),
                    (f"-----BEGIN PRIVATE KEY-----\n{body}\n", "-----BEGIN PRIVATE KEY-----***")])
        nested = f"-----BEGIN PRIVATE KEY-----\n{PEM_BODY[0]}\n-----BEGIN PRIVATE KEY-----\n{PEM_BODY[1]}\n" \
                 "-----END PRIVATE KEY-----"
        out = C.redact_text(nested)
        self.assertFalse([b for b in PEM_BODY if b in out], out)

    def test_new_rules_are_linear(self):
        n = 8000
        for s in ("password: |\n" + "  a b\n" * n, "  pass: |\n   a\n" * n, "Authorization: X " * n,
                  "redis://:" * n, "x lautet: " * n, "AWS_SECRET_ACCESS_KEY " * n):
            with self.subTest(s=s[:16]):
                t = time.monotonic()
                C.redact_text_counted(s)
                self.assertLess(time.monotonic() - t, 2.0)


DOCTOR_LOG = ["Doctor output", "  password:", "    Sommer2024-Gartenhaus", "-----BEGIN PRIVATE KEY-----", *PEM_BODY,
              "-----END PRIVATE KEY----- token=abc", "config:", "  private_key: |", "    line one secret",
              "    line two secret", "", "  next: ok", "token:", "", "value after a blank line", "first pass:",
              "collect", "done"]
DOCTOR_LOG_SHOWN = ["Doctor output", "  password:", "    ***", "-----BEGIN PRIVATE KEY-----***", "***", "***",
                    "-----END PRIVATE KEY----- token=***", "config:", "  private_key: ***", "    ***", "    ***", "",
                    "  next: ok", "token:", "", "value after a blank line", "first pass:", "collect", "done"]
SECRETS = ("Sommer2024-Gartenhaus", "line one secret", "line two secret", *PEM_BODY, "token=abc")


class LineRedactorTests(unittest.TestCase):
    def test_rules_that_span_lines(self):
        r = C.LineRedactor()
        self.assertEqual([r.line(x) for x in DOCTOR_LOG], DOCTOR_LOG_SHOWN)
        # each line alone (before): the value below its key and the key material stayed readable
        alone = "\n".join(C.redact_text(x) for x in DOCTOR_LOG)
        self.assertIn("Sommer2024-Gartenhaus", alone)
        self.assertIn(PEM_BODY[1], alone)
        # the whole text hides the same secrets
        whole = C.redact_text("\n".join(DOCTOR_LOG))
        self.assertEqual([s for s in SECRETS if s in whole], [])

    def test_a_begin_without_end_hides_a_bounded_number_of_lines(self):
        r = C.LineRedactor()
        out = [r.line(x) for x in ["-----BEGIN PRIVATE KEY-----"] + [f"line {i}" for i in range(C._PEM_MAX_LINES + 2)]]
        self.assertEqual(out[1:C._PEM_MAX_LINES + 1], ["***"] * C._PEM_MAX_LINES)
        self.assertEqual(out[-1], f"line {C._PEM_MAX_LINES + 1}")
        # the next line after a key with "Bearer" or a flag at the end
        r = C.LineRedactor()
        self.assertEqual([r.line(x) for x in ("Authorization: Bearer", "abcdefghijklmnop", "--token", "abc", "x")],
                         ["Authorization: Bearer", "***", "--token", "***", "x"])

    def test_log_mirror_keeps_the_state_across_reads(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "doctor-pass1.log"
            shown = []
            mirror = G.LogMirror(log, 0, 100, shown.append, "pass 1")
            text = "\n".join(DOCTOR_LOG) + "\n"
            cut = text.index(PEM_BODY[0]) + 10  # the second read starts inside the PEM body
            log.write_text(text[:cut])
            mirror.pump()
            with open(log, "a") as f:
                f.write(text[cut:])
            mirror.pump(final=True)
        self.assertEqual(shown, [f"[doctor] {x}" for x in DOCTOR_LOG_SHOWN if x.strip()])
        self.assertEqual(mirror.last, "done")


class OcUpgradeLogTests(T.GateEnv):
    def test_the_tail_is_redacted_with_the_lines_above_it(self):
        rid = "20261106T010203Z-abcdef"
        gp = G.gpaths()
        (gp["RUNS"] / rid).mkdir(parents=True)
        (gp["RUNS"] / rid / "doctor-pass1.log").write_text("\n".join(DOCTOR_LOG) + "\n")
        gp["JOURNAL"].write_text(json.dumps({"run_id": rid}))
        out = []
        self.assertEqual(G.log_cmd(["--lines", str(len(DOCTOR_LOG) - 4)], emit=out.append), 0)
        self.assertEqual(out[1:], DOCTOR_LOG_SHOWN[4:])  # the tail starts inside the PEM body
        self.assertIn(f"(last {len(DOCTOR_LOG) - 4} of {len(DOCTOR_LOG)} lines, redacted)", out[0])


class SnippetTests(unittest.TestCase):
    SECRET = "Gx7-hunter2-Sommer24-Gartenhaus-ab"

    def test_a_cut_never_leaves_a_value_without_its_key(self):
        ev = G.evaluate_doctor(1, f"Gateway auth check failed: gateway.auth.token: {self.SECRET} Doctor blocked; "
                                  "required repairs remain incomplete.")
        self.assertEqual(ev["code"], "doctor-blocked")
        self.assertNotIn("hunter2", ev["message"])
        self.assertIn("gateway.auth.token: ***", ev["message"])
        # the doctor-failed fallback (the last 160 characters)
        tail = "ken: " + self.SECRET + " " + " ".join(["word"] * 30)
        ev = G.evaluate_doctor(1, "x " * 300 + "early stop: gateway.auth.to" + tail)
        self.assertEqual(ev["code"], "doctor-failed")
        self.assertNotIn("hunter2", ev["message"])
        # text without secrets: the same cut as before
        norm = "word " * 30 + "MARK" + " text" * 80
        self.assertEqual(G._snippet(norm, 150), norm[110:310])
        # a token on both sides of idx (each side shorter than 40 characters)
        norm = "x " * 50 + "A1b2" * 8 + "C3d4" * 8 + " y" * 50
        self.assertNotIn("C3d4", G._snippet(norm, 132))


class CronAgentIdAndNameTests(RR.Bump1010):
    def test_normalize_agent_id_like_openclaw(self):
        for raw, want in (("main", "main"), ("Ops", "ops"), (" Haus Agent ", "haus-agent"), ("a.b", "a-b"),
                          ("---", "main"), ("", "main"), (None, "main"), ("x" * 70, "x" * 64),
                          ("Ünïcode Agent", "n-code-agent"), ("mail_bot-2", "mail_bot-2")):
            with self.subTest(raw=raw):
                self.assertEqual(M.normalize_agent_id(raw), want)

    def test_jobs_of_an_agent_id_that_is_not_canonical(self):
        CB.add_jobs(self.state, [
            ("job-haus", {"agentId": "haus-agent", "sessionTarget": "isolated",
                          "payload": {"kind": "agentTurn", "message": CB.PROMPT, "model": "openai/gpt-5.5"}}),
            ("job-haus-chain", {"sessionKey": "agent:Haus Agent:cron:x", "sessionTarget": "isolated",
                                "payload": {"kind": "agentTurn", "message": CB.PROMPT}})], start=40)
        cfg = json.loads(json.dumps(RR.CFG))
        cfg["agents"]["list"].append({"id": "Haus Agent", "model": {"primary": "openai/gpt-5.5", "fallbacks": []}})
        rec = G.cron_account_report(self.state, cfg, "2026.10.10")
        self.assertNotIn("unconfigured", rec)
        got = {a["id"]: (a["agent"], a["primary"], a["primary_affected"]) for a in rec["affected"]}
        self.assertEqual(got["job-haus"], ("haus-agent", "openai/gpt-5.5", True))
        # the agent's own model chain (before: the defaults' chain, vllm first)
        self.assertEqual(got["job-haus-chain"], ("haus-agent", "openai/gpt-5.5", True))
        self.assertEqual(rec["checked"], 4)
        # not configured at all: still left out
        rec = G.cron_account_report(self.state, RR.CFG, "2026.10.10")
        self.assertEqual([a["agent"] for a in rec["unconfigured"]], ["haus-agent", "haus-agent"])

    def test_job_names_are_redacted(self):
        CB.add_jobs(self.state, [
            ("job-router", {"name": "Router Passwort: Sommer2024", "agentId": "main", "sessionTarget": "isolated",
                            "payload": {"kind": "agentTurn", "message": CB.PROMPT, "model": "openai/gpt-5.5"}}),
            ("job-old", {"name": "WLAN pass: Gartenhaus7", "agentId": "oldbot", "sessionTarget": "isolated",
                         "payload": {"kind": "agentTurn", "message": CB.PROMPT}})], start=40)
        rec = G.cron_account_report(self.state, RR.CFG, "2026.10.10")
        self.assertIn("Router Passwort: ***", [a["name"] for a in rec["affected"]])
        self.assertEqual([a["name"] for a in rec["unconfigured"]], ["WLAN pass: ***"])
        lines = "\n".join(G.cron_job_lines(rec) + [G.cron_unconfigured_line(rec)])
        self.assertIn("cron job 'Router Passwort: ***' (job-router): ", lines)
        self.assertIn("'WLAN pass: ***' (job-old)", lines)
        # a record of an earlier add-on version kept the name as stored: redacted when shown
        self.assertEqual(G.cron_job_label({"name": "Router Passwort: Sommer2024", "id": "job-router"}),
                         "'Router Passwort: ***' (job-router)")
        self.assertEqual(self.run_gate(), 0, self.out)
        for where in (self.out, json.dumps(self.journal()), "\n".join(G.status_lines())):
            self.assertNotIn("Sommer2024", where)
            self.assertNotIn("Gartenhaus7", where)
        self.assertIn("Router Passwort: ***", self.out)


if __name__ == "__main__":
    unittest.main()
