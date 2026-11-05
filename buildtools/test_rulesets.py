"""Offline regression checks using the actual Mihomo and sing-box binaries."""

from contextlib import contextmanager
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import unittest
from urllib.request import urlopen

from build_rulesets import build, read_rules


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@contextmanager
def mihomo(root, providers, rules, mixed_port=0):
    controller = free_port()
    config = root / "config.json"
    config.write_text(json.dumps({
        "mixed-port": mixed_port,
        "bind-address": "127.0.0.1",
        "external-controller": f"127.0.0.1:{controller}",
        "mode": "rule",
        "log-level": "info",
        "rule-providers": providers,
        "rules": rules,
    }))
    log = root / "mihomo.log"
    with log.open("w") as output:
        process = subprocess.Popen(
            ["mihomo", "-d", str(root), "-f", str(config)],
            stdout=output, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError(log.read_text())
                try:
                    with urlopen(f"http://127.0.0.1:{controller}/providers/rules", timeout=0.5) as response:
                        loaded = json.load(response)["providers"] or {}
                except OSError:
                    loaded = {}
                if all(
                    loaded.get(name, {}).get("updatedAt")
                    and not loaded[name]["updatedAt"].startswith("0001-")
                    for name in providers
                ):
                    break
                time.sleep(0.02)
            else:
                raise AssertionError(f"Mihomo providers did not load:\n{log.read_text()}")
            yield loaded, log
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


class RulesetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="geosite-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        data = cls.root / "data"
        data.mkdir()
        (data / "fixture").write_text(
            "# All four source types; bare domains must be suffixes.\n"
            "plain.example\n"
            "domain:suffix.example @test\n"
            "full:exact.example\n"
            "keyword:needle\n"
            "regexp:^asset-[0-9]{2,4}\\.example$\n"
        )
        build(data, cls.root / "mihomo", cls.root / "sing-box")

    def test_sing_box_matching(self):
        cases = {
            "plain.example": True,
            "sub.plain.example": True,
            "plain.example.attacker": False,
            "notplain.example": False,
            "sub.suffix.example": True,
            "exact.example": True,
            "sub.exact.example": False,
            "myneedle.example": True,
            "asset-123.example": True,
            "asset-1.example": False,
        }
        for domain, expected in cases.items():
            with self.subTest(domain=domain):
                result = subprocess.run([
                    "sing-box", "rule-set", "match", "--format", "binary",
                    str(self.root / "sing-box/fixture.srs"), domain,
                ], check=True, capture_output=True, text=True)
                self.assertEqual(bool((result.stdout + result.stderr).strip()), expected)

    def test_mihomo_matching(self):
        for extension, behavior, rule_format in [("list", "classical", "text"), ("mrs", "domain", "mrs")]:
            with self.subTest(format=extension), tempfile.TemporaryDirectory(dir=self.root) as temporary:
                root = Path(temporary)
                # Keep provider files inside Mihomo's isolated safe directory.
                provider = root / f"fixture.{extension}"
                provider.write_bytes((self.root / "mihomo" / provider.name).read_bytes())
                port = free_port()
                providers = {"fixture": {
                    "type": "file", "behavior": behavior, "format": rule_format,
                    "path": str(provider),
                }}
                cases = {
                    "plain.example": True,
                    "sub.plain.example": True,
                    "plain.example.attacker": False,
                    "notplain.example": False,
                    "sub.suffix.example": True,
                    "exact.example": True,
                    "sub.exact.example": False,
                    "myneedle.example": extension == "list",
                    "asset-123.example": extension == "list",
                    "asset-1.example": False,
                }
                # Both actions reject locally, so the tests never resolve or dial hosts.
                with mihomo(root, providers, ["RULE-SET,fixture,REJECT", "MATCH,REJECT"], port) as (loaded, log):
                    self.assertEqual(loaded["fixture"]["ruleCount"], 5 if extension == "list" else 3)
                    for domain, expected in cases.items():
                        with self.subTest(domain=domain):
                            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                                connection.sendall(
                                    f"CONNECT {domain}:443 HTTP/1.1\r\nHost: {domain}:443\r\n\r\n".encode()
                                )
                                # Drain the tunnel until rejection completes and is logged.
                                while connection.recv(4096):
                                    pass
                            lines = [line for line in log.read_text().splitlines() if f"--> {domain}:443 " in line]
                            self.assertTrue(lines, log.read_text())
                            self.assertEqual("match RuleSet(fixture)" in lines[-1], expected)

    def test_repository_categories_load(self):
        data = Path(__file__).resolve().parents[1] / "data"
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            root = Path(temporary)
            build(data, root / "mihomo", root / "sing-box")
            providers = {}
            expected_counts = {}
            for source in sorted(data.iterdir()):
                expected_counts[source.name] = len(read_rules(source))
                for extension, behavior, rule_format in [("list", "classical", "text"), ("mrs", "domain", "mrs")]:
                    providers[f"{source.name}-{extension}"] = {
                        "type": "file", "behavior": behavior, "format": rule_format,
                        "path": str(root / "mihomo" / f"{source.name}.{extension}"),
                    }
                subprocess.run([
                    "sing-box", "rule-set", "decompile", "--output", str(root / "decoded.json"),
                    str(root / "sing-box" / f"{source.name}.srs"),
                ], check=True, capture_output=True)
            with mihomo(root, providers, ["MATCH,REJECT"]) as (loaded, log):
                for category, count in expected_counts.items():
                    self.assertEqual(loaded[f"{category}-list"]["ruleCount"], count, category)
                self.assertNotRegex(log.read_text(), r"level=(warning|error|fatal)")

    def test_unsupported_source_fails_instead_of_disappearing(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "bad"
            for rule in ["include:other", "unknown:value", "full:", "example.com &other"]:
                source.write_text(rule)
                with self.subTest(rule=rule), self.assertRaisesRegex(ValueError, "unsupported or empty rule"):
                    read_rules(source)


if __name__ == "__main__":
    unittest.main()
