#!/usr/bin/env python3
"""Compile geosite source lists without changing their matching semantics."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile


SING_BOX_FIELDS = {
    "domain": "domain_suffix",
    "full": "domain",
    "keyword": "domain_keyword",
    "regexp": "domain_regex",
}
MIHOMO_TYPES = {
    "domain": "DOMAIN-SUFFIX",
    "full": "DOMAIN",
    "keyword": "DOMAIN-KEYWORD",
    "regexp": "DOMAIN-REGEX",
}


def read_rules(path):
    rules = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("//"):
            continue
        # Attributes do not filter the unqualified category. Preserve regex text.
        line = re.split(r"\s+(?:@|//)", line, maxsplit=1)[0].strip()
        kind, separator, value = line.partition(":")
        if not separator:
            kind, value = "domain", line
        value = value.strip()
        if kind not in SING_BOX_FIELDS or not value or re.search(r"\s+&", value):
            raise ValueError(f"{path}:{number}: unsupported or empty rule: {line}")
        rules.append((kind, value))
    return list(dict.fromkeys(rules))


def run_compiler(command):
    result = subprocess.run(command, capture_output=True, text=True)
    # Mihomo can exit successfully after skipping malformed rules.
    output = result.stdout + result.stderr
    if result.returncode or re.search(r"\b(?:warn|warning|error|fatal)\b", output, re.IGNORECASE):
        raise RuntimeError(f"{' '.join(command)}:\n{output}")


def build(data, mihomo_out, sing_box_out):
    categories = sorted(path for path in data.rglob("*") if path.is_file())
    if not categories:
        raise ValueError(f"No categories found in {data}")
    with tempfile.TemporaryDirectory(prefix="geosite-sources-") as temporary:
        temporary = Path(temporary)
        for source in categories:
            rules = read_rules(source)
            category = source.relative_to(data)
            mrs = mihomo_out / f"{category}.mrs"
            classical = mihomo_out / f"{category}.list"
            srs = sing_box_out / f"{category}.srs"
            mrs.parent.mkdir(parents=True, exist_ok=True)
            srs.parent.mkdir(parents=True, exist_ok=True)

            # Classical rules preserve ALL types. MRS only supports domain rules.
            classical.write_text(
                "".join(f"{MIHOMO_TYPES[kind]},{value}\n" for kind, value in rules),
                encoding="utf-8",
            )
            domain_text = temporary / "domains.txt"
            domain_text.write_text(
                "".join(
                    f"{'+.' if kind == 'domain' else ''}{value}\n"
                    for kind, value in rules if kind in ("domain", "full")
                ),
                encoding="utf-8",
            )
            run_compiler([
                "mihomo", "convert-ruleset", "domain", "text", str(domain_text), str(mrs),
            ])

            fields = {}
            for kind, value in rules:
                fields.setdefault(SING_BOX_FIELDS[kind], []).append(value)
            rule_json = temporary / "rules.json"
            rule_json.write_text(json.dumps({
                "version": 3, "rules": [fields] if fields else [],
            }), encoding="utf-8")
            run_compiler([
                "sing-box", "rule-set", "compile", "--output", str(srs), str(rule_json),
            ])
    print(f"Built {len(categories)} categories: Mihomo .mrs + .list and sing-box .srs")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data"))
    parser.add_argument("--mihomo-out", type=Path, required=True)
    parser.add_argument("--sing-box-out", type=Path, required=True)
    args = parser.parse_args()
    build(args.data, args.mihomo_out, args.sing_box_out)


if __name__ == "__main__":
    main()
