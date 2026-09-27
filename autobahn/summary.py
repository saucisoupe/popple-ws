"""Summarise an Autobahn index.json: counts per verdict, then every case that
is not a plain pass. Exits non-zero if any case failed."""

import collections
import json
import sys

index = json.load(open(sys.argv[1]))
failed = False
for agent, cases in index.items():
    verdicts = collections.Counter(c["behavior"] for c in cases.values())
    closes = collections.Counter(c["behaviorClose"] for c in cases.values())
    print(f"{agent}: {len(cases)} cases")
    print("  behavior:", dict(verdicts))
    print("  close:   ", dict(closes))
    key = lambda k: [int(p) for p in k.split(".")]
    for case in sorted(cases, key=key):
        c = cases[case]
        if c["behavior"] not in ("OK", "INFORMATIONAL") or c["behaviorClose"] not in (
            "OK",
            "INFORMATIONAL",
        ):
            print(f"  {case}: {c['behavior']} / close {c['behaviorClose']}")
        failed |= "FAILED" in (c["behavior"], c["behaviorClose"])
sys.exit(1 if failed else 0)
