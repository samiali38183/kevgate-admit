"""Regenerate internal/risk/testdata/parity_vectors.json from the Python kevgate formula.

Usage: python scripts/gen_parity.py <path to kevgate/src> > internal/risk/testdata/parity_vectors.json

The vectors are the reference answers for TestParityWithPythonKevgate. They are
a grid over typical values plus a fixed-seed random sample.
"""
import itertools
import json
import random
import sys

sys.path.insert(0, sys.argv[1])
from kevgate.scoring import risk_score  # noqa: E402

vectors = []
cvss_v = [0.0, 1.5, 3.1, 4.9, 5.0, 6.1, 7.5, 8.8, 9.8, 10.0]
epss_v = [0.0, 0.001, 0.02, 0.25, 0.5, 0.97, 1.0]
for cvss, epss, acr, kev in itertools.product(cvss_v, epss_v, [1, 3, 4, 6, 8], [False, True]):
    vectors.append((cvss, epss, acr, kev))
rng = random.Random(20261110)
for _ in range(300):
    vectors.append((round(rng.uniform(0, 10), 1), round(rng.uniform(0, 1), 5), rng.randint(1, 8), rng.random() < 0.3))

out = [
    {"cvss": c, "epss": e, "acr": a, "kev": k, "risk": risk_score(c, e, a, k)}
    for c, e, a, k in vectors
]
json.dump(out, sys.stdout, separators=(",", ":"))
