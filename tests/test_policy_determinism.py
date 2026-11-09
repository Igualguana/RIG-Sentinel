"""Determinism and rule-order independence."""

import json
import os
import random
import subprocess
import sys
from pathlib import Path

from policy_fixtures import RULE_BLOCKS, baseline_engine, fixed_clock, make_request, policy_text

from rig_sentinel.policy import PolicyEngine, load_policy_text

REQUEST_MATRIX = [
    make_request(),
    make_request(environment="prod"),
    make_request(assurance="asserted"),
    make_request(tool="mcp://helpdesk/tickets.update", operation="database_write"),
    make_request(tool="mcp://mail/send", operation="external_send", resource="email:customer.example.com"),
    make_request(
        tool="mcp://mail/send",
        operation="external_send",
        resource="email:customer.example.com",
        labels=["untrusted_content_present"],
    ),
    make_request(agent="ops-bot", tool="mcp://shell/run", operation="execute", resource="shell:git"),
    make_request(
        agent="build-agent", tool="mcp://fs/write_file", operation="write", resource="fs:/srv/workspace/a"
    ),
    make_request(
        agent="build-agent",
        tool="mcp://fs/write_file",
        operation="delete",
        resource="fs:/srv/workspace/.rig-sentinel/x",
    ),
    make_request(
        agent="research-bot", tool="mcp://web/fetch", operation="network", resource="url:https://docs.example.com/a"
    ),
    make_request(tool="mcp://unknown/tool"),
    make_request(agent=None),
]


def _decisions(engine):
    return [engine.evaluate(request).to_dict() for request in REQUEST_MATRIX]


def test_repeated_evaluation_is_identical():
    engine = baseline_engine()
    first = _decisions(engine)
    for _ in range(5):
        assert _decisions(engine) == first


def test_rule_order_permutations_are_equivalent():
    reference_engine = baseline_engine()
    reference = _decisions(reference_engine)
    rng = random.Random(20261109)
    blocks = list(RULE_BLOCKS)
    for _ in range(200):
        rng.shuffle(blocks)
        engine = PolicyEngine(load_policy_text(policy_text(blocks)), clock=fixed_clock)
        assert engine.policy_sha256 == reference_engine.policy_sha256
        assert _decisions(engine) == reference


def test_independent_engines_agree():
    assert _decisions(baseline_engine()) == _decisions(baseline_engine())


_SCRIPT = """
import json, sys
sys.path.insert(0, sys.argv[1])
from policy_fixtures import baseline_engine
from test_policy_determinism import REQUEST_MATRIX
engine = baseline_engine()
print(json.dumps([engine.evaluate(r).to_dict() for r in REQUEST_MATRIX], sort_keys=True))
"""


def test_decisions_do_not_depend_on_hash_seed():
    tests_dir = str(Path(__file__).resolve().parent)
    outputs = []
    for seed in ("0", "1", "4242"):
        env = dict(os.environ, PYTHONHASHSEED=seed)
        result = subprocess.run(
            [sys.executable, "-c", _SCRIPT, tests_dir],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
            check=True,
        )
        outputs.append(json.loads(result.stdout))
    assert outputs[0] == outputs[1] == outputs[2]
    assert outputs[0] == json.loads(json.dumps(_decisions(baseline_engine()), sort_keys=True))
