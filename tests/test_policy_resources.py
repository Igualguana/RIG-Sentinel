import random

import pytest

from rig_sentinel.policy.resources import ResourceError, ResourceKind, parse_resource


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("fs:/srv/data/file.txt", "fs:/srv/data/file.txt"),
        ("fs:/srv/data/", "fs:/srv/data"),
        ("fs:/srv//data/./file", "fs:/srv/data/file"),
        ("fs:/", "fs:/"),
        ("db:helpdesk", "db:helpdesk"),
        ("db:helpdesk/tickets", "db:helpdesk/tickets"),
        ("url:https://Docs.Example.com/guide", "url:https://docs.example.com/guide"),
        ("url:https://docs.example.com", "url:https://docs.example.com/"),
        ("url:https://docs.example.com:443/a", "url:https://docs.example.com/a"),
        ("url:http://docs.example.com:80/a", "url:http://docs.example.com/a"),
        ("url:https://docs.example.com:8443/a", "url:https://docs.example.com:8443/a"),
        ("url:https://10.0.0.1/a", "url:https://10.0.0.1/a"),
        ("url:http://localhost/", "url:http://localhost/"),
        ("shell:git", "shell:git"),
        ("email:Customer.Example.com", "email:customer.example.com"),
        ("secret:vault/app/key", "secret:vault/app/key"),
        ("none:", "none:"),
    ],
)
def test_canonicalization(raw, canonical):
    assert parse_resource(raw).canonical == canonical
    # Canonical forms are fixed points.
    assert parse_resource(canonical).canonical == canonical


@pytest.mark.parametrize(
    "raw",
    [
        "",
        None,
        42,
        "fs",  # no kind separator
        "FS:/srv",  # kind is case-sensitive
        "file:/srv",  # unsupported kind
        "fs:srv/data",  # relative
        "fs://srv/data",  # leading //
        "fs:/srv/data/../etc/passwd",  # traversal
        "fs:/..",
        "fs:/srv\\data",  # backslash
        "fs:/srv/%2e%2e/etc",  # percent-encoding
        "fs:/srv/da ta",  # whitespace
        "fs:/srv/data\x00",  # NUL
        "fs:/srv/data\n",  # newline (log injection)
        "fs:/srv/d\u00e4ta",  # non-ASCII
        "fs:C:/Windows",  # drive letter
        "fs:/srv/file.",  # trailing dot (Windows ambiguity)
        "fs:/srv/*",  # wildcard in a request
        "url:https://user:pw@docs.example.com/",  # credentials
        "url:https://docs.example.com@evil.example.net/",
        "url:https://docs.example.com/a?q=1",  # query
        "url:https://docs.example.com/a#frag",  # fragment
        "url:ftp://docs.example.com/",  # scheme
        "url:HTTPS://docs.example.com/",
        "url:https://docs.example.com:0/",
        "url:https://docs.example.com:65536/",
        "url:https://docs.example.com:/",
        "url:https://docs.example.com:0443/",
        "url:https://1.2.3/",  # ambiguous numeric host
        "url:https://0x7f000001/",  # hex host
        "url:https://docs.example.com./",  # trailing dot
        "url:https://-bad.example.com/",
        "url:https://[::1]/",  # IPv6 not supported in M1
        "url:https://xn--d-1fa.example/" + "a" * 2048,  # too long
        "db:Helpdesk",
        "db:helpdesk/tickets/extra",
        "db:",
        "shell:/bin/sh",
        "shell:git status",
        "shell:",
        "email:10.0.0.1",
        "email:",
        "secret:",
        "secret:Vault",
        "none:x",
    ],
)
def test_rejected_resources(raw):
    with pytest.raises(ResourceError):
        parse_resource(raw)


def test_length_limit():
    ok = "fs:/" + "/".join(["a" * 254] * 8) + "/" + "a" * 4
    assert len(ok) == 2048
    parse_resource(ok)
    with pytest.raises(ResourceError):
        parse_resource(ok + "a")


def test_fs_segment_length_limit():
    parse_resource("fs:/srv/" + "a" * 255)
    with pytest.raises(ResourceError):
        parse_resource("fs:/srv/" + "a" * 256)
    # The segment limit is filesystem-specific; URL paths are not affected.
    parse_resource("url:https://docs.example.com/" + "a" * 300)


def test_kinds_are_typed():
    ref = parse_resource("db:crm/accounts")
    assert ref.kind is ResourceKind.DB
    assert ref.authority == "crm"
    assert ref.segments == ("accounts",)


def test_fuzz_parse_never_raises_unexpected_errors():
    rng = random.Random(20261109)
    alphabet = "fsdburlhtpmaiecne:/.\\%?#@*-_ ~+=,\x00\n\u0430AZ09"
    for _ in range(3000):
        candidate = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40)))
        try:
            ref = parse_resource(candidate)
        except ResourceError:
            continue
        # Anything accepted must canonicalize to a stable, re-parseable form.
        assert parse_resource(ref.canonical) == ref
        assert ".." not in ref.segments
