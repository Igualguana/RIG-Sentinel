from pathlib import Path

from rig_sentinel.providers import ProviderDetector


def test_detects_real_openai_import() -> None:
    detector = ProviderDetector()

    findings = detector.detect(
        Path("agent.py"),
        Path("agent.py"),
        "from openai import OpenAI\nclient = OpenAI()",
    )

    assert len(findings) == 1
    assert findings[0].provider == "openai"
    assert findings[0].confidence == "HIGH"


def test_does_not_detect_plain_openai_word() -> None:
    detector = ProviderDetector()

    findings = detector.detect(
        Path("notes.txt"),
        Path("notes.txt"),
        'AI_MARKERS = {"openai": ["openai"]}',
    )

    assert findings == []


def test_detects_openai_api_key_as_medium_confidence() -> None:
    detector = ProviderDetector()

    findings = detector.detect(
        Path(".env.example"),
        Path(".env.example"),
        "OPENAI_API_KEY=example",
    )

    assert len(findings) == 1
    assert findings[0].provider == "openai"
    assert findings[0].confidence == "MEDIUM"