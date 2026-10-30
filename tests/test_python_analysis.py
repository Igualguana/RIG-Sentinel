from rig_sentinel.python_analysis import PythonAnalyzer


def test_detects_real_import() -> None:
    analyzer = PythonAnalyzer()

    result = analyzer.analyze(
        """
from openai import OpenAI
import subprocess
"""
    )

    assert "openai" in result.imports
    assert "subprocess" in result.imports


def test_does_not_treat_string_as_import() -> None:
    analyzer = PythonAnalyzer()

    result = analyzer.analyze(
        """
RULES = [
    "from openai import",
    "import anthropic",
]
"""
    )

    assert "openai" not in result.imports
    assert "anthropic" not in result.imports


def test_detects_real_function_call() -> None:
    analyzer = PythonAnalyzer()

    result = analyzer.analyze(
        """
import subprocess

subprocess.run(["whoami"])
"""
    )

    assert "subprocess.run" in result.calls


def test_does_not_treat_string_as_call() -> None:
    analyzer = PythonAnalyzer()

    result = analyzer.analyze(
        """
RULES = [
    "subprocess.run(",
    "requests.post(",
]
"""
    )

    assert "subprocess.run" not in result.calls
    assert "requests.post" not in result.calls


def test_detects_chained_attribute_call() -> None:
    analyzer = PythonAnalyzer()

    result = analyzer.analyze(
        """
stripe.refunds.create()
"""
    )

    assert "stripe.refunds.create" in result.calls


def test_invalid_python_returns_empty_analysis() -> None:
    analyzer = PythonAnalyzer()

    result = analyzer.analyze(
        "this is not valid python !!!"
    )

    assert result.imports == ()
    assert result.calls == ()
    assert result.attributes == ()