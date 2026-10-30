from pathlib import Path

from rig_sentinel.config import (
    ConfigLoader,
    SentinelConfig,
)


def test_missing_config_returns_empty_config(
    tmp_path: Path,
) -> None:
    loader = ConfigLoader()

    config = loader.load(tmp_path)

    assert config == SentinelConfig()
    assert config.approved_agents == ()


def test_loads_approved_agents(
    tmp_path: Path,
) -> None:
    config_file = tmp_path / ".rig-sentinel.toml"

    config_file.write_text(
        """
approved_agents = [
    "billing_agent",
    "support_agent",
]
""",
        encoding="utf-8",
    )

    loader = ConfigLoader()

    config = loader.load(tmp_path)

    assert config.approved_agents == (
        "billing_agent",
        "support_agent",
    )


def test_invalid_config_does_not_crash(
    tmp_path: Path,
) -> None:
    config_file = tmp_path / ".rig-sentinel.toml"

    config_file.write_text(
        """
approved_agents = [
    this is invalid toml
""",
        encoding="utf-8",
    )

    loader = ConfigLoader()

    config = loader.load(tmp_path)

    assert config.approved_agents == ()


def test_removes_duplicate_and_empty_agent_names(
    tmp_path: Path,
) -> None:
    config_file = tmp_path / ".rig-sentinel.toml"

    config_file.write_text(
        """
approved_agents = [
    "agent",
    "agent",
    "",
    "  support_agent  ",
]
""",
        encoding="utf-8",
    )

    loader = ConfigLoader()

    config = loader.load(tmp_path)

    assert config.approved_agents == (
        "agent",
        "support_agent",
    )