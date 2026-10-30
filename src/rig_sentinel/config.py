from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SentinelConfig:
    approved_agents: tuple[str, ...] = ()


class ConfigLoader:
    FILE_NAME = ".rig-sentinel.toml"

    def load(
        self,
        root: Path,
    ) -> SentinelConfig:
        config_path = root / self.FILE_NAME

        if not config_path.exists():
            return SentinelConfig()

        try:
            raw = config_path.read_bytes()
            data = tomllib.loads(
                raw.decode("utf-8")
            )
        except (
            OSError,
            UnicodeDecodeError,
            tomllib.TOMLDecodeError,
        ):
            return SentinelConfig()

        approved_agents = self._approved_agents(
            data
        )

        return SentinelConfig(
            approved_agents=approved_agents,
        )

    @staticmethod
    def _approved_agents(
        data: dict,
    ) -> tuple[str, ...]:
        raw_agents = data.get(
            "approved_agents",
            [],
        )

        if not isinstance(raw_agents, list):
            return ()

        agents: list[str] = []

        for item in raw_agents:
            if not isinstance(item, str):
                continue

            name = item.strip()

            if not name:
                continue

            if name not in agents:
                agents.append(name)

        return tuple(agents)