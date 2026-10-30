from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rig_sentinel.agents import AgentDetector, AgentFinding
from rig_sentinel.credential_flow import (
    CredentialFlowAnalyzer,
    CredentialFlowFinding,
)
from rig_sentinel.exposure_report import (
    ExposureReport,
    ExposureReportBuilder,
)
from rig_sentinel.identity import IdentityDetector, IdentityFinding
from rig_sentinel.identity_linking import (
    AgentIdentityLink,
    IdentityLinker,
)
from rig_sentinel.least_privilege import (
    LeastPrivilegeAnalyzer,
    LeastPrivilegeFinding,
)
from rig_sentinel.mcp import MCPDetector, MCPFinding
from rig_sentinel.privilege import (
    PrivilegeAnalyzer,
    PrivilegeFinding,
)
from rig_sentinel.providers import ProviderDetector, ProviderFinding
from rig_sentinel.repository import RepositoryWalker
from rig_sentinel.tools import ToolDetector, ToolFinding


@dataclass(frozen=True)
class ScanReport:
    root: str
    files_scanned: int
    providers: tuple[ProviderFinding, ...]
    mcp_findings: tuple[MCPFinding, ...]
    tools: tuple[ToolFinding, ...]
    identities: tuple[IdentityFinding, ...]
    identity_links: tuple[AgentIdentityLink, ...]
    credential_flows: tuple[CredentialFlowFinding, ...]
    privilege_findings: tuple[PrivilegeFinding, ...]
    least_privilege_findings: tuple[LeastPrivilegeFinding, ...]
    agents: tuple[AgentFinding, ...]
    exposure: ExposureReport

    @property
    def provider_count(self) -> int:
        return len(self.providers)

    @property
    def mcp_count(self) -> int:
        return len(self.mcp_findings)

    @property
    def tool_count(self) -> int:
        return len(self.tools)

    @property
    def identity_count(self) -> int:
        return len(self.identities)

    @property
    def identity_link_count(self) -> int:
        return len(self.identity_links)

    @property
    def credential_flow_count(self) -> int:
        return len(self.credential_flows)

    @property
    def privilege_finding_count(self) -> int:
        return len(self.privilege_findings)

    @property
    def least_privilege_finding_count(self) -> int:
        return len(self.least_privilege_findings)

    @property
    def agent_count(self) -> int:
        return len(self.agents)


class RepositoryScanner:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

        self.walker = RepositoryWalker(self.root)
        self.provider_detector = ProviderDetector()
        self.mcp_detector = MCPDetector()
        self.tool_detector = ToolDetector()
        self.identity_detector = IdentityDetector()
        self.identity_linker = IdentityLinker()
        self.credential_flow_analyzer = CredentialFlowAnalyzer()
        self.privilege_analyzer = PrivilegeAnalyzer()
        self.least_privilege_analyzer = LeastPrivilegeAnalyzer()
        self.agent_detector = AgentDetector()
        self.exposure_builder = ExposureReportBuilder()

    def scan(self) -> ScanReport:
        providers: list[ProviderFinding] = []
        mcp_findings: list[MCPFinding] = []
        tools: list[ToolFinding] = []
        identities: list[IdentityFinding] = []
        credential_flows: list[CredentialFlowFinding] = []

        files_scanned = 0

        for repository_file in self.walker.walk():
            path = repository_file.path
            relative_path = repository_file.relative_path

            try:
                text = path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
            except OSError:
                continue

            files_scanned += 1

            providers.extend(
                self.provider_detector.detect(
                    path,
                    relative_path,
                    text,
                )
            )

            mcp_findings.extend(
                self.mcp_detector.detect(
                    path,
                    relative_path,
                    text,
                )
            )

            tools.extend(
                self.tool_detector.detect(
                    path,
                    relative_path,
                    text,
                )
            )

            identities.extend(
                self.identity_detector.detect(
                    path,
                    relative_path,
                    text,
                )
            )

            credential_flows.extend(
                self.credential_flow_analyzer.analyze(
                    path,
                    relative_path,
                    text,
                )
            )

        providers = self._unique(providers)
        mcp_findings = self._unique(mcp_findings)
        tools = self._unique(tools)
        identities = self._unique(identities)
        credential_flows = self._unique(credential_flows)

        agents: list[AgentFinding] = []

        candidate_files = (
            {item.file for item in providers}
            | {item.file for item in mcp_findings}
            | {item.file for item in tools}
        )

        for file_name in sorted(candidate_files):
            finding = self.agent_detector.detect(
                Path(file_name),
                tuple(providers),
                tuple(mcp_findings),
                tuple(tools),
            )

            if finding is not None:
                agents.append(finding)

        agents = self._unique(agents)

        identity_links = self.identity_linker.link(
            tuple(agents),
            tuple(identities),
        )

        privilege_findings = self.privilege_analyzer.analyze(
            tuple(agents),
            identity_links,
            tuple(credential_flows),
        )

        least_privilege_findings = (
            self.least_privilege_analyzer.analyze(
                tuple(credential_flows),
                privilege_findings,
            )
        )

        exposure = self.exposure_builder.build(
            tuple(agents)
        )

        return ScanReport(
            root=str(self.root),
            files_scanned=files_scanned,
            providers=tuple(providers),
            mcp_findings=tuple(mcp_findings),
            tools=tuple(tools),
            identities=tuple(identities),
            identity_links=identity_links,
            credential_flows=tuple(credential_flows),
            privilege_findings=privilege_findings,
            least_privilege_findings=least_privilege_findings,
            agents=tuple(agents),
            exposure=exposure,
        )

    @staticmethod
    def _unique(items: list) -> list:
        seen = set()
        result = []

        for item in items:
            if item in seen:
                continue

            seen.add(item)
            result.append(item)

        return result