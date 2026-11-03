
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rig_sentinel.agents import AgentDetector, AgentFinding
from rig_sentinel.config import ConfigLoader
from rig_sentinel.credential_flow import (
    CredentialFlowAnalyzer,
    CredentialFlowFinding,
)
from rig_sentinel.exposure_report import (
    ExposureReport,
    ExposureReportBuilder,
)
from rig_sentinel.identity import (
    IdentityDetector,
    IdentityFinding,
)
from rig_sentinel.identity_linking import (
    AgentIdentityLink,
    IdentityLinker,
)
from rig_sentinel.least_privilege import (
    LeastPrivilegeAnalyzer,
    LeastPrivilegeFinding,
)
from rig_sentinel.mcp import MCPDetector, MCPFinding
from rig_sentinel.multi_agent_graph import (
    MultiAgentGraphBuilder,
    MultiAgentGraphResult,
)
from rig_sentinel.privilege import (
    PrivilegeAnalyzer,
    PrivilegeFinding,
)
from rig_sentinel.providers import (
    ProviderDetector,
    ProviderFinding,
)
from rig_sentinel.repository import RepositoryWalker
from rig_sentinel.shadow_agents import (
    ShadowAgentAnalyzer,
    ShadowAgentFinding,
)
from rig_sentinel.shared_credentials import (
    SharedCredentialAnalyzer,
    SharedCredentialFinding,
)
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

    shared_credential_findings: tuple[
        SharedCredentialFinding, ...
    ]

    shadow_agent_findings: tuple[
        ShadowAgentFinding, ...
    ]

    multi_agent_graph: MultiAgentGraphResult

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
    def shared_credential_finding_count(self) -> int:
        return len(self.shared_credential_findings)

    @property
    def shadow_agent_finding_count(self) -> int:
        return len(self.shadow_agent_findings)

    @property
    def multi_agent_node_count(self) -> int:
        return self.multi_agent_graph.node_count

    @property
    def multi_agent_edge_count(self) -> int:
        return self.multi_agent_graph.edge_count

    @property
    def shared_identity_relation_count(self) -> int:
        return self.multi_agent_graph.shared_identity_count

    @property
    def agent_count(self) -> int:
        return len(self.agents)


class RepositoryScanner:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

        # Repository and configuration
        self.walker = RepositoryWalker(self.root)
        self.config_loader = ConfigLoader()

        # Discovery
        self.provider_detector = ProviderDetector()
        self.mcp_detector = MCPDetector()
        self.tool_detector = ToolDetector()
        self.identity_detector = IdentityDetector()
        self.agent_detector = AgentDetector()

        # Identity and credential intelligence
        self.identity_linker = IdentityLinker()
        self.credential_flow_analyzer = CredentialFlowAnalyzer()

        # Privilege and risk analysis
        self.privilege_analyzer = PrivilegeAnalyzer()
        self.least_privilege_analyzer = LeastPrivilegeAnalyzer()
        self.shared_credential_analyzer = SharedCredentialAnalyzer()
        self.shadow_agent_analyzer = ShadowAgentAnalyzer()

        # Multi-agent graph
        self.multi_agent_graph_builder = MultiAgentGraphBuilder()

        # Exposure analysis
        self.exposure_builder = ExposureReportBuilder()

    def scan(self) -> ScanReport:
        providers: list[ProviderFinding] = []
        mcp_findings: list[MCPFinding] = []
        tools: list[ToolFinding] = []
        identities: list[IdentityFinding] = []
        credential_flows: list[CredentialFlowFinding] = []

        files_scanned = 0

        # --------------------------------------------------
        # 1. Repository discovery
        # --------------------------------------------------

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

        # --------------------------------------------------
        # 2. Deduplicate discovery results
        # --------------------------------------------------

        providers = self._unique(providers)
        mcp_findings = self._unique(mcp_findings)
        tools = self._unique(tools)
        identities = self._unique(identities)
        credential_flows = self._unique(credential_flows)

        # --------------------------------------------------
        # 3. Agent discovery
        # --------------------------------------------------

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
        agents_tuple = tuple(agents)

        # --------------------------------------------------
        # 4. Approved inventory
        # --------------------------------------------------

        config = self.config_loader.load(self.root)

        # --------------------------------------------------
        # 5. Identity linking
        # --------------------------------------------------

        identity_links = self.identity_linker.link(
            agents_tuple,
            tuple(identities),
        )

        credential_flows_tuple = tuple(credential_flows)

        # --------------------------------------------------
        # 6. Credential and privilege analysis
        # --------------------------------------------------

        privilege_findings = self.privilege_analyzer.analyze(
            agents_tuple,
            identity_links,
            credential_flows_tuple,
        )

        least_privilege_findings = (
            self.least_privilege_analyzer.analyze(
                credential_flows_tuple,
                privilege_findings,
            )
        )

        # --------------------------------------------------
        # 7. Shared credentials
        # --------------------------------------------------

        shared_credential_findings = (
            self.shared_credential_analyzer.analyze(
                identity_links,
            )
        )

        # --------------------------------------------------
        # 8. Shadow agent detection
        # --------------------------------------------------

        shadow_agent_findings = (
            self.shadow_agent_analyzer.analyze(
                agents_tuple,
                config.approved_agents,
            )
        )

        # --------------------------------------------------
        # 9. Multi-Agent Graph
        # --------------------------------------------------

        multi_agent_graph = (
            self.multi_agent_graph_builder.build(
                agents_tuple,
                identity_links,
            )
        )

        # --------------------------------------------------
        # 10. Exposure analysis
        # --------------------------------------------------

        exposure = self.exposure_builder.build(
            agents_tuple
        )

        # --------------------------------------------------
        # 11. Final report
        # --------------------------------------------------

        return ScanReport(
            root=str(self.root),
            files_scanned=files_scanned,
            providers=tuple(providers),
            mcp_findings=tuple(mcp_findings),
            tools=tuple(tools),
            identities=tuple(identities),
            identity_links=identity_links,
            credential_flows=credential_flows_tuple,
            privilege_findings=privilege_findings,
            least_privilege_findings=least_privilege_findings,
            shared_credential_findings=shared_credential_findings,
            shadow_agent_findings=shadow_agent_findings,
            multi_agent_graph=multi_agent_graph,
            agents=agents_tuple,
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
