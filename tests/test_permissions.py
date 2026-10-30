from rig_sentinel.permissions import PermissionInferenceEngine


def test_infers_shell_permission() -> None:
    engine = PermissionInferenceEngine()

    result = engine.infer("shell")

    assert result is not None
    assert result.tool.name == "shell"

    permission = result.tool.permissions[0]

    assert permission.name == "system.execute"
    assert permission.action == "execute"
    assert permission.resource == "host_system"
    assert permission.risk == "CRITICAL"

    assert result.resources[0].name == "host_system"


def test_infers_email_send_permission() -> None:
    engine = PermissionInferenceEngine()

    result = engine.infer("email_send")

    assert result is not None

    permission = result.tool.permissions[0]

    assert permission.name == "email.send_external"
    assert permission.resource == "external_email"
    assert permission.risk == "HIGH"


def test_infers_financial_permission() -> None:
    engine = PermissionInferenceEngine()

    result = engine.infer("financial_action")

    assert result is not None

    permission = result.tool.permissions[0]

    assert permission.name == "payments.modify"
    assert permission.resource == "payments"
    assert permission.risk == "CRITICAL"


def test_unknown_tool_returns_none() -> None:
    engine = PermissionInferenceEngine()

    result = engine.infer("unknown_tool")

    assert result is None


def test_infer_many_tools() -> None:
    engine = PermissionInferenceEngine()

    results = engine.infer_many(
        (
            "shell",
            "http_request",
            "email_send",
            "financial_action",
        )
    )

    assert len(results) == 4

    tool_names = {
        result.tool.name
        for result in results
    }

    assert tool_names == {
        "shell",
        "http_request",
        "email_send",
        "financial_action",
    }