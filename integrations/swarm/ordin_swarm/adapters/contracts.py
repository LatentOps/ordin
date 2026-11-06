"""Documented SDK pins and truthful adapter coverage inventory."""

from importlib.metadata import PackageNotFoundError, version
from ordin_swarm._reports import checked

PINS = {
    "langgraph": {"langgraph": "1.2.20", "langgraph-prebuilt": "1.1.1", "langchain-core": "1.7.6"},
    "crewai": {"crewai": "1.15.35", "crewai-core": "1.15.35"},
    "autogen": {"autogen-core": "0.7.5"},
    "custom": {},
}


def installed_versions(framework):
    if framework not in PINS:
        raise ValueError("unsupported framework adapter")
    result: dict[str, str | None] = {}
    for distribution in PINS[framework]:
        try:
            result[distribution] = version(distribution)
        except PackageNotFoundError:
            result[distribution] = None
    return result


def require_version(framework):
    actual = installed_versions(framework)
    if actual != PINS[framework]:
        raise ValueError("framework API version has not passed pinned conformance")
    return actual


def coverage(framework, *, installed=False, connected=False):
    actual = installed_versions(framework)
    return checked(
        {
            "schema_version": "ordin.swarm_framework_adapter.v1",
            "framework": framework,
            "versions": actual,
            "tested_versions": PINS[framework],
            "compatible": actual == PINS[framework],
            "installed": installed,
            "connected": connected,
            "upstream_status": "archived"
            if framework == "autogen"
            else "maintained"
            if framework != "custom"
            else "host_owned",
            "mode": "intercept",
            "physical_enforcement": False,
            "execution_authority": False,
            "covered": [
                "bound_synchronous_tool_calls",
                "host_session_identity",
                "exact_arguments",
                "post_tool_outcome",
            ],
            "uncovered": [
                "unwrapped_tools",
                "background_tasks",
                "direct_python_calls",
                "provider_network",
                "native_messages",
                "native_artifact_stores",
                "remote_plugins",
                "async_native_tools",
            ],
            "native_approvals": "unavailable_escalation_refused",
        }
    )
