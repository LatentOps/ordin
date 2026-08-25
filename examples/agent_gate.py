from ordin import AgentGate, ExecutionContext, Ordin, ReviewPolicy


def main() -> None:
    context = ExecutionContext(
        cwd="/workspace/project",
        repo_root="/workspace/project",
        agent="example-agent",
    )
    gate = AgentGate(
        Ordin(
            context=context,
            policy=ReviewPolicy(fail_on="ask"),
        )
    )

    result = gate.evaluate(
        "git status --short",
        intent="inspect repository state",
    )

    print(f"disposition: {result.disposition}")
    print(f"decision: {result.review.decision}")
    for reason in result.review.reasons:
        print(f"- {reason}")

    # Ordin does not execute the command. The caller decides what to do next.
    if result.may_execute:
        print("caller may execute the proposed action")
    elif result.requires_approval:
        print("caller should request approval")
    else:
        print("caller should reject the proposed action")


if __name__ == "__main__":
    main()
