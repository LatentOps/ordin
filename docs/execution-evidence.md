# Execution capability profiles and observations

Ordin can describe what capabilities a caller-owned runtime should consider granting to an action and can consume caller-supplied observations about previously executed actions. Both surfaces are advisory evidence. Ordin still does not execute actions, configure a sandbox, verify runtime claims, persist history, or contact external services.

## Capability recommendations

Every generic `ActionReview` may include an `ExecutionCapabilityProfile` derived deterministically from the normalized effects and resources Ordin already understands.

```python
from ordin import ActionEnvelope, Ordin

review = Ordin().review_action(
    ActionEnvelope.shell("rm -rf ./build")
)

print(review.capabilities.as_dict())
```

A profile can describe:

- filesystem access: `none`, `read`, `write`, or `unknown`;
- bounded filesystem scopes derived from typed resources;
- network access: `none`, `read`, `write`, or `unknown`;
- bounded network scopes;
- whether privilege escalation appears required;
- whether process/code execution appears required.

The profile is a recommendation to the integrating runtime. It does not grant permissions and does not configure operating-system isolation.

Unknown non-shell actions with no trusted semantics receive `unknown` filesystem/network access rather than an optimistic `none` recommendation.

## Post-action observations

An integrating runtime may explicitly describe what it observed after an earlier action executed:

```python
from ordin import ActionObservation, ObservationHistory, ObservedResource

observations = ObservationHistory(
    observations=(
        ActionObservation(
            action_id="step-17",
            exit_code=0,
            effects=("filesystem.read",),
            resources=(
                ObservedResource(type="path", value="/workspace/config.json"),
            ),
            metadata={"runtime": "local-agent"},
        ),
    )
)
```

Observations are assertions from the caller. Ordin does not independently verify that an observed effect really occurred.

### Identity matching

Observed evidence is accepted only when its `action_id` matches exactly one action in the caller-supplied `ActionHistory`.

Ordin rejects:

- observations without action history;
- observations referring to an unknown action ID;
- an observation attached to an action ID that appears more than once in history;
- duplicate observation IDs.

This prevents runtime evidence from being silently attached to the wrong prior action.

## Predicted versus observed evidence

Temporal review preserves both sources of evidence.

Predicted typed effects remain available as ordinary `effect:*` signals and are also namespaced as:

```text
signal:predicted-effect:filesystem.read
```

Caller-supplied observed effects are added as:

```text
signal:observed-effect:filesystem.read
```

and also contribute the ordinary `effect:filesystem.read` signal so existing temporal rules can conservatively react to newly observed danger.

Exit status observations add:

```text
signal:observed-success
signal:observed-failure
```

Observed evidence is additive. It can strengthen a later review but cannot erase a dangerous effect Ordin predicted earlier. If predicted and observed evidence disagree, both remain available to temporal policy evaluation.

## Reviewing with observations

```python
from ordin import (
    ActionEnvelope,
    ActionHistory,
    ActionObservation,
    ObservationHistory,
    Ordin,
)

prior = ActionEnvelope.shell(
    "git status --short",
    action_id="step-1",
)

history = ActionHistory(actions=(prior,))
observations = ObservationHistory(
    observations=(
        ActionObservation(action_id="step-1", exit_code=0),
    )
)

review = Ordin().review_action(
    ActionEnvelope.shell("git log -1 --oneline"),
    history=history,
    observations=observations,
)
```

`Ordin.review_action()` also accepts schema-valid mappings for both `history` and `observations`.

## Machine contracts

The versioned contracts are:

- `ordin.execution_capabilities.v1`
- `ordin.action_observation.v1`
- `ordin.observation_history.v1`

An `ordin.action_review.v1` response contains a `capabilities` field. It is nullable for compatibility with manually constructed/internal reviews, while the normal Ordin action-review path derives a profile.

## Trust boundary

Treat these layers separately:

```text
proposed action
      |
      v
Ordin predicted semantics
      |
      v
capability recommendation
      |
      v
caller-owned sandbox / runtime
      |
      v
caller-supplied observation
      |
      v
later Ordin temporal review
```

The runtime remains responsible for actual sandbox enforcement, execution, observation collection, approval flow, and persistence.
