"""Coordinator previews retain original credential proof before governed broker admission."""

from copy import copy
from dataclasses import replace
import json

import pytest

from tests.test_swarm_approval import configured
from tests.test_swarm_broker import require_kernel


def test_coordinator_credentialed_https_issues_before_preview_and_returns_fixed_receipt(tmp_path):
    require_kernel()
    from ordin.runtime_contract import CredentialBinding
    from ordin.swarm.owned_tools import OwnedHTTPRoute
    from tests.test_swarm_owned_http import CERTS, endpoint, get_action, request_bytes

    secret = b"governance-private-credential-fixture"
    with endpoint(tls=True, body=b"echo: " + secret) as (url, seen, failures):
        route = OwnedHTTPRoute(
            "private-docs",
            url,
            ("127.0.0.1",),
            ca_file=CERTS / "ca.pem",
            credential_binding=CredentialBinding(
                "fixture-key", "localhost", int(url.split(":")[2].split("/")[0])
            ),
            credential=secret,
            allow_private=True,
        )
        with configured(
            tmp_path, decision="allow", owned_tools=True, http_routes=(route,), physical=True
        ) as data:
            governance, coordinator, scope, channel, lease, grant, _, _, _, native = data
            broker = native[0]
            source = native[16]["sources"]["child"]
            action = get_action(route)
            # No caller or host frontend pre-mints a receipt. The coordinator
            # obtains it from the original registered broker before its preview.
            evaluated = coordinator.evaluate(
                scope, channel, lease, grant, action, idempotency_key="credential-preview"
            )
            uses = broker.review_credential_uses(source, action)
            assert len(uses) == 1
            reservation = coordinator.reserve(
                scope,
                channel,
                lease,
                evaluated.reference,
                action,
                idempotency_key="credential-reserve",
            )
            protected = coordinator._prepared[reservation.reference]
            admitted = broker.authorization_scope(protected.authorization)
            assert admitted.delegation_scope.review_context.credential_uses[0] is uses[0]
            accounting = coordinator.guarded_dispatch(
                scope, broker._broker_channel, reservation.reference
            )
            assert accounting.status == "host_completed", accounting.as_dict()
            actual = coordinator.broker_result(scope, broker._broker_channel, reservation.reference)
            assert (
                actual.physical_enforcement
                and actual.value == b'{"completed":true,"credentialed":true}'
            )
            assert not governance._originals  # Core ALLOW did not borrow a human vote.
            public = (
                json.dumps(actual.as_dict()) + repr(actual) + json.dumps(admitted.plan.as_dict())
            )
            assert secret.decode() not in public and "echo:" not in public
            assert seen == [request_bytes(url, (), secret)] and not failures
            with pytest.raises(ValueError):
                coordinator.evaluate(scope, channel, lease, grant, action, idempotency_key="replay")
            assert len(seen) == 1
            assert not broker.verify_credential_uses(source, action, (copy(uses[0]),))
            wrong = replace(action, parameters={**action.parameters, "url": url + "/different"})
            with pytest.raises(ValueError):
                coordinator.evaluate(
                    scope, channel, lease, grant, wrong, idempotency_key="wrong-route"
                )
            assert len(seen) == 1
