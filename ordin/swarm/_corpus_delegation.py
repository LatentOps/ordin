"""Original native issuer fixture; it is never production authority or a JSON grant."""

import hashlib
import json
from pathlib import Path

from ordin.assurance import (
    DelegationAuthority,
    DelegationIssuer,
    HostEvidenceSource,
    ProtectedAsset,
    ProtectedProfileSelection,
    RepositoryScope,
    SecurityProfile,
    load_approved_profile,
)
from ordin.runtime_boundary import RuntimeCapabilityBoundary
from ordin.runtime_contract import FilesystemCapability, ToolCapability
from ordin.runtime_observation import RuntimeEvidenceSource

REPOSITORY = RepositoryScope("ordin/swarm-corpus", "synthetic-v1")


class Delegations:
    def __init__(
        self,
        directory: Path,
        *,
        agents=3,
        clock=lambda: 100,
        maximum=None,
        principals=None,
        session_digests=None,
        limits=None,
    ):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        profile = SecurityProfile(
            "swarm-corpus",
            "1",
            REPOSITORY,
            (ProtectedAsset("fixture", "path", "/fixture", "prefix"),),
        )
        path = directory / "profile.json"
        path.write_text(json.dumps(profile.as_dict()), encoding="utf-8")
        path.chmod(0o600)
        self.maximum = maximum or DelegationAuthority(
            RuntimeCapabilityBoundary(
                "fixture-maximum",
                filesystem=(FilesystemCapability("read", "/fixture", "prefix"),),
                tools=(ToolCapability("fixture", None, "read_file"),),
                filesystem_semantics="lexical_prefix",
                runtime_filesystem_guarantees=True,
            )
        )
        selection = ProtectedProfileSelection(
            config_root=directory.resolve(),
            relative_path="profile.json",
            protected_runtime_path="/trusted/swarm-corpus/profile.json",
            repository=REPOSITORY,
            expected_profile_digest=profile.digest,
            expected_file_digest=hashlib.sha256(path.read_bytes()).hexdigest(),
            expected_version="1",
            operator_identity="corpus-operator",
            agent_boundary=self.maximum.capability,
            runtime_source=RuntimeEvidenceSource("fixture", "b" * 64, "corpus-sandbox", "c" * 64),
        )
        self.profile = load_approved_profile(
            selection, current_repository=REPOSITORY, active_runtime_policy_digest="c" * 64
        )
        names = principals or tuple("actor-" + str(i) for i in range(agents))
        if len(names) != agents:
            raise ValueError("fixture source inventory mismatch")
        digests = session_digests or tuple(
            hashlib.sha256(str(i).encode()).hexdigest() for i in range(agents)
        )
        self.sources = tuple(
            HostEvidenceSource(
                names[i],
                REPOSITORY,
                digests[i],
                0,
                "c" * 64,
                self.profile.selection_digest,
            )
            for i in range(agents)
        )
        self.issuer = DelegationIssuer(
            self.sources[0],
            self.profile,
            self.maximum,
            self.maximum,
            clock=clock,
            **({"limits": limits} if limits is not None else {}),
        )
        self.root = self.issuer.authorize_root(
            self.maximum, grant_id="corpus-root", expires_at=clock() + 1000
        )

    def child(self, index=1, *, authority=None, grant_id=None):
        return self.issuer.issue_child(
            self.root,
            self.sources[index],
            authority or self.maximum,
            grant_id=grant_id or "child-" + str(index),
            expires_at=self.root.record.expires_at,
        )
