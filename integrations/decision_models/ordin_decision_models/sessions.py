"""Host-side async dispatch for providers with one-use, input-bound consent."""

from .protocol import ProviderDescriptor, check_evidence, evidence


class AsyncProviderSessions:
    """Create a scoped provider only after the router decides inference is needed.

    The async host factory receives sanitized state/questions, never workload
    labels. It can review disclosure and issue a fresh protected receipt. The
    resulting provider receives no host source, profile or issuance interface.
    The caller's router bounds the complete factory plus inference deadline.
    """

    def __init__(self, descriptor: ProviderDescriptor, factory):
        if not isinstance(descriptor, ProviderDescriptor) or not callable(factory):
            raise ValueError("provider sessions require a pinned descriptor and async host factory")
        self._descriptor, self._factory = descriptor, factory

    @property
    def descriptor(self):
        return self._descriptor

    async def evaluate_async(self, state, questions, *, deadline_ms):
        provider = await self._factory(state, questions)
        if getattr(provider, "descriptor", None) != self.descriptor or not callable(
            getattr(provider, "evaluate_async", None)
        ):
            return evidence(self.descriptor, state, questions, error_class="version_mismatch")
        value = await provider.evaluate_async(state, questions, deadline_ms=deadline_ms)
        return check_evidence(value, self.descriptor, state, questions)
