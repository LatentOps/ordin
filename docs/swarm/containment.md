# Scoped containment and recovery

`SwarmContainmentController` is an opt-in protected host API over the original
`SwarmCoordinator`. Construct it with the coordinator's original control source,
operator capability, `IncidentPolicy` and `IncidentSignalSource`. Reports and
model messages cannot construct these capabilities. Importing the module does
not start a service, change policy or revoke an agent.

An operator signal selects one exact action, agent, delegation subtree, task,
swarm or tenant. Parent containment includes its descendants in blast-radius
accounting. `pause`, `revoke` and `quarantine` first commit a monotonic durable
revocation intent. The native delegation service checks that DB fence during
review and immediately before committing a cached admission, including direct
credential/broker routes. A disconnected authority cannot authorize a new use.

The controller then pauses original registry contexts, requests stopping owned
broker jobs and asynchronously revokes issued grants and registered scoped
credential routes. Queued coordinator reservations are canceled by the durable
fence. The worker does not hold controller or DB locks while waiting for an
in-flight issuer/credential operation. A request can therefore return while
cleanup is pending. There is a finite incident history and at most one cleanup
worker per admitted incident; reaching capacity never reopens a route.

The status report separates canceled, completed, unable-to-stop and unknown
backend results from durable reservation outcomes. It includes notification
completion and proof gaps, hashes instead of action/credential contents, and a
hash chain linked to the durable intent. This detects changes against a retained
trusted chain head; it is not an externally signed transparency log.

No API claims atomic kernel revocation, rollback of completed effects or control
over unmediated paths. Only registered original brokers and credential routes
are controllable. A broker receipt must be an original current object for its
exact authorization, action, context, epoch and owned job. PID strings, copied
dataclasses, receipt JSON, caller risk labels and successful callback text cannot
prove that a process stopped. Missing communication retains unknown status.

`IncidentPolicy.automatic_rules` is empty by default. Each enabled rule names an
exact protected temporal rule ID, minimum severity, narrow action/agent/subtree
scope and maximum affected count. `temporal_signal` reruns the bound original
temporal engine over authenticated facts; it does not accept a supplied finding.
The existing temporal policy language can express repeated denials, suspicious
lateral relays, privilege escalation fanout, deletion and child-spawn quotas.
Such matches identify observed or proposed risk according to their rule; they
do not prove successful exploitation. Broad task/swarm/tenant containment always
requires the protected operator. Changed evidence invalidates an unused automatic
signal. Source truncation and unknown prehistory cannot establish a benign state.

Recovery requires completed notifications, original reconciled backend outcomes,
a current operator approval and a strictly newer owner fence or policy epoch.
`approve_resume` creates a short-lived original receipt bound to that exact
incident and evidence. `resume` delegates the final check to the coordinator,
which verifies outside DB/control locks then rechecks the durable state before
commit. Unknown in-flight outcomes, stale approvals and copied JSON cannot clear
a fence. A true process restart cannot restore lost original backend evidence
from a report and remains closed until actual reconciliation is available.

Resuming the coordinator scope does not restore old grants, TLS channels,
registry contexts, reservations or execution tickets. Workloads require fresh
enrollment, policy evaluation and reservation. Budget uncertainty remains
accounted for. Selecting an earlier configuration never rolls back an epoch.
