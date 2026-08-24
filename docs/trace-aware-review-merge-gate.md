# Trace-aware review merge gate

Trace-aware review is merged only after the full repository test suite and `commandgraph doctor` pass across Python 3.10, 3.11, 3.12, and 3.13.

The feature remains caller-controlled and local: prior commands are supplied explicitly, re-evaluated by CommandGraph, and are not persisted or uploaded by the tool.
