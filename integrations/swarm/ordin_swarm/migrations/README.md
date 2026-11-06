# Initial coordinator schema

`0001-coordinator.sql` documents the exact bounded v1 authority schema. Protected
Python store constructors apply it transactionally, initialize the random database
identity/root manifest, and validate all expected tables and constraints. This
reference SQL is data; it cannot issue native grants, permits or runtime receipts.
Never initialize an already used namespace as empty history.
