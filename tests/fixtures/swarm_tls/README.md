# Public synthetic TLS fixtures

These certificates and leaf private keys are public test fixtures. Never trust
this CA or use these keys outside isolated local tests. They contain no production
credentials. The signing CA's private key is not retained in the repository.

The fixtures use distinct client certificates for parent, child, siblings and
broker roles. The server requires and verifies a client certificate, and the
client verifies the server certificate and localhost identity. Tests use actual
TLS handshakes over local socket pairs, then pin verified leaf fingerprints to
protected workload enrollments. Validity spans 2020–2040 for reproducible tests.
