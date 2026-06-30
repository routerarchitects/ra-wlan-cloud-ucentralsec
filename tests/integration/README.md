# Integration Tests for ucentralsec Service

This directory contains integration tests designed to verify security policies, ownership inheritance, user role creation limits, and deletion/demotion rules in the `ucentralsec` microservice.

## Prerequisites

Before running the tests, ensure that:
1. The `ucentralsec` microservice is running locally or in a container.
2. The PostgreSQL database is running (e.g. via Docker).
3. The environment variables required by the test suite are defined in your `local_test.env` file (copied from `local_test.env.example` which is Git-ignored to prevent leaking credentials).

To get started, copy the template and configure it:
```bash
cp local_test.env.example local_test.env
```

Required environment variables inside `local_test.env`:
- `OWSEC_BASE_URL`: The URL where the `ucentralsec` API is reachable.
- `OWSEC_ROOT_EMAIL`: The ROOT user email.
- `OWSEC_ROOT_PASSWORD`: The ROOT user password.
- `OW_RBAC_TLS_ROOT_CA` (optional): Path to a TLS Root CA certificate if using HTTPS.


## Running the Tests

To run the integration tests and display the test case execution matrix:

```bash
go test -v
```

## Database Cleanup

- Before execution, the test suite calls `RunDbCleanup()`, which deletes all non-root users from the database.
- The test suite **does not** clean up the users *after* execution. This preserves the created users in the database so you can query or inspect them to verify the test results.
