# ResAuthenticator

## Description

The rest authenticator rely on an external rest endpoint to validate user credentials.

It will:

- check in the system_auth.roles table if the role exist. If the role exist check password with the stored hashed one
- If the role doesn't exist, it call an external rest endpoint (https only)
- If creds are fine it stored the user/hashed password in the system_auth.roles table and return the authenticate object user

## Rest Endpoint definition

Endpoint: GET /api/v1/user/groups, Protected with Basic Auth

Response:
 - 200 if ok with body:
`{
  "groups": [ "group1", "group2" ]
}`
- 404 if user not found
- 401 if auth failed

## Test

Building Scylla with the frozen toolchain `dbuild` is as easy as:

```bash
$ git submodule update --init --force --recursive
$ ./tools/toolchain/dbuild ./configure.py
$ ./tools/toolchain/dbuild ninja build/release/scylla
```

Run scylla with RestAuthenticator

```bash
$ ./tools/toolchain/dbuild ./build/release/scylla --workdir tmp --smp 2 --developer-mode 1 --logger-log-level rest_authenticator=debug --authenticator com.criteo.scylladb.auth.RestAuthenticator --rest-authenticator-endpoint-host localhost --rest-authenticator-endpoint-port 8000 --rest-authenticator-endpoint-cafile-path ./tools/rest_authenticator_server/ssl/ca.crt
```

Run FastAPI rest server

```bash
$ ./tools/rest_authenticator_server/rest_server.sh
```

Run Test client

```bash
$ ./tools/rest_authenticator_server/scylla_client.sh
```