#!/bin/bash
#
# This script is a copy of our documentation in
# pachyderm/doc/cookbook/vault.md. It gives us a manual test of the exact
# instructions we give to clients.

### Not in instructions. This checks the setup and creates the plugin binary ###
set -ex
which aws vault pachctl
vault read sys/health
pachctl version
pachctl auth list-admins # make sure auth is activated

# Disable old plugin (if any)
vault secrets disable pachyderm

# Build plugin
mkdir /tmp/vault-plugins || true
go build -o /tmp/vault-plugins/pachyderm "$(dirname ${0})/.."

### Start the written instructions ###

# Assuming the binary is in /tmp/vault-plugins/pachyderm
export SHASUM=$(shasum -a 256 "/tmp/vault-plugins/pachyderm" | cut -d " " -f1)
echo $SHASUM
vault write sys/plugins/catalog/pachyderm sha_256="$SHASUM" command="pachyderm"
vault secrets enable -path=pachyderm -plugin-name=pachyderm plugin

echo "admin" | pachctl auth login
ADMIN_TOKEN="$(cat ~/.pachyderm/config.json | jq -r '.v1.session_token')"

vault write pachyderm/config \
      admin_token="${ADMIN_TOKEN}" \
      pachd_address="${ADDRESS:-127.0.0.1:30650}" \
      ttl=5m # optional

vault write -f pachyderm/login/robot:testuser

