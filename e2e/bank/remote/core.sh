#!/usr/bin/env bash
# Demo Bank's core, run as root on its own VM: the ledger (PostgreSQL 16; the payment service's role logs in only by a
# client certificate from the bank's workload CA, over TLS 1.3, and the ledger itself records which certificate moved
# money) and the fraud-scoring service (a stand-in for a partner API that admits a pre-shared API key). The TLS root
# for these two servers is made here and never leaves. Accounts, names and amounts are fictional.
#
#   core.sh install
#   core.sh setup      env: INTERNAL_IP EXTERNAL_IP; /opt/demobank/public/workload-ca.pem from the trust zone
#   core.sh start | stop | status | audit
set -euo pipefail
D=/opt/demobank
PG=/etc/postgresql/16/main
export PATH="$D/bin:$PATH"
HINT=payments.workload.demobank.example

install() {
  mkdir -p "$D/logs"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql-16 openssl netcat-openbsd python3 >/dev/null
  systemctl stop postgresql
  echo "installed: $(/usr/lib/postgresql/16/bin/postgres --version)"
}

setup() {
  : "${INTERNAL_IP:?}" "${EXTERNAL_IP:?}"
  [ -s "$D/public/workload-ca.pem" ] || { echo "!! workload CA missing"; exit 1; }
  mkdir -p "$D"/{tls,secrets,public,logs}
  chmod 700 "$D/tls" "$D/secrets"
  (umask 077; cd "$D/tls"
   if [ ! -f root.crt ]; then
     step certificate create "Demo Bank core TLS root" root.crt root.key --profile root-ca --no-password --insecure --not-after 720h >/dev/null
     step certificate create core.demobank.internal server.crt server.key --profile leaf --ca root.crt --ca-key root.key \
       --san core.demobank.internal --san "$INTERNAL_IP" --san "$EXTERNAL_IP" --no-password --insecure --not-after 240h >/dev/null
   fi)
  cp "$D/tls/root.crt" "$D/public/core-tls-root.crt"; chmod -R a+rX "$D/public"; chmod 755 "$D"
  # the fraud service's key: made by the "partner", handed once to the bank's Vault administrator (see demo-bank.sh)
  [ -s "$D/secrets/fraud-api-key" ] || (umask 077; echo "dbk_fraud_$(openssl rand -hex 24)" > "$D/secrets/fraud-api-key")

  install -d -o postgres -g postgres -m 700 "$PG/tls"
  install -o postgres -g postgres -m 600 "$D/tls/server.crt" "$PG/tls/server.crt"
  install -o postgres -g postgres -m 600 "$D/tls/server.key" "$PG/tls/server.key"
  install -o postgres -g postgres -m 644 "$D/public/workload-ca.pem" "$PG/tls/workload-ca.pem"
  cat > "$PG/conf.d/demobank.conf" <<EOF
listen_addresses = '*'
ssl = on
ssl_cert_file = '$PG/tls/server.crt'
ssl_key_file = '$PG/tls/server.key'
ssl_ca_file = '$PG/tls/workload-ca.pem'
ssl_min_protocol_version = 'TLSv1.3'
password_encryption = 'scram-sha-256'
log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] %q%u@%d %r '
EOF
  # who may log in: the payment service's role, over TLS, by a certificate whose CN maps to it; nobody else remotely
  cat > "$PG/pg_hba.conf" <<'EOF'
local   all   postgres                 peer
hostssl bank  payments  0.0.0.0/0      cert map=workload
hostssl bank  payments  ::/0           cert map=workload
host    all   all       0.0.0.0/0      reject
host    all   all       ::/0           reject
EOF
  printf 'workload  %s  payments\n' "$HINT" > "$PG/pg_ident.conf"
  chown postgres:postgres "$PG/pg_hba.conf" "$PG/pg_ident.conf" "$PG/conf.d/demobank.conf"
  systemctl start postgresql
  if ! su postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname = 'bank'\"" | grep -q 1; then
    su postgres -c "psql -v ON_ERROR_STOP=1 -q" <<'SQL'
CREATE ROLE payments LOGIN;                 -- no password: the certificate is the only way in
CREATE DATABASE bank;
\c bank
CREATE EXTENSION sslinfo;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO payments;
CREATE TABLE accounts (
  id            text PRIMARY KEY,
  holder        text NOT NULL,
  currency      char(3) NOT NULL DEFAULT 'USD',
  balance_cents bigint NOT NULL CHECK (balance_cents >= 0)
);
CREATE TABLE transfers (
  id                 bigserial PRIMARY KEY,
  from_account       text NOT NULL REFERENCES accounts(id),
  to_account         text NOT NULL REFERENCES accounts(id),
  amount_cents       bigint NOT NULL CHECK (amount_cents > 0),
  fraud_ref          text NOT NULL,
  tee                text NOT NULL,                                        -- as the service reports it
  client_cn          text NOT NULL DEFAULT ssl_client_dn_field('commonName'), -- from the TLS session
  client_cert_serial text NOT NULL DEFAULT ssl_client_serial()::text,
  client_cert_issuer text NOT NULL DEFAULT ssl_issuer_dn(),
  db_user            text NOT NULL DEFAULT current_user,
  created_at         timestamptz NOT NULL DEFAULT now(),
  CHECK (from_account <> to_account)
);
GRANT CONNECT ON DATABASE bank TO payments;
GRANT SELECT, UPDATE (balance_cents) ON accounts TO payments;
GRANT SELECT, INSERT (from_account, to_account, amount_cents, fraud_ref, tee) ON transfers TO payments;
GRANT USAGE ON SEQUENCE transfers_id_seq TO payments;
INSERT INTO accounts (id, holder, balance_cents) VALUES
  ('ACC-1001', 'Demo customer (fictional)', 500000),
  ('ACC-2002', 'Demo merchant (fictional)', 100000);
SQL
  fi
  echo "setup done"
}

running() { [ -f "$D/logs/$1.pid" ] && kill -0 "$(cat "$D/logs/$1.pid")" 2>/dev/null; }

start() {
  systemctl start postgresql
  if ! running fraud-api; then
    nohup "$D/bin/fraud-api" -listen :8444 -cert "$D/tls/server.crt" -key "$D/tls/server.key" \
      -api-key-file "$D/secrets/fraud-api-key" >> "$D/logs/fraud-api.log" 2>&1 &
    echo $! > "$D/logs/fraud-api.pid"
  fi
  for p in 5432 8444; do for _ in $(seq 1 60); do nc -z 127.0.0.1 $p && break; sleep 0.25; done; done
  status
}

stop() {
  if running fraud-api; then kill "$(cat "$D/logs/fraud-api.pid")"; fi
  rm -f "$D/logs/fraud-api.pid"
  systemctl stop postgresql
}

status() {
  if running fraud-api; then echo "fraud-api running"; else echo "fraud-api STOPPED"; fi
  if systemctl is-active -q postgresql; then echo "postgresql running"; else echo "postgresql STOPPED"; fi
  ss -ltnp | awk 'NR>1 {print $4}' | sort -u | tr '\n' ' '; echo
}

# the ledger as the bank's auditor sees it, and the server's own log of who logged in how
audit() {
  su postgres -c "psql -d bank -P pager=off" <<'SQL'
SELECT id, holder, currency, to_char(balance_cents / 100.0, 'FM999999990.00') AS balance FROM accounts ORDER BY id;
SELECT id, from_account, to_account, to_char(amount_cents / 100.0, 'FM999999990.00') AS amount, fraud_ref, tee,
       client_cn, client_cert_serial, client_cert_issuer, db_user, created_at FROM transfers ORDER BY id;
SQL
  echo "--- ledger log: connections"
  grep -hE "connection (received|authenticated|authorized)|FATAL|no pg_hba|certificate" /var/log/postgresql/postgresql-16-main.log | tail -40 || true
  echo "--- fraud service log"
  tail -20 "$D/logs/fraud-api.log" || true
}

"$@"
