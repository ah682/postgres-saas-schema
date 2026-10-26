# SaaS Platform - PostgreSQL Schema

A database design reference for a multi-tenant SaaS application. Covers auth, organisations, subscription billing, one-off product purchases, and the usual operational stuff (audit log, webhooks, notifications).

Built for **PostgreSQL 15+**, with tests for schema loading, role privileges, tenant isolation, connection reuse and reference integrity.

---

## What's in the schema

| Section | Tables | Notes |
|---|---|---|
| Auth | `users`, `sessions`, `one_time_tokens`, `oauth_accounts` | The trusted application must hash tokens before storage and manage rotation/expiry. |
| Organisations | `organisations`, `org_members` | Every account is an org. Personal accounts are just orgs with one seat, which makes B2B team upgrades trivial. |
| Billing | `plans`, `subscriptions`, `coupons` | Mirrors Stripe's object model so webhook reconciliation is straightforward. Per-seat quantity on subscriptions. |
| Products | `products` | One-off purchasable items, separate from recurring plans. |
| Invoices | `invoices`, `invoice_line_items` | `amount_due_cents` is a generated column so it's never out of sync. |
| Payments | `payment_methods`, `charges` | Card details are display-only (last4 / brand). Raw PANs never touch this database. |
| Orders | `orders`, `order_items` | Fulfilment metadata stored as JSONB, so it works equally well for downloads, licence keys, or physical goods. |
| Audit log | `audit_log` | Read-only to the tenant role; trusted services write. BigInt identity values can have gaps. |
| Developer tier | `api_keys`, `webhook_endpoints`, `webhook_deliveries` | Fields for signing and retry tracking; delivery/signing code is not included. |
| Notifications | `notification_preferences`, `notifications` | Per-channel granularity (email / in-app / SMS) stored in JSONB maps. |

---

## Design decisions

**Identifiers.** Most primary keys use `uuid_generate_v4()`, which permits distributed ID generation. `audit_log` uses a bigint identity; gaps after rollbacks, caching or failed inserts are normal. Access control comes from roles and policies, not the choice of identifier.

**Soft deletes.** Most tables use a `deleted_at` timestamp. Partial indexes (`WHERE deleted_at IS NULL`) support active-row queries while keeping history available. Set a retention policy for that history as the application grows.

**JSONB for variable-width data.** Plan limits, feature flags, billing addresses, and OAuth raw profiles are all stored as JSONB. These fields vary enough between rows that normalising them into columns would just produce a wide, sparse table nobody wants to look at.

**Generated columns for derived values.** `invoice_line_items.total_cents` and `invoices.amount_due_cents` are `GENERATED ALWAYS AS ... STORED`. The database keeps them accurate so there's no application-layer logic to forget about.

**Single `set_updated_at` trigger.** One PL/pgSQL function, attached via a DO block loop. Adding a new table to the list is a one-liner.

**Row-Level Security.** Tenant policies filter by `app.current_org_id`, with explicit grants in `bootstrap.sql`. The application authenticates the user, authorizes the operation and sets that tenant context for the transaction. Anyone able to execute arbitrary SQL can change the context; owners, superusers and `BYPASSRLS` roles bypass the policies. RLS therefore relies on a trusted server and parameterized queries. The connection example below shows how to use it safely with a pool.

**Stripe IDs on the billing rows themselves.** Keeping `stripe_subscription_id`, `stripe_invoice_id`, etc. directly on the relevant rows (rather than a separate integration table) means a single lookup ties any incoming webhook to the right record.

---

## Getting started

### Prerequisites

- PostgreSQL 15 or later
- The `uuid-ossp`, `pgcrypto`, and `citext` extensions (bundled with a standard Postgres install, nothing extra to install)

### Apply the schema

```bash
psql -U postgres -c "CREATE DATABASE saas_dev;"
psql -X -v ON_ERROR_STOP=1 -U postgres -d saas_dev -f schema.sql
psql -X -v ON_ERROR_STOP=1 -U postgres -d saas_dev -f bootstrap.sql
```

`schema.sql` is a fresh-database script, not an incremental migration. `bootstrap.sql` must run once as the schema owner with `CREATEROLE`. It creates a cluster-wide `saas_app` role and deliberately fails if that role exists; review existing role ownership/memberships/grants before adapting it for another database. It also revokes public schema creation from `PUBLIC` in this database. New tables receive no automatic app grants.

The seed block at the bottom of the file creates:

- Four plans (Starter / Growth / Pro / Enterprise)
- A demo organisation (`acme-corp`)
- A demo identity (`jane@acme.example`) with `password_hash = NULL`; no password login or demo credential is provided
- An active trialing subscription on the Growth plan

If you're applying this to a real environment, delete or comment out **Section 16** first.

### Connecting as a tenant

`saas_app` is a restricted `NOLOGIN` privilege role, never the schema owner, superuser, `BYPASSRLS`, or a member of an administrative role. Provision a separate authenticated server login with a narrowly scoped grant, for example:

```sql
-- As an administrator, once. Configure credentials/authentication separately.
CREATE ROLE saas_server LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT saas_app TO saas_server;
```

Authenticate the user and check their current membership (`accepted_at`, `deleted_at`) and permission for the operation. The server must interpret `org_members.role`; the database does not implement member/admin permissions. Then, on a checked-out connection authenticated as `saas_server`:

```sql
BEGIN;
SET LOCAL ROLE saas_app;
-- In real server code use a bound UUID parameter:
-- SELECT set_config('app.current_org_id', $1, true);
SET LOCAL app.current_org_id = '22222222-0000-0000-0000-000000000001';
SELECT * FROM subscriptions;
SELECT * FROM invoices;
COMMIT;
```

All request queries must execute in that same transaction. Roll back on every error before releasing the connection. Use transaction-compatible pooling; statement pooling cannot preserve this transaction contract. Never use session-level `SET app.current_org_id`: `SET LOCAL` reverts to the previous session value at commit/rollback, so initialize connections with empty context and discard/reset any connection with legacy session state. Configure tenant-free role/database defaults. Missing/empty context returns no tenant rows and rejects tenant writes; a malformed UUID raises an error. The test suite exercises commit, rollback and failure on one physical connection. See PostgreSQL's [SET LOCAL semantics](https://www.postgresql.org/docs/16/sql-set.html) and [RLS trust boundary](https://www.postgresql.org/docs/16/ddl-rowsecurity.html).

### Role permissions and relationships

The tenant role can read/update its organisation, manage tenant resources, memberships and scoped notifications, and read global plans/products and tenant audit records. Creating organisations, writing audit history, administering catalogues, truncating tables and changing policies require separate privileges. The server must enforce member/admin permissions, billing access, soft-delete visibility and hidden catalogue entries. Notification policies cover the whole org; the server must also filter by recipient where needed.

`users`, `sessions`, `one_time_tokens`, `oauth_accounts`, `notification_preferences` and `coupons` have no tenant-role grants. Null-org notifications and audit events also belong to administrative services, which need their own privileges. Those services handle hashing, encryption, rotation, webhook signing and delivery. Despite its name, `webhook_endpoints.secret_hash` needs encrypted, recoverable signing material or a key reference: a one-way hash cannot recover the original HMAC key.

Composite foreign keys keep subscriptions, invoices, charges, payment methods and orders in the same tenant. Orders, API key creators and scoped notification recipients require an org membership row; the server still checks whether that membership is active. Audit and invitation actors may be administrators outside the org. Child line/item/delivery rows inherit their tenant from their parent. Optional links remain nullable, and historical references can prevent hard deletion of memberships. When adapting an existing database, clean up inconsistent references before adding these constraints in a migration.

### Run the database contract tests

Install PostgreSQL server/client binaries, the three extensions and Python 3, then run as a normal user (not root):

```bash
bash ./scripts/test.sh
# If pg_config points at another version:
PG_BIN=/usr/lib/postgresql/16/bin bash ./scripts/test.sh
```

The command creates a private disposable cluster under `/tmp`, accepts only local Unix-socket connections in that private directory, loads schema/bootstrap, and runs `tests/test_contract.py` with real app-role connections. It cleans up on exit and never uses the host database service. Local `trust` authentication is limited to this disposable test cluster; configure authentication for real deployments separately. The GitHub Actions workflow runs the same command on PostgreSQL 15–18.

Tests cover missing context, both tenants, wrong-tenant writes and reparenting, child resources, membership management, scoped/global notifications, global auth denial, role/owner differences, privilege escalation, connection reuse and inconsistent foreign keys even as owner. They also check generated amounts, the single default payment method and API key revocation.

---

## Schema diagram (simplified)

```
organisations
    |
    +-- org_members ---- users
    |                      +-- sessions
    |                      +-- oauth_accounts
    |                      +-- one_time_tokens
    |
    +-- subscriptions -- plans
    |
    +-- invoices
    |     +-- invoice_line_items
    |
    +-- payment_methods
    +-- charges
    |
    +-- orders
    |     +-- order_items -- products
    |
    +-- api_keys
    +-- webhook_endpoints
    |     +-- webhook_deliveries
    |
    +-- audit_log
```

---

## Extending the schema

A few things were left out on purpose to keep this focused:

- **Usage metering** - add a `usage_records` table keyed on `(org_id, metric, period)` and aggregate into invoices at billing time.
- **Feature flags per org** - the `organisations.feature_flags` JSONB column is a decent starting point. For a proper flags system you'd want a `feature_flag_definitions` table and a `flag_overrides` table alongside it.
- **Referral / affiliate tracking** - a `referral_codes` table with a `referred_by` FK on `organisations` is easy to bolt on.
- **Multi-currency** - amounts are stored in the smallest unit of the invoice's currency. To go multi-currency properly you'd want to store exchange rates at invoice creation time rather than converting later.

---

## License

[MIT](LICENSE), copyright Ava Hall (ah682).
