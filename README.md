# SaaS Platform - PostgreSQL Schema

A production-oriented database schema for a multi-tenant SaaS application. Covers auth, organisations, subscription billing, one-off product purchases, and the usual operational stuff (audit log, webhooks, notifications).

Built with **PostgreSQL 15+**.

---

## What's in the schema

| Section | Tables | Notes |
|---|---|---|
| Auth | `users`, `sessions`, `one_time_tokens`, `oauth_accounts` | Session tokens are stored as SHA-256 hashes. Raw tokens go to the client only. |
| Organisations | `organisations`, `org_members` | Every account is an org. Personal accounts are just orgs with one seat, which makes B2B team upgrades trivial. |
| Billing | `plans`, `subscriptions`, `coupons` | Mirrors Stripe's object model so webhook reconciliation is straightforward. Per-seat quantity on subscriptions. |
| Products | `products` | One-off purchasable items, separate from recurring plans. |
| Invoices | `invoices`, `invoice_line_items` | `amount_due_cents` is a generated column so it's never out of sync. |
| Payments | `payment_methods`, `charges` | Card details are display-only (last4 / brand). Raw PANs never touch this database. |
| Orders | `orders`, `order_items` | Fulfilment metadata stored as JSONB, so it works equally well for downloads, licence keys, or physical goods. |
| Audit log | `audit_log` | Append-only. BigInt identity PK is intentional, no gaps. |
| Developer tier | `api_keys`, `webhook_endpoints`, `webhook_deliveries` | HMAC-signed outbound webhooks with exponential retry tracking. |
| Notifications | `notification_preferences`, `notifications` | Per-channel granularity (email / in-app / SMS) stored in JSONB maps. |

---

## Design decisions

**UUIDs everywhere.** All primary keys are `uuid_generate_v4()`. This prevents ID enumeration attacks, plays nicely with distributed inserts if we ever need to shard, and means IDs can be generated client-side before the row hits the database.

**Soft deletes.** Most tables use a `deleted_at` timestamp rather than a hard `DELETE`. Partial indexes (`WHERE deleted_at IS NULL`) keep query performance equivalent to a hard delete while preserving the history for support and compliance.

**JSONB for variable-width data.** Plan limits, feature flags, billing addresses, and OAuth raw profiles are all stored as JSONB. These fields vary enough between rows that normalising them into columns would just produce a wide, sparse table nobody wants to look at.

**Generated columns for derived values.** `invoice_line_items.total_cents` and `invoices.amount_due_cents` are `GENERATED ALWAYS AS ... STORED`. The database keeps them accurate so there's no application-layer logic to forget about.

**Single `set_updated_at` trigger.** One PL/pgSQL function, attached via a DO block loop. Adding a new table to the list is a one-liner.

**Row-Level Security.** All org-scoped tables have RLS enabled. The application sets `app.current_org_id` at the start of each request and every query is automatically filtered to that tenant. A bug in the application layer cannot leak one org's data to another.

**Stripe IDs on the billing rows themselves.** Keeping `stripe_subscription_id`, `stripe_invoice_id`, etc. directly on the relevant rows (rather than a separate integration table) means a single lookup ties any incoming webhook to the right record.

---

## Getting started

### Prerequisites

- PostgreSQL 15 or later
- The `uuid-ossp`, `pgcrypto`, and `citext` extensions (bundled with a standard Postgres install, nothing extra to install)

### Apply the schema

```bash
psql -U postgres -c "CREATE DATABASE saas_dev;"
psql -U postgres -d saas_dev -f schema.sql
```

The seed block at the bottom of the file creates:
- Four plans (Starter / Growth / Pro / Enterprise)
- A demo organisation (`acme-corp`)
- A demo user (`ava@acme.example` / password: `examp40`)
- An active trialing subscription on the Growth plan

If you're applying this to a real environment, delete or comment out **Section 16** first.

### Connecting as a tenant

The RLS policies expect a session variable on each connection:

```sql
SET app.current_org_id = '22222222-0000-0000-0000-000000000001';

-- All queries are now scoped to Acme Corp automatically.
SELECT * FROM subscriptions;
SELECT * FROM invoices;
```

If you're using a connection pool (PgBouncer, etc.), set this variable in a `SET` command right after acquiring a connection from the pool.

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

MIT
