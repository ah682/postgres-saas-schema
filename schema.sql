-- =============================================================================
-- SaaS Platform — PostgreSQL Schema
-- =============================================================================
-- Stack: PostgreSQL 15+, pgcrypto, uuid-ossp
-- Conventions:
--   • All PKs are UUIDs (v4) — avoids enumeration attacks and works well
--     across distributed writes if we ever shard.
--   • Soft-deletes via deleted_at rather than hard DELETE, except for
--     session/token tables where we actually want rows gone.
--   • Every mutable table gets created_at / updated_at. The updated_at
--     column is kept accurate by a shared trigger (see bottom of file).
--   • Row-Level Security is enabled on all user-facing tables. Policies
--     are defined here so they travel with the schema.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------

create extension if not exists "uuid-ossp";
create extension if not exists "pgcrypto";
create extension if not exists "citext";      -- case-insensitive text for emails


-- =============================================================================
-- SECTION 1 — ENUMS
-- =============================================================================

create type subscription_status as enum (
    'trialing',
    'active',
    'past_due',
    'canceled',
    'unpaid',
    'paused'
);

create type invoice_status as enum (
    'draft',
    'open',
    'paid',
    'void',
    'uncollectible'
);

create type payment_method_type as enum (
    'card',
    'bank_transfer',
    'paypal',
    'crypto'
);

create type plan_interval as enum (
    'monthly',
    'quarterly',
    'annual'
);

create type org_member_role as enum (
    'owner',
    'admin',
    'member',
    'billing',       -- can only touch invoices/subs, nothing else
    'viewer'
);

create type audit_action as enum (
    'create',
    'update',
    'delete',
    'login',
    'logout',
    'password_change',
    'subscription_change',
    'payment_attempt'
);


-- =============================================================================
-- SECTION 2 — ORGANISATIONS (top-level tenants)
-- =============================================================================
-- Every resource in the platform belongs to an org. Personal accounts are
-- just orgs with a single member. This makes B2B expansion trivial.

create table organisations (
    id              uuid primary key default uuid_generate_v4(),
    name            text not null,
    slug            text not null unique,        -- used in URLs: app.co/acme-corp
    logo_url        text,
    billing_email   citext not null,

    -- Stripe / payment-processor IDs kept alongside the record so we don't
    -- have to join through a separate table for the common billing queries.
    stripe_customer_id      text unique,

    -- Feature flags stored as jsonb so we can gate arbitrary flags without
    -- a schema migration every time product ships a new experiment.
    feature_flags   jsonb not null default '{}',

    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    deleted_at      timestamptz
);

create index idx_organisations_slug        on organisations (slug)        where deleted_at is null;
create index idx_organisations_stripe_id   on organisations (stripe_customer_id);


-- =============================================================================
-- SECTION 3 — USERS & AUTHENTICATION
-- =============================================================================

create table users (
    id                  uuid primary key default uuid_generate_v4(),

    -- citext handles "User@Example.com" == "user@example.com" transparently.
    email               citext not null unique,
    email_verified_at   timestamptz,

    -- Passwords are hashed by the application layer (bcrypt/argon2) before
    -- being stored. This column is nullable so OAuth-only users don't have
    -- a password at all.
    password_hash       text,

    full_name           text not null,
    avatar_url          text,
    phone               text,

    -- TOTP secret is encrypted at rest using pgcrypto before insert.
    totp_secret         text,
    totp_enabled_at     timestamptz,

    -- Track failed logins to support account lockout.
    failed_login_count  int not null default 0,
    locked_until        timestamptz,

    -- UTC offset preference stored as interval — avoids DST headaches
    -- compared to a tz name string.
    timezone            text not null default 'UTC',
    locale              text not null default 'en',

    last_sign_in_at     timestamptz,
    last_sign_in_ip     inet,

    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now(),
    deleted_at          timestamptz
);

create index idx_users_email       on users (email)      where deleted_at is null;
create index idx_users_deleted_at  on users (deleted_at) where deleted_at is not null;


-- ---------------------------------------------------------------------------
-- Sessions — short-lived, backed by a refresh-token rotation scheme.
-- We delete these on logout rather than soft-deleting.
-- ---------------------------------------------------------------------------

create table sessions (
    id              uuid primary key default uuid_generate_v4(),
    user_id         uuid not null references users (id) on delete cascade,

    -- The token stored here is already hashed (sha256). Raw token goes to
    -- the client as an HttpOnly cookie.
    token_hash      text not null unique,

    ip_address      inet,
    user_agent      text,

    -- Absolute expiry — even a rotated token chain dies here.
    expires_at      timestamptz not null,

    created_at      timestamptz not null default now()
);

create index idx_sessions_user_id    on sessions (user_id);
create index idx_sessions_expires_at on sessions (expires_at);

-- Prune expired sessions nightly (hook this into pg_cron or a job queue).
-- Sessions older than the expiry are useless rows.


-- ---------------------------------------------------------------------------
-- Password reset / email verification tokens
-- ---------------------------------------------------------------------------

create table one_time_tokens (
    id          uuid primary key default uuid_generate_v4(),
    user_id     uuid not null references users (id) on delete cascade,
    token_hash  text not null unique,
    token_type  text not null check (token_type in ('password_reset', 'email_verify', 'invite')),
    used_at     timestamptz,
    expires_at  timestamptz not null,
    created_at  timestamptz not null default now()
);

create index idx_ott_user_id    on one_time_tokens (user_id);
create index idx_ott_expires_at on one_time_tokens (expires_at);


-- ---------------------------------------------------------------------------
-- OAuth provider links (Google, GitHub, etc.)
-- ---------------------------------------------------------------------------

create table oauth_accounts (
    id              uuid primary key default uuid_generate_v4(),
    user_id         uuid not null references users (id) on delete cascade,
    provider        text not null,              -- 'google', 'github', 'microsoft'
    provider_uid    text not null,              -- provider's user id
    access_token    text,                       -- encrypted before insert
    refresh_token   text,                       -- encrypted before insert
    token_expires_at timestamptz,
    raw_profile     jsonb,                      -- store full provider response for debugging
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),

    unique (provider, provider_uid)
);

create index idx_oauth_user_id on oauth_accounts (user_id);


-- =============================================================================
-- SECTION 4 — ORG MEMBERSHIP
-- =============================================================================

create table org_members (
    id          uuid primary key default uuid_generate_v4(),
    org_id      uuid not null references organisations (id) on delete cascade,
    user_id     uuid not null references users (id) on delete cascade,
    role        org_member_role not null default 'member',

    -- Denote the member that sent the invite for audit purposes.
    invited_by  uuid references users (id),
    accepted_at timestamptz,

    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now(),
    deleted_at  timestamptz,

    unique (org_id, user_id)
);

create index idx_org_members_org_id  on org_members (org_id)  where deleted_at is null;
create index idx_org_members_user_id on org_members (user_id) where deleted_at is null;


-- =============================================================================
-- SECTION 5 — PLANS & SUBSCRIPTIONS
-- =============================================================================

create table plans (
    id              uuid primary key default uuid_generate_v4(),
    name            text not null,              -- 'Starter', 'Growth', 'Enterprise'
    slug            text not null unique,
    description     text,
    interval        plan_interval not null,

    -- Price in the smallest currency unit (cents for USD).
    price_cents     int not null check (price_cents >= 0),
    currency        text not null default 'usd',

    -- Stripe price/product IDs so we can reconcile webhooks.
    stripe_price_id     text unique,
    stripe_product_id   text,

    -- Limits enforced by the application — stored here so billing pages can
    -- describe them without hardcoding in the frontend.
    limits          jsonb not null default '{}',
    -- e.g. {"seats": 5, "api_calls_per_month": 50000, "storage_gb": 20}

    is_public       boolean not null default true,   -- hidden plans for enterprise deals
    sort_order      int not null default 0,

    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    deleted_at      timestamptz
);

create index idx_plans_slug on plans (slug) where deleted_at is null;


create table subscriptions (
    id                  uuid primary key default uuid_generate_v4(),
    org_id              uuid not null references organisations (id) on delete cascade,
    plan_id             uuid not null references plans (id),

    status              subscription_status not null default 'trialing',

    -- Stripe subscription ID — used to reconcile incoming webhooks.
    stripe_subscription_id  text unique,

    -- Inclusive range: the period the current invoice covers.
    current_period_start    timestamptz not null,
    current_period_end      timestamptz not null,

    trial_start         timestamptz,
    trial_end           timestamptz,

    cancel_at           timestamptz,            -- scheduled cancellation
    canceled_at         timestamptz,            -- when it was actually canceled

    -- The quantity field handles per-seat pricing.
    quantity            int not null default 1 check (quantity > 0),

    -- Any active discount coupon code applied.
    coupon_code         text,
    discount_pct        numeric(5, 2) check (discount_pct between 0 and 100),

    metadata            jsonb not null default '{}',

    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now()
);

create index idx_subscriptions_org_id  on subscriptions (org_id);
create index idx_subscriptions_status  on subscriptions (status);
create index idx_subscriptions_stripe  on subscriptions (stripe_subscription_id);


-- =============================================================================
-- SECTION 6 — PRODUCTS & CATALOGUE
-- =============================================================================
-- Separate from plans — these are one-off purchasable items (add-ons,
-- templates, credits, etc.).

create table products (
    id              uuid primary key default uuid_generate_v4(),
    name            text not null,
    slug            text not null unique,
    description     text,
    long_description text,

    price_cents     int not null check (price_cents >= 0),
    currency        text not null default 'usd',

    stripe_price_id     text unique,
    stripe_product_id   text,

    -- Optionally gate products behind a minimum plan.
    required_plan_id    uuid references plans (id),

    -- Images stored as an ordered jsonb array of {url, alt} objects.
    images          jsonb not null default '[]',

    -- Flexible metadata (weight, dimensions, download URL, etc.)
    metadata        jsonb not null default '{}',

    is_active       boolean not null default true,
    sort_order      int not null default 0,

    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    deleted_at      timestamptz
);

create index idx_products_slug      on products (slug)      where deleted_at is null;
create index idx_products_is_active on products (is_active) where deleted_at is null;


-- ---------------------------------------------------------------------------
-- Discount / coupon codes (shared across plans and products)
-- ---------------------------------------------------------------------------

create table coupons (
    id              uuid primary key default uuid_generate_v4(),
    code            text not null unique,
    description     text,

    -- Exactly one of these should be set.
    discount_pct    numeric(5, 2) check (discount_pct between 0 and 100),
    discount_cents  int          check (discount_cents >= 0),

    -- How many times this code can be redeemed in total.
    max_redemptions int,
    redemption_count int not null default 0,

    -- Which objects this applies to. Null means universal.
    applies_to_plan_ids    uuid[],
    applies_to_product_ids uuid[],

    valid_from      timestamptz,
    valid_until     timestamptz,

    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);


-- =============================================================================
-- SECTION 7 — INVOICES & LINE ITEMS
-- =============================================================================

create table invoices (
    id                  uuid primary key default uuid_generate_v4(),
    org_id              uuid not null references organisations (id) on delete cascade,
    subscription_id     uuid references subscriptions (id),

    -- Stripe invoice ID for reconciliation.
    stripe_invoice_id   text unique,

    status              invoice_status not null default 'draft',

    subtotal_cents      int not null default 0,
    tax_cents           int not null default 0,
    discount_cents      int not null default 0,
    total_cents         int not null default 0,
    amount_paid_cents   int not null default 0,
    amount_due_cents    int not null generated always as (total_cents - amount_paid_cents) stored,

    currency            text not null default 'usd',

    -- Period this invoice covers (may differ from sub period for prorations).
    period_start        timestamptz,
    period_end          timestamptz,

    due_date            timestamptz,
    paid_at             timestamptz,
    voided_at           timestamptz,

    pdf_url             text,
    hosted_invoice_url  text,

    metadata            jsonb not null default '{}',

    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now()
);

create index idx_invoices_org_id     on invoices (org_id);
create index idx_invoices_status     on invoices (status);
create index idx_invoices_stripe_id  on invoices (stripe_invoice_id);


create table invoice_line_items (
    id              uuid primary key default uuid_generate_v4(),
    invoice_id      uuid not null references invoices (id) on delete cascade,

    -- Either a plan or a product — at least one should be set.
    plan_id         uuid references plans (id),
    product_id      uuid references products (id),

    description     text not null,
    quantity        int not null default 1 check (quantity > 0),
    unit_price_cents int not null,
    total_cents     int not null generated always as (quantity * unit_price_cents) stored,
    currency        text not null default 'usd',

    -- Proration line items need their own period.
    period_start    timestamptz,
    period_end      timestamptz,

    created_at      timestamptz not null default now()
);

create index idx_line_items_invoice_id on invoice_line_items (invoice_id);


-- =============================================================================
-- SECTION 8 — PAYMENT METHODS & CHARGES
-- =============================================================================

create table payment_methods (
    id                  uuid primary key default uuid_generate_v4(),
    org_id              uuid not null references organisations (id) on delete cascade,

    type                payment_method_type not null default 'card',
    stripe_pm_id        text unique,

    -- Non-sensitive display info only — we never store raw card numbers.
    card_brand          text,                   -- 'visa', 'mastercard', etc.
    card_last4          char(4),
    card_exp_month      smallint check (card_exp_month between 1 and 12),
    card_exp_year       smallint,

    billing_name        text,
    billing_email       citext,
    billing_address     jsonb,                  -- {line1, city, state, postal_code, country}

    is_default          boolean not null default false,

    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now(),
    deleted_at          timestamptz
);

create index idx_pm_org_id on payment_methods (org_id) where deleted_at is null;

-- Enforce a single default per org using a partial unique index.
create unique index idx_pm_one_default_per_org
    on payment_methods (org_id)
    where is_default = true and deleted_at is null;


create table charges (
    id                  uuid primary key default uuid_generate_v4(),
    org_id              uuid not null references organisations (id),
    invoice_id          uuid references invoices (id),
    payment_method_id   uuid references payment_methods (id),

    stripe_charge_id    text unique,
    stripe_pi_id        text unique,            -- PaymentIntent ID

    amount_cents        int not null check (amount_cents > 0),
    currency            text not null default 'usd',

    -- Outcome
    succeeded           boolean,
    failure_code        text,
    failure_message     text,

    -- Raw Stripe response — useful for disputes and debugging.
    stripe_response     jsonb,

    created_at          timestamptz not null default now()
);

create index idx_charges_org_id     on charges (org_id);
create index idx_charges_invoice_id on charges (invoice_id);


-- =============================================================================
-- SECTION 9 — PURCHASES (one-off product orders)
-- =============================================================================

create table orders (
    id                  uuid primary key default uuid_generate_v4(),
    org_id              uuid not null references organisations (id),
    user_id             uuid not null references users (id),  -- who placed it

    invoice_id          uuid references invoices (id),
    charge_id           uuid references charges (id),

    status              text not null default 'pending'
                            check (status in ('pending', 'processing', 'completed', 'refunded', 'failed')),

    total_cents         int not null check (total_cents >= 0),
    currency            text not null default 'usd',

    -- Fulfilment details (download links, licence keys, etc.)
    fulfilment_data     jsonb not null default '{}',

    created_at          timestamptz not null default now(),
    updated_at          timestamptz not null default now()
);

create index idx_orders_org_id  on orders (org_id);
create index idx_orders_user_id on orders (user_id);


create table order_items (
    id              uuid primary key default uuid_generate_v4(),
    order_id        uuid not null references orders (id) on delete cascade,
    product_id      uuid not null references products (id),
    quantity        int not null default 1 check (quantity > 0),
    unit_price_cents int not null,
    total_cents     int not null generated always as (quantity * unit_price_cents) stored,
    created_at      timestamptz not null default now()
);

create index idx_order_items_order_id on order_items (order_id);


-- =============================================================================
-- SECTION 10 — AUDIT LOG
-- =============================================================================
-- Append-only. No updates, no deletes. This table is the source of truth
-- for security investigations, compliance, and customer support.

create table audit_log (
    id              bigint primary key generated always as identity,
    org_id          uuid references organisations (id),
    user_id         uuid references users (id),

    action          audit_action not null,

    -- What was changed — freeform so we can log anything.
    resource_type   text,                       -- 'subscription', 'user', etc.
    resource_id     text,

    -- Store before/after for updates. Scrub PII before insert.
    old_data        jsonb,
    new_data        jsonb,

    ip_address      inet,
    user_agent      text,

    -- Stripe event ID if this action came from a webhook.
    stripe_event_id text,

    created_at      timestamptz not null default now()
);

-- We query audit_log heavily by org + time window for the in-app activity feed.
create index idx_audit_log_org_created   on audit_log (org_id, created_at desc);
create index idx_audit_log_user_created  on audit_log (user_id, created_at desc);
create index idx_audit_log_resource      on audit_log (resource_type, resource_id);


-- =============================================================================
-- SECTION 11 — NOTIFICATIONS
-- =============================================================================

create table notification_preferences (
    id          uuid primary key default uuid_generate_v4(),
    user_id     uuid not null references users (id) on delete cascade unique,

    -- Each channel preference stored as a jsonb map of {event_type: bool}.
    email       jsonb not null default '{}',
    in_app      jsonb not null default '{}',
    sms         jsonb not null default '{}',

    updated_at  timestamptz not null default now()
);


create table notifications (
    id              uuid primary key default uuid_generate_v4(),
    user_id         uuid not null references users (id) on delete cascade,
    org_id          uuid references organisations (id),

    type            text not null,              -- 'invoice_paid', 'trial_ending', etc.
    title           text not null,
    body            text,
    action_url      text,
    icon            text,

    read_at         timestamptz,
    dismissed_at    timestamptz,

    created_at      timestamptz not null default now()
);

create index idx_notifications_user_unread
    on notifications (user_id, created_at desc)
    where read_at is null and dismissed_at is null;


-- =============================================================================
-- SECTION 12 — API KEYS (for developer/integration tier users)
-- =============================================================================

create table api_keys (
    id              uuid primary key default uuid_generate_v4(),
    org_id          uuid not null references organisations (id) on delete cascade,
    created_by      uuid not null references users (id),

    name            text not null,
    key_prefix      char(8) not null,           -- shown in UI: "sk_live_ab12cdef..."
    key_hash        text not null unique,        -- sha256 of the full key

    -- Scope as a simple text array — e.g. '{read:products, write:orders}'
    scopes          text[] not null default '{}',

    last_used_at    timestamptz,
    expires_at      timestamptz,

    created_at      timestamptz not null default now(),
    revoked_at      timestamptz
);

create index idx_api_keys_org_id on api_keys (org_id) where revoked_at is null;


-- =============================================================================
-- SECTION 13 — WEBHOOKS (outbound event delivery)
-- =============================================================================

create table webhook_endpoints (
    id              uuid primary key default uuid_generate_v4(),
    org_id          uuid not null references organisations (id) on delete cascade,

    url             text not null,
    secret_hash     text not null,              -- used to sign payloads (HMAC-SHA256)

    -- Which events to fan out to this endpoint.
    enabled_events  text[] not null default '{"*"}',

    is_active       boolean not null default true,

    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);


create table webhook_deliveries (
    id                  uuid primary key default uuid_generate_v4(),
    endpoint_id         uuid not null references webhook_endpoints (id) on delete cascade,

    event_type          text not null,
    payload             jsonb not null,

    attempt_count       int not null default 0,
    next_retry_at       timestamptz,
    max_attempts        int not null default 5,

    -- Last response from the destination.
    response_status     int,
    response_body       text,
    response_duration_ms int,

    delivered_at        timestamptz,
    failed_at           timestamptz,

    created_at          timestamptz not null default now()
);

create index idx_webhook_deliveries_endpoint on webhook_deliveries (endpoint_id);
create index idx_webhook_deliveries_pending
    on webhook_deliveries (next_retry_at)
    where delivered_at is null and failed_at is null;


-- =============================================================================
-- SECTION 14 — TRIGGERS
-- =============================================================================
-- Single function, applied to every table that has an updated_at column.

create or replace function set_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at = now();
    return new;
end;
$$;

-- Macro-style do block to attach the trigger to every relevant table without
-- repeating boilerplate.
do $$
declare
    t text;
begin
    foreach t in array array[
        'organisations',
        'users',
        'oauth_accounts',
        'org_members',
        'plans',
        'subscriptions',
        'products',
        'coupons',
        'invoices',
        'payment_methods',
        'orders',
        'webhook_endpoints',
        'api_keys'
    ]
    loop
        execute format(
            'create trigger trg_%s_updated_at
             before update on %s
             for each row execute function set_updated_at();',
            t, t
        );
    end loop;
end;
$$;


-- =============================================================================
-- SECTION 15 — ROW-LEVEL SECURITY
-- =============================================================================
-- App connects as a role with no direct table grants. It sets a session
-- variable (app.current_org_id) at the start of each request, and RLS
-- ensures queries are automatically scoped to that org.
--
--   SET app.current_org_id = 'org-uuid-here';

alter table organisations      enable row level security;
alter table org_members        enable row level security;
alter table subscriptions      enable row level security;
alter table invoices           enable row level security;
alter table invoice_line_items enable row level security;
alter table payment_methods    enable row level security;
alter table charges            enable row level security;
alter table orders             enable row level security;
alter table order_items        enable row level security;
alter table audit_log          enable row level security;
alter table api_keys           enable row level security;
alter table webhook_endpoints  enable row level security;
alter table webhook_deliveries enable row level security;
alter table notifications      enable row level security;

-- Helper function — avoids repeating the cast in every policy.
create or replace function current_org_id()
returns uuid
language sql stable
as $$
    select nullif(current_setting('app.current_org_id', true), '')::uuid;
$$;

-- Organisations — members can only see their own org.
create policy rls_organisations_select on organisations
    for select using (id = current_org_id());

create policy rls_organisations_update on organisations
    for update using (id = current_org_id());

-- Subscriptions scoped to current org.
create policy rls_subscriptions_all on subscriptions
    for all using (org_id = current_org_id());

-- Invoices scoped to current org.
create policy rls_invoices_all on invoices
    for all using (org_id = current_org_id());

create policy rls_invoice_lines_all on invoice_line_items
    for all using (
        invoice_id in (
            select id from invoices where org_id = current_org_id()
        )
    );

-- Payment methods scoped to current org.
create policy rls_payment_methods_all on payment_methods
    for all using (org_id = current_org_id());

-- Charges scoped to current org.
create policy rls_charges_all on charges
    for all using (org_id = current_org_id());

-- Orders & items.
create policy rls_orders_all on orders
    for all using (org_id = current_org_id());

create policy rls_order_items_all on order_items
    for all using (
        order_id in (
            select id from orders where org_id = current_org_id()
        )
    );

-- Audit log — read-only for the app role.
create policy rls_audit_log_select on audit_log
    for select using (org_id = current_org_id());

-- API keys & webhooks scoped to current org.
create policy rls_api_keys_all on api_keys
    for all using (org_id = current_org_id());

create policy rls_webhook_endpoints_all on webhook_endpoints
    for all using (org_id = current_org_id());

create policy rls_webhook_deliveries_all on webhook_deliveries
    for all using (
        endpoint_id in (
            select id from webhook_endpoints where org_id = current_org_id()
        )
    );


-- =============================================================================
-- SECTION 16 — SEED DATA (development only)
-- =============================================================================
-- Wrap in a transaction so a failed seed doesn't leave partial data.

begin;

-- Plans
insert into plans (id, name, slug, interval, price_cents, limits, sort_order) values
    ('11111111-0000-0000-0000-000000000001', 'Starter',    'starter',    'monthly',   0,     '{"seats":1,"api_calls_per_month":5000,"storage_gb":2}',    1),
    ('11111111-0000-0000-0000-000000000002', 'Growth',     'growth',     'monthly',   4900,  '{"seats":5,"api_calls_per_month":50000,"storage_gb":20}',   2),
    ('11111111-0000-0000-0000-000000000003', 'Pro',        'pro',        'monthly',   9900,  '{"seats":15,"api_calls_per_month":200000,"storage_gb":100}', 3),
    ('11111111-0000-0000-0000-000000000004', 'Enterprise', 'enterprise', 'annual',    0,     '{"seats":null,"api_calls_per_month":null,"storage_gb":null}',4);

-- Demo org
insert into organisations (id, name, slug, billing_email) values
    ('22222222-0000-0000-0000-000000000001', 'Acme Corp', 'acme-corp', 'billing@acme.example');

-- Demo user (password: "hunter2" — bcrypt hash below is for demo purposes only)
insert into users (id, email, password_hash, full_name, email_verified_at) values
    (
        '33333333-0000-0000-0000-000000000001',
        'jane@acme.example',
        '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj3bp.Pj5yCm',
        'Jane Doe',
        now()
    );

-- Membership
insert into org_members (org_id, user_id, role, accepted_at) values
    ('22222222-0000-0000-0000-000000000001', '33333333-0000-0000-0000-000000000001', 'owner', now());

-- Active subscription on Growth plan
insert into subscriptions (
    org_id, plan_id, status,
    current_period_start, current_period_end,
    trial_end
) values (
    '22222222-0000-0000-0000-000000000001',
    '11111111-0000-0000-0000-000000000002',
    'trialing',
    now(),
    now() + interval '30 days',
    now() + interval '14 days'
);

commit;


-- =============================================================================
-- END OF SCHEMA
-- =============================================================================
