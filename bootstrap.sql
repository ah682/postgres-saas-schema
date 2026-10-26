-- Apply once after schema.sql in a fresh database, as the schema owner with
-- CREATEROLE. Role names are cluster-wide; this fails if saas_app already exists
-- so an existing role's privileges cannot silently change the security boundary.
-- Provision an authenticated server LOGIN separately; grant it saas_app only.
BEGIN;
CREATE ROLE saas_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
    NOREPLICATION NOBYPASSRLS;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO saas_app;

GRANT SELECT, UPDATE ON organisations TO saas_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    org_members, subscriptions, invoices, invoice_line_items, payment_methods,
    charges, orders, order_items, api_keys, webhook_endpoints, webhook_deliveries,
    notifications TO saas_app;
GRANT SELECT ON plans, products, audit_log TO saas_app;
-- No TRUNCATE, REFERENCES, schema CREATE, ownership or role administration.
-- No auth, personal notification preference or coupon administration access.
-- Audit writes use a separate trusted administrative service; saas_app can
-- neither forge events nor update/delete history. Owners remain trusted.
-- New tables receive no automatic grants: decide their scope explicitly.
COMMIT;
