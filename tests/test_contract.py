"""Behavioral contract against a disposable, real PostgreSQL database."""
import os
import subprocess
import unittest

A = '22222222-0000-0000-0000-000000000001'
B = '22222222-0000-0000-0000-000000000002'
UA = '33333333-0000-0000-0000-000000000001'
UB = '33333333-0000-0000-0000-000000000002'
PLAN = '11111111-0000-0000-0000-000000000002'

def ident(n):
    return f'90000000-0000-0000-0000-{n:012d}'


def psql(sql, role=None):
    env = dict(os.environ)
    if role:
        env['PGUSER'] = 'saas_test_login'
        env['PGOPTIONS'] = '-c role=saas_app' if role == 'saas_app' else ''
    return subprocess.run(['psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1',
                           '-v', 'VERBOSITY=verbose'], input=sql, text=True,
                          capture_output=True, env=env)


class TenantContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = f"""
        INSERT INTO organisations(id,name,slug,billing_email) VALUES ('{B}','Beta','beta','b@example.test');
        INSERT INTO users(id,email,full_name) VALUES ('{UB}','b@example.test','Beta User');
        INSERT INTO org_members(org_id,user_id) VALUES ('{B}','{UB}');
        INSERT INTO products(id,name,slug,price_cents) VALUES ('{ident(1)}','Fixture','fixture',100);
        """
        for org, user, base in [(A, UA, 10), (B, UB, 20)]:
            fixture += f"""
            INSERT INTO subscriptions(id,org_id,plan_id,current_period_start,current_period_end)
              VALUES ('{ident(base)}','{org}','{PLAN}',now(),now()+interval '1 month');
            INSERT INTO invoices(id,org_id,subscription_id,total_cents,amount_paid_cents)
              VALUES ('{ident(base+1)}','{org}','{ident(base)}',500,100);
            INSERT INTO invoice_line_items(invoice_id,description,quantity,unit_price_cents)
              VALUES ('{ident(base+1)}','fixture',2,150);
            INSERT INTO payment_methods(id,org_id) VALUES ('{ident(base+2)}','{org}');
            INSERT INTO charges(id,org_id,invoice_id,payment_method_id,amount_cents)
              VALUES ('{ident(base+3)}','{org}','{ident(base+1)}','{ident(base+2)}',100);
            INSERT INTO orders(id,org_id,user_id,invoice_id,charge_id,total_cents)
              VALUES ('{ident(base+4)}','{org}','{user}','{ident(base+1)}','{ident(base+3)}',100);
            INSERT INTO order_items(order_id,product_id,quantity,unit_price_cents)
              VALUES ('{ident(base+4)}','{ident(1)}',2,150);
            INSERT INTO audit_log(org_id,user_id,action) VALUES ('{org}','{user}','create');
            INSERT INTO api_keys(org_id,created_by,name,key_prefix,key_hash)
              VALUES ('{org}','{user}','fixture','testkey1','fixture-{base}');
            INSERT INTO webhook_endpoints(id,org_id,url,secret_hash)
              VALUES ('{ident(base+5)}','{org}','https://example.test','not-a-real-secret');
            INSERT INTO webhook_deliveries(endpoint_id,event_type,payload)
              VALUES ('{ident(base+5)}','fixture','{{}}');
            INSERT INTO notifications(org_id,user_id,type,title) VALUES ('{org}','{user}','fixture','fixture');
            """
        fixture += f"INSERT INTO notifications(user_id,type,title) VALUES ('{UA}','global','global');"
        result = psql(fixture)
        if result.returncode:
            raise AssertionError(result.stderr)

    def query(self, sql, org=A):
        context = f"SET LOCAL app.current_org_id = '{org}';" if org else ''
        return psql(f'BEGIN; {context} {sql}; ROLLBACK;', 'saas_app')

    def assert_ok(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def assert_error(self, sql, code, org=A):
        result = self.query(sql, org)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(code, result.stderr)

    def test_app_role_cannot_bypass_or_own_schema(self):
        self.assertEqual(self.assert_ok(self.query('SELECT current_user; SELECT session_user')),
                         'saas_app\nsaas_test_login')
        self.assertEqual(self.assert_ok(psql("""
            SELECT count(*) FROM pg_roles WHERE rolname='saas_app' AND
              NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolcanlogin;
            SELECT count(*) FROM pg_class WHERE relnamespace='public'::regnamespace
              AND relowner=(SELECT oid FROM pg_roles WHERE rolname='saas_app');
            SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname='saas_app');
        """)), '1\n0\n0')
        self.assertEqual(self.assert_ok(psql("SELECT count(*) FROM pg_roles WHERE rolname='saas_test_login' AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole AND NOT rolcreatedb")), '1')
        self.assert_error('CREATE TABLE public.forbidden(id int)', '42501')
        self.assert_error('ALTER TABLE invoices DISABLE ROW LEVEL SECURITY', '42501')
        self.assert_error('TRUNCATE invoices CASCADE', '42501')
        self.assert_error('SET ROLE postgres', '42501')

    def test_all_scoped_tables_deny_without_context_and_show_only_selected_tenant(self):
        # Child tables derive tenant through their single parent; global notifications stay hidden.
        for table in ['organisations','org_members','invoices','invoice_line_items',
                      'payment_methods','charges','orders','order_items','audit_log',
                      'api_keys','webhook_endpoints','webhook_deliveries','notifications']:
            for org, expected in [(None,'0'), (A,'1'), (B,'1')]:
                with self.subTest(table=table, org=org):
                    self.assertEqual(self.assert_ok(self.query(f'SELECT count(*) FROM {table}', org)), expected)
        self.assertEqual(self.assert_ok(self.query('SELECT count(*) FROM subscriptions')), '2')
        self.assertEqual(self.assert_ok(self.query('SELECT count(*) FROM subscriptions', B)), '1')
        self.assertEqual(self.assert_ok(self.query('SELECT count(*) FROM subscriptions', None)), '0')

    def test_global_auth_and_preferences_are_not_tenant_role_data(self):
        for table in ['users','sessions','one_time_tokens','oauth_accounts','notification_preferences','coupons']:
            with self.subTest(table=table):
                self.assert_error(f'SELECT * FROM {table}', '42501')
        self.assertEqual(self.assert_ok(self.query('SELECT count(*) FROM plans')), '4')
        self.assert_error("INSERT INTO plans(name,slug,interval,price_cents) VALUES ('x','x','monthly',0)", '42501')

    def test_context_is_transaction_local_on_reused_connection(self):
        sql = f"""
        SELECT count(*) FROM invoices;
        BEGIN; SET LOCAL app.current_org_id='{A}'; SELECT count(*) FROM invoices; COMMIT;
        SELECT count(*) FROM invoices;
        BEGIN; SET LOCAL app.current_org_id='{B}'; SELECT count(*) FROM invoices; ROLLBACK;
        SELECT count(*) FROM invoices;
        BEGIN; SET LOCAL app.current_org_id='{A}';
        DO $$ BEGIN RAISE EXCEPTION 'simulate application failure'; END $$;
        ROLLBACK; SELECT count(*) FROM invoices;
        """
        # Continue after the deliberate SQL error to exercise rollback on the same physical connection.
        result = psql('\\set ON_ERROR_STOP off\n' + sql, 'saas_app')
        self.assertEqual(self.assert_ok(result), '0\n1\n0\n1\n0\n0')
        self.assertIn('simulate application failure', result.stderr)
        self.assert_error('SELECT * FROM invoices', '22P02', org='malformed')
        self.assertEqual(self.assert_ok(self.query("SET LOCAL app.current_org_id=''; SELECT count(*) FROM invoices")), '0')

    def test_documented_local_role_and_context_reset_together(self):
        result = psql(f"""
            BEGIN; SET LOCAL ROLE saas_app; SET LOCAL app.current_org_id='{A}';
            SELECT count(*) FROM invoices; COMMIT; SELECT current_user;
            BEGIN; SET LOCAL ROLE saas_app;
            SELECT count(*) FROM invoices; ROLLBACK; SELECT current_user;
        """, 'server_login')
        self.assertEqual(self.assert_ok(result), '1\nsaas_test_login\n0\nsaas_test_login')

    def test_tenant_guc_is_not_authentication(self):
        # An arbitrary SQL-capable caller can select B. The trusted server must authorize first.
        self.assertEqual(self.assert_ok(self.query('SELECT name FROM organisations', B)), 'Beta')
        self.assertEqual(self.assert_ok(psql('SELECT count(*) FROM organisations')), '2')

    def test_cross_tenant_writes_and_reparenting_are_denied(self):
        self.assert_error(f"INSERT INTO invoices(org_id) VALUES ('{B}')", '42501')
        self.assert_error(f"INSERT INTO invoices(org_id) VALUES ('{A}')", '42501', None)
        self.assert_error(f"UPDATE invoices SET org_id='{B}' WHERE id='{ident(11)}'", '42501')
        self.assertEqual(self.assert_ok(self.query(f"WITH d AS (DELETE FROM invoices WHERE id='{ident(21)}' RETURNING id) SELECT count(*) FROM d")), '0')
        self.assertEqual(self.assert_ok(self.query(f"WITH u AS (UPDATE invoices SET total_cents=1 WHERE id='{ident(21)}' RETURNING id) SELECT count(*) FROM u")), '0')
        for sql in [
            f"INSERT INTO invoice_line_items(invoice_id,description,unit_price_cents) VALUES ('{ident(21)}','foreign',1)",
            f"INSERT INTO order_items(order_id,product_id,unit_price_cents) VALUES ('{ident(24)}','{ident(1)}',1)",
            f"INSERT INTO webhook_deliveries(endpoint_id,event_type,payload) VALUES ('{ident(25)}','foreign','{{}}')",
            f"UPDATE invoice_line_items SET invoice_id='{ident(21)}'",
            f"UPDATE order_items SET order_id='{ident(24)}'",
            f"UPDATE webhook_deliveries SET endpoint_id='{ident(25)}'",
        ]:
            with self.subTest(sql=sql):
                self.assert_error(sql, '42501')

    def test_membership_and_notifications_are_usable_and_tenant_scoped(self):
        self.assertEqual(self.assert_ok(self.query("WITH u AS (UPDATE org_members SET role='viewer' RETURNING role) SELECT role FROM u")), 'viewer')
        self.assert_error(f"INSERT INTO org_members(org_id,user_id) VALUES ('{B}','{UA}')", '42501')
        self.assert_error(f"UPDATE org_members SET org_id='{B}'", '42501')
        self.assertEqual(self.assert_ok(self.query("WITH u AS (UPDATE notifications SET read_at=now() RETURNING id) SELECT count(*) FROM u")), '1')
        self.assert_ok(self.query(f"INSERT INTO notifications(org_id,user_id,type,title) VALUES ('{A}','{UA}','ok','ok')"))
        self.assert_error(f"INSERT INTO notifications(org_id,user_id,type,title) VALUES ('{B}','{UB}','bad','bad')", '42501')
        self.assert_error(f"INSERT INTO notifications(user_id,type,title) VALUES ('{UA}','global','global')", '42501')

    def test_global_identity_can_join_multiple_orgs_through_authorized_server(self):
        # The trusted server has authorized this membership operation. Identities remain global.
        self.assertEqual(self.assert_ok(self.query(f"WITH i AS (INSERT INTO org_members(org_id,user_id) VALUES ('{A}','{UB}') RETURNING user_id) SELECT user_id FROM i")), UB)
        self.assertEqual(self.assert_ok(self.query(f"INSERT INTO org_members(org_id,user_id) VALUES ('{A}','{UB}'); WITH d AS (DELETE FROM org_members WHERE org_id='{A}' AND user_id='{UB}' RETURNING id) SELECT count(*) FROM d")), '1')

    def test_tenant_linked_foreign_keys_reject_other_tenants(self):
        cases = [
            f"INSERT INTO invoices(org_id,subscription_id) VALUES ('{A}','{ident(20)}')",
            f"INSERT INTO charges(org_id,invoice_id,amount_cents) VALUES ('{A}','{ident(21)}',1)",
            f"INSERT INTO charges(org_id,payment_method_id,amount_cents) VALUES ('{A}','{ident(22)}',1)",
            f"INSERT INTO orders(org_id,user_id,invoice_id,total_cents) VALUES ('{A}','{UA}','{ident(21)}',1)",
            f"INSERT INTO orders(org_id,user_id,charge_id,total_cents) VALUES ('{A}','{UA}','{ident(23)}',1)",
            f"INSERT INTO orders(org_id,user_id,total_cents) VALUES ('{A}','{UB}',1)",
            f"INSERT INTO api_keys(org_id,created_by,name,key_prefix,key_hash) VALUES ('{A}','{UB}','bad','testkey1','bad')",
            f"INSERT INTO notifications(org_id,user_id,type,title) VALUES ('{A}','{UB}','bad','bad')",
            f"UPDATE invoices SET subscription_id='{ident(20)}' WHERE id='{ident(11)}'",
            f"UPDATE charges SET payment_method_id='{ident(22)}' WHERE id='{ident(13)}'",
        ]
        for sql in cases:
            with self.subTest(sql=sql):
                self.assert_error(sql, '23503')
                # Integrity is a schema invariant even for a trusted owner bypassing RLS.
                result = psql(f'BEGIN; {sql}; ROLLBACK;')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('23503', result.stderr)

    def test_same_tenant_nullable_links_and_generated_amounts(self):
        self.assert_ok(self.query(f"INSERT INTO invoices(org_id,subscription_id) VALUES ('{A}','{ident(10)}')"))
        self.assert_ok(self.query(f"INSERT INTO invoices(org_id) VALUES ('{A}')"))
        self.assert_ok(self.query(f"INSERT INTO charges(org_id,amount_cents) VALUES ('{A}',1)"))
        self.assertEqual(self.assert_ok(self.query('SELECT amount_due_cents FROM invoices')), '400')
        self.assertEqual(self.assert_ok(self.query('SELECT total_cents FROM invoice_line_items')), '300')
        self.assert_error(f"INSERT INTO invoice_line_items(invoice_id,description,quantity,unit_price_cents) VALUES ('{ident(11)}','bad',0,1)", '23514')
        self.assert_error(f"INSERT INTO payment_methods(org_id,is_default) VALUES ('{A}',true),('{A}',true)", '23505')

    def test_app_cannot_forge_or_modify_audit_history(self):
        self.assert_error("UPDATE audit_log SET resource_type='forged'", '42501')
        self.assert_error('DELETE FROM audit_log', '42501')
        self.assert_error(f"INSERT INTO audit_log(org_id,action) VALUES ('{A}','create')", '42501')

    def test_api_key_revocation_update_works(self):
        self.assertEqual(self.assert_ok(self.query(f"WITH u AS (UPDATE api_keys SET revoked_at=now() WHERE org_id='{A}' RETURNING revoked_at) SELECT count(*) FROM u WHERE revoked_at IS NOT NULL")), '1')


if __name__ == '__main__':
    unittest.main(verbosity=2)
