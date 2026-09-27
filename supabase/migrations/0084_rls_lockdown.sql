-- ============================================================
-- 0084 — RLS lockdown: role-scoped reads + private storage buckets
-- ------------------------------------------------------------
-- Until now nearly every table carried "read for authenticated" USING (true),
-- so any signed-in account could SELECT salaries, payroll, claims and the GL
-- straight from PostgREST, and five storage buckets were public-read. Writes
-- were already gated (RPCs + assert_access); this closes the read side.
--
--  * public.can_read(module, min_level) — boolean twin of assert_access (same
--    enforce_access switch, same three hard-coded editors, same
--    user_permissions lookup), for use inside policies.
--  * HR, finance, claims and admin tables: replace USING (true) with
--    module-level or own-row policies.
--  * Buckets uploads / dispatch-receipts / engagement-docs / compliance-docs /
--    project-docs become private; reads need an authenticated user with the
--    matching module grant (the client now opens files via signed URLs).
--
-- SECURITY DEFINER RPCs (bootstrap, my_hr_summary, …) bypass RLS and are
-- unchanged. Every table not named here keeps its existing policy.
-- See docs/RLS-LOCKDOWN.md for the per-role before/after and the rollback.
-- Idempotent: safe to re-run.
-- ============================================================

-- ---------- helpers ----------

-- Mirrors assert_access (0073) but returns true/false instead of raising.
create or replace function public.can_read(p_module text, p_min_level int default 1) returns boolean
language plpgsql stable security definer set search_path = public as $$
declare
  v_on boolean := coalesce((select value::text = 'true' from public.app_config where key = 'enforce_access'), false);
  v_email text := coalesce(nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email', '');
  v_level int;
begin
  if not v_on then return true; end if;
  if coalesce(current_setting('jikoni.system_action', true), '') = 'true' then return true; end if;
  if lower(v_email) in (
       'jwanjiku@ignis-innovation.com', 'dnderitu@ignis-innovation.com', 'brian55mwangi@gmail.com') then
    return true;
  end if;
  -- Non-editors are view-only everywhere (0073), so a level >= 2 check never passes for them.
  if p_min_level >= 2 then return false; end if;
  select level into v_level from public.user_permissions where email = v_email and module = p_module;
  return coalesce(v_level, 0) >= p_min_level;
end $$;

grant execute on function public.can_read(text, int) to authenticated;

-- The caller's app_users.id (null when signed out / not provisioned).
create or replace function public.my_app_user_id() returns uuid
language sql stable security definer set search_path = public as $$
  select id from public.app_users where auth_id = (select auth.uid())
$$;

grant execute on function public.my_app_user_id() to authenticated;

-- ---------- HR-sensitive: HR readers or the row's own staff member ----------

do $$
declare
  r record;
begin
  -- table, own-row condition (null = HR only)
  for r in select * from (values
    ('staff_files',        'app_user_id = (select public.my_app_user_id())'),
    ('appraisals',         'app_user_id = (select public.my_app_user_id()) or reviewer_id = (select public.my_app_user_id())'),
    ('staff_feedback',     'author_id = (select public.my_app_user_id())'),
    ('staff_exits',        'app_user_id = (select public.my_app_user_id())'),
    ('certifications',     'app_user_id = (select public.my_app_user_id())'),
    ('leave_applications', 'app_user_id = (select public.my_app_user_id()) or approver_id = (select public.my_app_user_id())'),
    ('leave_balances',     'app_user_id = (select public.my_app_user_id())'),
    ('leave_policies',     null),
    ('candidates',         null),
    ('recruitment_reqs',   null)
  ) as t(tbl, own)
  loop
    execute format('drop policy if exists "read for authenticated" on public.%I', r.tbl);
    execute format('drop policy if exists "rls84 read" on public.%I', r.tbl);
    execute format('create policy "rls84 read" on public.%I for select to authenticated using ((select public.can_read(''hr'', 1))%s)',
                   r.tbl, case when r.own is null then '' else ' or ' || r.own end);
  end loop;
end $$;

-- Payroll: HR/finance editors only, plus each staff member's own payslip line.
drop policy if exists "read for authenticated" on public.payroll_runs;
drop policy if exists "rls84 read" on public.payroll_runs;
create policy "rls84 read" on public.payroll_runs for select to authenticated
  using ((select public.can_read('hr', 2)) or (select public.can_read('finance', 2)));

drop policy if exists "read for authenticated" on public.payroll_items;
drop policy if exists "rls84 read" on public.payroll_items;
create policy "rls84 read" on public.payroll_items for select to authenticated
  using ((select public.can_read('hr', 2)) or (select public.can_read('finance', 2))
         or app_user_id = (select public.my_app_user_id()));

-- ---------- finance ----------

do $$
declare
  t text;
begin
  foreach t in array array['journal_entries','journal_lines','invoices_ap','payments','bank_accounts',
                           'sales_invoices','petty_cash_floats','budget_lines','mpesa_payments','etims_submissions'] loop
    execute format('drop policy if exists "read for authenticated" on public.%I', t);
    execute format('drop policy if exists "rls84 read" on public.%I', t);
    execute format('create policy "rls84 read" on public.%I for select to authenticated using ((select public.can_read(''finance'', 1)))', t);
  end loop;
end $$;

drop policy if exists "proformas read" on public.proformas;
drop policy if exists "rls84 read" on public.proformas;
create policy "rls84 read" on public.proformas for select to authenticated
  using ((select public.can_read('finance', 1)));

drop policy if exists "proforma_lines read" on public.proforma_lines;
drop policy if exists "rls84 read" on public.proforma_lines;
create policy "rls84 read" on public.proforma_lines for select to authenticated
  using ((select public.can_read('finance', 1)));

-- Procurement approves vendor bank changes (Vendors tab), so it keeps sight of them.
drop policy if exists "read for authenticated" on public.vendor_bank_changes;
drop policy if exists "rls84 read" on public.vendor_bank_changes;
create policy "rls84 read" on public.vendor_bank_changes for select to authenticated
  using ((select public.can_read('finance', 1)) or (select public.can_read('procurement', 1)));

-- ---------- staff money requests: own rows, finance or HR ----------

drop policy if exists "read expense claims" on public.expense_claims;
drop policy if exists "rls84 read" on public.expense_claims;
create policy "rls84 read" on public.expense_claims for select to authenticated
  using (requester_id = (select public.my_app_user_id())
         or (select public.can_read('finance', 1)) or (select public.can_read('hr', 1)));

-- Lines follow their parent: the subquery is itself filtered by the claim policy.
drop policy if exists "read expense claim lines" on public.expense_claim_lines;
drop policy if exists "rls84 read" on public.expense_claim_lines;
create policy "rls84 read" on public.expense_claim_lines for select to authenticated
  using (exists (select 1 from public.expense_claims c where c.id = claim_id));

drop policy if exists "read travel advances" on public.travel_advances;
drop policy if exists "rls84 read" on public.travel_advances;
create policy "rls84 read" on public.travel_advances for select to authenticated
  using (holder_id = (select public.my_app_user_id())
         or (select public.can_read('finance', 1)) or (select public.can_read('hr', 1)));

drop policy if exists "read travel advance lines" on public.travel_advance_lines;
drop policy if exists "rls84 read" on public.travel_advance_lines;
create policy "rls84 read" on public.travel_advance_lines for select to authenticated
  using (exists (select 1 from public.travel_advances a where a.id = advance_id));

drop policy if exists "read petty cash requests" on public.petty_cash_requests;
drop policy if exists "rls84 read" on public.petty_cash_requests;
create policy "rls84 read" on public.petty_cash_requests for select to authenticated
  using (requester_id = (select public.my_app_user_id())
         or (select public.can_read('finance', 1)) or (select public.can_read('hr', 1)));

-- ---------- admin-only (User Management holders: super / sub admin) ----------
-- app_config stays readable: the client reads it directly (finance loader).
-- oauth_connections and app_secrets keep NO client policy (fully locked, 0046):
-- an own-row policy would expose OAuth tokens to the browser.

do $$
declare
  t text;
begin
  foreach t in array array['audit_log','invites','sod_conflicts'] loop
    execute format('drop policy if exists "read for authenticated" on public.%I', t);
    execute format('drop policy if exists "rls84 read" on public.%I', t);
    execute format('create policy "rls84 read" on public.%I for select to authenticated using ((select public.can_read(''users'', 1)))', t);
  end loop;
end $$;

-- ---------- storage: private buckets, module-scoped reads ----------
-- Insert/update policies from 0014/0021/0023/0025/0041 are kept as they are.

update storage.buckets set public = false
 where id in ('uploads', 'dispatch-receipts', 'engagement-docs', 'compliance-docs', 'project-docs');

drop policy if exists "dispatch receipts read" on storage.objects;
create policy "dispatch receipts read" on storage.objects for select to authenticated
  using (bucket_id = 'dispatch-receipts' and (select public.can_read('inventory', 1)));

drop policy if exists "engagement docs read" on storage.objects;
create policy "engagement docs read" on storage.objects for select to authenticated
  using (bucket_id = 'engagement-docs' and (select public.can_read('crm', 1)));

drop policy if exists "compliance-docs read" on storage.objects;
create policy "compliance-docs read" on storage.objects for select to authenticated
  using (bucket_id = 'compliance-docs' and (select public.can_read('compliance', 1)));

drop policy if exists "project-docs read" on storage.objects;
create policy "project-docs read" on storage.objects for select to authenticated
  using (bucket_id = 'project-docs' and (select public.can_read('projects', 1)));

-- 'uploads' holds petty-cash invoices, claim/advance receipts, weekly-report and
-- GRN attachments under shared prefixes with no owner segment, so ownership can't
-- be derived from the path: any signed-in user (no longer the open internet).
drop policy if exists "uploads read" on storage.objects;
create policy "uploads read" on storage.objects for select to authenticated
  using (bucket_id = 'uploads');
