# RLS lockdown (migration 0084)

Status: **prepared, not applied.** Branch `kazi/jikoni-rls-lockdown`. This touches RLS and storage, so Ob or Mike should review it and apply it by hand.

## What changes

Before 0084, nearly every table had `"read for authenticated" USING (true)`. Any signed-in account could `SELECT` salaries, payroll, claims, the GL and the audit log straight from PostgREST, and five storage buckets could be read by anyone with a link.

After 0084:

- **`public.can_read(module, min_level)`** is a boolean version of `assert_access` (0073). It uses the same `app_config.enforce_access` switch, the same three hard-coded editors and the same `user_permissions` lookup. Non-editors are view-only, so any `min_level >= 2` check passes only for the three editors. **`public.my_app_user_id()`** returns the caller's `app_users.id`.
- Policies call both helpers as `(select …)`, so Postgres evaluates them once per query, not once per row.
- SECURITY DEFINER RPCs (`bootstrap`, `my_hr_summary`, every write RPC) ignore RLS and are unchanged. Payslips, own leave and own documents in the Staff Portal come from `my_hr_summary`, so staff keep them.

| Tables | New read rule |
|---|---|
| staff_files, staff_exits, certifications, leave_balances | `can_read('hr',1)` OR own row (`app_user_id`) |
| appraisals | HR OR subject (`app_user_id`) OR reviewer (`reviewer_id`) |
| leave_applications | HR OR applicant (`app_user_id`) OR approver (`approver_id`) |
| staff_feedback | HR OR author (`author_id`). Anonymous feedback (null author) is HR-only |
| leave_policies, candidates, recruitment_reqs | HR only. The public careers page uses the `list_public_jobs` / `apply_to_job` RPCs, so it is unaffected |
| payroll_runs | `can_read('hr',2)` OR `can_read('finance',2)`, which in practice means the three editors |
| payroll_items | same as payroll_runs, OR the staff member's own line |
| journal_entries, journal_lines, invoices_ap, payments, bank_accounts, sales_invoices, proformas, proforma_lines, petty_cash_floats, budget_lines, mpesa_payments, etims_submissions | `can_read('finance',1)` |
| vendor_bank_changes | finance OR `can_read('procurement',1)`. Procurement approves bank changes on the Vendors tab |
| expense_claims, travel_advances, petty_cash_requests | own row (`requester_id` / `holder_id`) OR finance OR HR |
| expense_claim_lines, travel_advance_lines | visible when the parent claim/advance is visible (`exists` on the parent, which is itself filtered by RLS) |
| audit_log, invites, sod_conflicts | `can_read('users',1)`: User Management holders (super / sub admin) |

**Unchanged on purpose:**
- `app_config`: the client reads it directly.
- `oauth_connections` and `app_secrets`: they already have no client policy and are fully locked (0046). An own-row policy would expose OAuth tokens to the browser.
- `notifications` and `weekly_reports` already have own-row policies.
- `staff-documents` and `job-applications` buckets: already private.
- Every other table keeps `USING (true)`: entities, app_users, user_permissions, role_templates, record_transitions, chart_of_accounts, documents, ref_counters, vendors, vendor_screenings, approval_matrix, requisitions, purchase_orders, goods_received_notes, tasks, engagements (+ notes, updates, partners, documents), eng_project_links, projects (+ members, budget items, expenses, milestones, drawdowns), field_activities, stock_* tables, dispatches, assets, asset_assignments, asset_depreciations, statutory_rates, enumerators, field_assignments, raise_pipeline, term_sheets, dataroom_*, diligence_requests, policies, company_documents, compliance_obligations, risks, contracts, sanctions_checks, partners, opportunities, crm_dropdown_options, recurring_bills, rate_limit, notifications, weekly_reports.

### Storage

`uploads`, `dispatch-receipts`, `engagement-docs`, `compliance-docs` and `project-docs` become **private** (`public = false`). The public read policies are replaced with authenticated ones:

| Bucket | Read rule |
|---|---|
| dispatch-receipts | `can_read('inventory',1)` |
| engagement-docs | `can_read('crm',1)` |
| compliance-docs | `can_read('compliance',1)` |
| project-docs | `can_read('projects',1)` |
| uploads | any authenticated user. Petty-cash invoices, claim/advance receipts, weekly-report and GRN attachments sit under shared prefixes (`petty-cash/`, `claims/`, …) with no owner segment, so the owner can't be derived from the path |

Insert and update policies are kept as they are.

### Client

`getPublicUrl` is gone. `src/lib/signedUrl.ts` adds `signedUrlFor(bucket, pathOrUrl)` and `openSignedUrl(bucket, pathOrUrl, downloadName?)`. They sign for 1 hour at click time and accept either an object path or an old full public URL. No stored URLs are migrated.

The store helpers `uploadedFileUrl`, `projectDocUrl`, `engDocUrl`, `complianceDocUrl` and `receiptUrl` become `openUploadedFile`, `openProjectDoc`, `openEngDoc`, `openComplianceDoc` and `openDispatchReceipt`. Each shows a toast when the file can't be signed. Call sites: `Receipts.tsx`, `drawers.tsx`, `StaffPortal.tsx`, `Hr.tsx`, `Finance.tsx`, `Compliance.tsx`, `Inventory.tsx`.

## Who can read what: before vs after

Levels are the role templates in `src/data.ts`. After 0073, every account except the three editors is clamped to view (at most level 1), and the rules below assume that. Access really comes from each person's `user_permissions` rows, so anyone with custom grants follows their grants, not the template.

| Data | Before (all roles) | Editors (3) | super / sub (non-editor) | admin | fin | std | view |
|---|---|---|---|---|---|---|---|
| staff_files (incl. gross_salary), appraisals, exits, certs, leave | all rows | all | all (hr 1) | own only | all (hr 1) | own only | own only |
| candidates, recruitment_reqs, leave_policies | all | all | all | none | all | none | none |
| payroll_runs | all | all | none | none | none | none | none |
| payroll_items | all | all | own line | own line | own line | own line | own line |
| GL, AP, payments, bank, sales, proformas, floats, budgets, M-Pesa, eTIMS | all | all | all | all | all | none | none |
| vendor_bank_changes | all | all | all | all | all | all (procurement 1) | none |
| expense claims / advances / petty cash (+ lines) | all | all | all | all (finance) | all | own only | own only |
| audit_log, invites, sod_conflicts | all | all | all (users 1) | none | none | none | none |
| dispatch-receipts files | public internet | yes | yes | yes | yes | yes | no |
| engagement-docs files | public internet | yes | yes | yes | yes | yes | yes |
| compliance-docs files | public internet | yes | yes | yes | yes | yes | yes |
| project-docs files | public internet | yes | yes | yes | yes | yes | no |
| uploads files | public internet | signed-in | signed-in | signed-in | signed-in | signed-in | signed-in |

**HR permission holders** (anyone with `user_permissions.hr >= 1`) see every row in the HR tables, including `gross_salary`, but not `payroll_runs` or other people's `payroll_items`.

## Direct client reads checked

These are the `supabase.from(...).select` calls in `src/`. Everything else goes through RPCs.

- **Staff Portal / everyone:** tasks, app_users, field_activities, notifications, petty_cash_requests, expense_claims (+ lines), travel_advances (+ lines), recurring_bills, weekly_reports. Claims, advances and petty cash now return the caller's own rows for staff, and all rows for finance/HR, which is what the approval queues need.
- **Finance loader:** vendors, invoices_ap, payments, journal_entries (+ lines), app_config, audit_log, vendor_bank_changes, POs, GRNs, requisitions. Users without finance/users/procurement grants get empty lists instead of errors.
- **HR loaders:** leave_applications, leave_balances, staff_files, payroll_runs (+ items), recruitment_reqs (+ candidates), enumerators, field_assignments, appraisals, certifications, staff_feedback, staff_exits. HR-level-1 viewers now see an empty payroll list, because payroll is limited to HR/finance level 2, which only the editors hold.
- **Inventory:** stock_movements, dispatches, assets, asset_assignments (unchanged).
- **CRM:** partners (unchanged).

## Known risks / decisions

1. **gross_salary has no column-level restriction.** The HR view selects `gross_salary` directly (`store.tsx`, `loadHrModule`), and no existing SECURITY DEFINER RPC returns it. Revoking the column would break the Personnel tab for everyone. HR level-1 viewers therefore still see salaries through their row access. To go further, add an HR RPC that returns staff files with the salary, revoke `select (gross_salary)` from `authenticated`, and drop it from the direct query.
2. **`enforce_access = false` turns every rule off.** `can_read` mirrors `assert_access`, so with the switch off it returns true and reads are open again. Keep it on (0008 sets it).
3. **uploads** is readable by any signed-in user, which is much narrower than the public internet but not per-owner. The fix is to add the owner's id to upload paths and scope the policy to it.
4. **Hard-coded editor emails** are repeated in `can_read`. Keep them in sync with 0073 and `GLOBAL_EDITORS`.
5. **Popup handling.** `openSignedUrl` opens the tab synchronously and then sets its URL. Browsers that block `about:blank` popups fall back to a normal `window.open`.
6. **Not tested against the hosted DB** (by design). It was checked on a throwaway local Postgres 16 with stub tables: it applied cleanly twice (idempotent), and the per-role row counts matched the table above.

## Apply (Ob / Mike)

```
node scripts/apply-sql.mjs supabase/migrations/0084_rls_lockdown.sql
```

Deploy the client change (merge the branch) at the same time. Once the buckets are private, the old `getPublicUrl` links in a deployed build stop working.

## Rollback

```sql
do $$
declare t text;
begin
  foreach t in array array['staff_files','appraisals','staff_feedback','staff_exits','certifications',
    'leave_applications','leave_balances','leave_policies','candidates','recruitment_reqs',
    'payroll_runs','payroll_items','journal_entries','journal_lines','invoices_ap','payments',
    'bank_accounts','sales_invoices','petty_cash_floats','budget_lines','mpesa_payments',
    'etims_submissions','vendor_bank_changes','audit_log','invites','sod_conflicts'] loop
    execute format('drop policy if exists "rls84 read" on public.%I', t);
    execute format('drop policy if exists "read for authenticated" on public.%I', t);
    execute format('create policy "read for authenticated" on public.%I for select to authenticated using (true)', t);
  end loop;
end $$;

drop policy if exists "rls84 read" on public.proformas;
drop policy if exists "proformas read" on public.proformas;
create policy "proformas read" on public.proformas for select to authenticated using (true);
drop policy if exists "rls84 read" on public.proforma_lines;
drop policy if exists "proforma_lines read" on public.proforma_lines;
create policy "proforma_lines read" on public.proforma_lines for select to authenticated using (true);
drop policy if exists "rls84 read" on public.expense_claims;
drop policy if exists "read expense claims" on public.expense_claims;
create policy "read expense claims" on public.expense_claims for select to authenticated using (true);
drop policy if exists "rls84 read" on public.expense_claim_lines;
drop policy if exists "read expense claim lines" on public.expense_claim_lines;
create policy "read expense claim lines" on public.expense_claim_lines for select to authenticated using (true);
drop policy if exists "rls84 read" on public.travel_advances;
drop policy if exists "read travel advances" on public.travel_advances;
create policy "read travel advances" on public.travel_advances for select to authenticated using (true);
drop policy if exists "rls84 read" on public.travel_advance_lines;
drop policy if exists "read travel advance lines" on public.travel_advance_lines;
create policy "read travel advance lines" on public.travel_advance_lines for select to authenticated using (true);
drop policy if exists "rls84 read" on public.petty_cash_requests;
drop policy if exists "read petty cash requests" on public.petty_cash_requests;
create policy "read petty cash requests" on public.petty_cash_requests for select to authenticated using (true);

update storage.buckets set public = true
 where id in ('uploads', 'dispatch-receipts', 'engagement-docs', 'compliance-docs', 'project-docs');
drop policy if exists "dispatch receipts read" on storage.objects;
create policy "dispatch receipts read" on storage.objects for select to public using (bucket_id = 'dispatch-receipts');
drop policy if exists "engagement docs read" on storage.objects;
create policy "engagement docs read" on storage.objects for select to public using (bucket_id = 'engagement-docs');
drop policy if exists "compliance-docs read" on storage.objects;
create policy "compliance-docs read" on storage.objects for select to public using (bucket_id = 'compliance-docs');
drop policy if exists "project-docs read" on storage.objects;
create policy "project-docs read" on storage.objects for select to public using (bucket_id = 'project-docs');
drop policy if exists "uploads read" on storage.objects;
create policy "uploads read" on storage.objects for select using (bucket_id = 'uploads');
-- can_read / my_app_user_id can stay; nothing else depends on them.
```

The signed-URL client keeps working after a rollback, because signing also works on public buckets.
