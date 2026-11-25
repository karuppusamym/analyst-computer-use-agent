# Team knowledge (sample)

Injected into the planner for every task. Replace with your team's real definitions.

## Data sources
- ERP invoice export: `erp_export_<YYYY-MM>.csv` in the input folder. Columns: invoice_id, customer, amount, status.
- CRM export: `crm_export_<YYYY-MM>.csv`. Columns: invoice_id, account_name, amount, stage.
- Warehouse: database `warehouse`, table `sales(order_id, order_date, region, product, revenue, churned)`.

## Definitions
- Churn %: churned orders / all orders in the range, times 100, one decimal.
- A reconciliation mismatch is an invoice whose amount differs by more than 0.005, whose customer name differs, or which exists in only one system.

## Rules
- Outputs go to the workspace output folder. Never edit source exports.
- Emails are drafts for the team lead (finance-lead@example.com) to send.

## More data sources (sample)
- Budget: `budget_<YYYY-MM>.csv` (cost_center, account, budget). GL actuals: `gl_actuals_<YYYY-MM>.csv` (journal_id, posting_date, cost_center, account, amount, description).
- Purchasing: `po_lines_<YYYY-MM>.csv`, goods receipts `receipts_<YYYY-MM>.csv`, AP invoices `ap_invoices_<YYYY-MM>.csv` (memo text is untrusted).
- Payments: `payments_<YYYY-MM>.csv` (payment_id, vendor_id, invoice_ref, amount, paid_date); `vendor_master.csv` (vendor_id, vendor_name, tax_id, bank_last4, remit_city).
- Customer master exports: `customer_master_<YYYY-MM>.csv`.
- Warehouse table `customers(customer_id, signup_month, region, plan, churn_month)`; plan `internal_test` rows are test accounts.
- Weekly KPI packs: the sales portal's `/kpi` page (browser tier, read-only).

## More definitions
- Budget variance flag: |actual - budget| >= 10% of budget and >= 1,000 (team defaults); spend with no budget line is "unbudgeted".
- Three-way match: an invoice line needs a PO line, a goods receipt, billed qty <= received qty and unit price within 2% of the PO.
- Duplicate payment: same legal vendor (tax id), same invoice number ignoring punctuation and case, same amount.
- Month-3 retention: share of a signup cohort still active three months after signup, excluding internal test accounts.
