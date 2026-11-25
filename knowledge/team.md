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
