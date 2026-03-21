# Metrics Contract v1

Scope: Step1 approved runs (`qa_status IN ('PASS','WARN')`) using `step1.vw_valid_*` when available.

## READY_NOW

### orders_cnt
- Definition: number of orders in run.
- Grain: run_id
- SQL:
```sql
SELECT COUNT(*) AS orders_cnt
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### gmv
- Definition: sum of `order_gmv`.
- Grain: run_id
- SQL:
```sql
SELECT COALESCE(SUM(order_gmv),0) AS gmv
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### gp
- Definition: sum of `order_gp`.
- Grain: run_id
- SQL:
```sql
SELECT COALESCE(SUM(order_gp),0) AS gp
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### gp_margin
- Definition: `gp / gmv`.
- Grain: run_id
- SQL:
```sql
SELECT CASE WHEN SUM(order_gmv) > 0 THEN SUM(order_gp) / SUM(order_gmv) ELSE NULL END AS gp_margin
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### aov
- Definition: `gmv / orders_cnt`.
- Grain: run_id
- SQL:
```sql
SELECT CASE WHEN COUNT(*) > 0 THEN SUM(order_gmv) / COUNT(*) ELSE NULL END AS aov
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### gp_per_order
- Definition: `gp / orders_cnt`.
- Grain: run_id
- SQL:
```sql
SELECT CASE WHEN COUNT(*) > 0 THEN SUM(order_gp) / COUNT(*) ELSE NULL END AS gp_per_order
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### requested_units
- Definition: sum of requested units.
- Grain: run_id
- SQL:
```sql
SELECT COALESCE(SUM(requested_units),0) AS requested_units
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### fulfilled_units
- Definition: sum of fulfilled units.
- Grain: run_id
- SQL:
```sql
SELECT COALESCE(SUM(fulfilled_units),0) AS fulfilled_units
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### fill_rate_units
- Definition: `fulfilled_units / requested_units`.
- Grain: run_id
- SQL:
```sql
SELECT CASE WHEN SUM(requested_units) > 0 THEN SUM(fulfilled_units)::double precision / SUM(requested_units) ELSE NULL END AS fill_rate_units
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### fill_rate_mean / fill_rate_p50 / fill_rate_p95 (optional diagnostics)
- Definition: distribution statistics over `order_fill_rate_units`.
- Grain: run_id
- SQL:
```sql
SELECT
  AVG(order_fill_rate_units) AS fill_rate_mean,
  PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY order_fill_rate_units) AS fill_rate_p50,
  PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY order_fill_rate_units) AS fill_rate_p95
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### lost_gmv_oos
- Definition: sum of OOS lost GMV.
- Grain: run_id
- SQL:
```sql
SELECT COALESCE(SUM(order_lost_gmv_oos),0) AS lost_gmv_oos
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### oos_lost_gmv_rate
- Definition: `lost_gmv_oos / gmv`.
- Grain: run_id
- SQL:
```sql
SELECT CASE WHEN SUM(order_gmv) > 0 THEN SUM(order_lost_gmv_oos) / SUM(order_gmv) ELSE NULL END AS oos_lost_gmv_rate
FROM step1.vw_valid_orders
WHERE run_id = :run_id;
```

### new_buyers_7d
- Definition: distinct buyers whose first order date in this run falls within first 7 days of run horizon.
- Grain: run_id
- SQL:
```sql
WITH ordered AS (
  SELECT o.run_id, o.order_id, o.date, os.customer_id
  FROM step1.vw_valid_orders o
  JOIN raw.raw_orders_stream os ON os.order_id = o.order_id
  WHERE o.run_id = :run_id
), bounds AS (
  SELECT MIN(date) AS start_date FROM ordered
), first_buy AS (
  SELECT customer_id, MIN(date) AS first_date FROM ordered GROUP BY customer_id
)
SELECT COUNT(*) AS new_buyers_7d
FROM first_buy, bounds
WHERE first_date BETWEEN bounds.start_date AND (bounds.start_date + INTERVAL '6 day');
```

### active_buyers_avg
- Definition: average `active_cnt` across store-days.
- Grain: run_id
- SQL:
```sql
SELECT AVG(active_cnt) AS active_buyers_avg
FROM step1.vw_valid_customer_daily
WHERE run_id = :run_id;
```

### churn_rate
- Definition: aggregate churn rate `SUM(churned_today) / SUM(active_cnt)`.
- Grain: run_id
- SQL:
```sql
SELECT
  CASE WHEN SUM(active_cnt) > 0
       THEN SUM(churned_today)::double precision / SUM(active_cnt)
       ELSE NULL END AS churn_rate
FROM step1.vw_valid_customer_daily
WHERE run_id = :run_id;
```

### rep_mean
- Definition: average reputation.
- Grain: run_id
- SQL:
```sql
SELECT AVG(rep) AS rep_mean
FROM step1.vw_valid_customer_daily
WHERE run_id = :run_id;
```

### churn_prob_mean (optional diagnostic)
- Definition: average churn probability signal.
- Grain: run_id
- SQL:
```sql
SELECT AVG(churn_prob) AS churn_prob_mean
FROM step1.vw_valid_customer_daily
WHERE run_id = :run_id;
```

### perishable_gmv_share
- Definition: fulfilled GMV share of perishable SKU.
- Grain: run_id
- SQL:
```sql
SELECT
  CASE WHEN SUM(i.calc_line_gmv_fulfilled) > 0
       THEN SUM(CASE WHEN p.is_perishable = 1 THEN i.calc_line_gmv_fulfilled ELSE 0 END) / SUM(i.calc_line_gmv_fulfilled)
       ELSE NULL END AS perishable_gmv_share
FROM step1.vw_valid_order_items i
JOIN raw.raw_products p ON p.product_id = i.product_id
WHERE i.run_id = :run_id;
```

### writeoff_units
- Definition: total pulled/writeoff units from `step1.step1_writeoff_log`.
- Grain: run_id
- SQL:
```sql
SELECT COALESCE(SUM(qty_writeoff),0) AS writeoff_units
FROM step1.step1_writeoff_log
WHERE run_id = :run_id;
```

### writeoff_cogs
- Definition: total writeoff COGS from `step1.step1_writeoff_log`.
- Grain: run_id
- SQL:
```sql
SELECT COALESCE(SUM(writeoff_cogs),0) AS writeoff_cogs
FROM step1.step1_writeoff_log
WHERE run_id = :run_id;
```

### received_cogs
- Definition: total received inventory cost in test window (`SUM(qty_added * unit_cogs)`).
- Grain: run_id
- SQL:
```sql
SELECT COALESCE(SUM(r.qty_added * p.unit_cogs),0) AS received_cogs
FROM step1.step1_replenishment_log r
JOIN raw.raw_products p ON p.product_id = r.product_id
WHERE r.run_id = :run_id;
```

### sold_cogs
- Definition: total sold COGS in test window (`SUM(fulfilled_qty * unit_cogs)`).
- Grain: run_id
- SQL:
```sql
SELECT COALESCE(SUM(fulfilled_qty * unit_cogs),0) AS sold_cogs
FROM step1.step1_order_items
WHERE run_id = :run_id;
```

### expiry_writeoff_cogs
- Definition: writeoff COGS only for expiry-related reasons (`expiry`, `pull_before_expiry`, `expired`).
- Grain: run_id
- SQL:
```sql
SELECT COALESCE(SUM(writeoff_cogs),0) AS expiry_writeoff_cogs
FROM step1.step1_writeoff_log
WHERE run_id = :run_id
  AND LOWER(COALESCE(writeoff_reason_norm, reason)) IN ('expiry','pull_before_expiry','expired');
```

### expiry_waste_rate_cogs
- Definition: `expiry_writeoff_cogs / received_cogs`.
- Grain: run_id
- SQL:
```sql
WITH e AS (
  SELECT COALESCE(SUM(writeoff_cogs),0)::double precision AS expiry_writeoff_cogs
  FROM step1.step1_writeoff_log
  WHERE run_id = :run_id
    AND LOWER(COALESCE(writeoff_reason_norm, reason)) IN ('expiry','pull_before_expiry','expired')
),
r AS (
  SELECT COALESCE(SUM(x.qty_added * p.unit_cogs),0)::double precision AS received_cogs
  FROM step1.step1_replenishment_log x
  JOIN raw.raw_products p ON p.product_id = x.product_id
  WHERE x.run_id = :run_id
)
SELECT CASE WHEN r.received_cogs > 0 THEN e.expiry_writeoff_cogs / r.received_cogs ELSE NULL END AS expiry_waste_rate_cogs
FROM e, r;
```

### writeoff_rate_vs_requested_units
- Definition: `writeoff_units / requested_units` (phase-1 proxy until receipts ledger is added).
- Grain: run_id
- SQL:
```sql
WITH w AS (
  SELECT COALESCE(SUM(qty_writeoff),0)::double precision AS writeoff_units
  FROM step1.step1_writeoff_log
  WHERE run_id = :run_id
),
o AS (
  SELECT COALESCE(SUM(requested_units),0)::double precision AS requested_units
  FROM step1.vw_valid_orders
  WHERE run_id = :run_id
)
SELECT CASE WHEN o.requested_units > 0 THEN w.writeoff_units / o.requested_units ELSE NULL END AS writeoff_rate_vs_requested_units
FROM w, o;
```

### supply/ops/shock realism diagnostics (optional)
- `supplier_fill_rate_mean`, `replen_capacity_mult_mean`, `leadtime_days_mean` from `step1.step1_supply_daily`.
- `shrink_units_rate` = `SUM(shrink_units) / requested_units` from `step1.step1_ops_daily`.
- `shock_days_share` = `AVG(is_shock)` from `step1.step1_demand_shocks_daily`.

## BLOCKED_BY_DATA

The following metrics are intentionally blocked until inventory aging/writeoff model is added:
- DOI (days of inventory)
- inventory turnover
- days_to_expiry distribution
- aged_inventory_share

Reason: full inventory-age timeline is still not persisted as a dedicated fact table.

---

## v1.1 Delta (Machine-readable semantics for Event Bus)

This section introduces a machine-readable semantics layer that complements the metric
definitions above.

### Required identifiers

Each metric used in AB inference must have:

- `metric_id`
- `metric_semantics_id`
- `direction` (`up` | `down`)
- `grain`
- `window`
- `numerator` (or formula atom)
- `denominator` (or `null` for non-ratio)

### Registry contract

Semantics are published via:

- topic: `metrics.semantics.published.v1`
- schema: `metric_semantics_registry.v1`
- schema file: `configs/contracts/event_bus/metric_semantics_registry_v1.json`

### Binding rules (blocking)

1. Any `primary_metric_id` in AB inference must resolve to one `metric_semantics_id` in registry.
2. Any guardrail metric used in decisioning must also resolve in registry.
3. If metric semantics binding fails, preflight must return `FAIL` with explicit contract error code.
4. Inference without registry binding is invalid and must not produce rollout-eligible decision.

### Recommended canonical IDs for current metrics

These IDs standardize machine references while preserving current human names.

| metric_id | metric_semantics_id | direction | grain | window |
|---|---|---|---|---|
| `aov` | `sem.aov.order_value.v1` | `up` | `run` or analysis unit | test window |
| `gp_margin` | `sem.gp.margin.v1` | `up` | `run` or analysis unit | test window |
| `fill_rate_units` | `sem.fill_rate.units.v1` | `up` | `run` or analysis unit | test window |
| `oos_lost_gmv_rate` | `sem.oos_lost_gmv_rate.v1` | `down` | `run` or analysis unit | test window |
| `writeoff_rate_vs_requested_units` | `sem.writeoff.proxy_rate.v1` | `down` | `run` or analysis unit | test window |
| `writeoff_units` | `sem.writeoff.units.v1` | `down` | `run` or analysis unit | test window |
| `perishable_gmv_share` | `sem.perishable_gmv_share.v1` | `depends` | `run` or analysis unit | test window |
| `active_buyers_avg` | `sem.active_buyers.avg.v1` | `up` | `run` or analysis unit | test window |
| `rep_mean` | `sem.reputation.mean.v1` | `up` | `run` or analysis unit | test window |

Notes:

- `writeoff_rate_vs_requested_units` remains a proxy semantic and must be explicitly labeled as proxy in reports.
- If `direction = depends`, experiment contract must specify expected sign for this run.
