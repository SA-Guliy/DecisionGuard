-- V1 DONE combined checks (RAW + Step1)
-- psql usage:
-- \set run_id 'v1_run_001'
-- \echo Using run_id = :'run_id'

-- RAW row counts
SELECT 'raw_orders_stream' AS table, COUNT(*) AS rows FROM raw.raw_orders_stream
UNION ALL SELECT 'raw_order_items', COUNT(*) FROM raw.raw_order_items
UNION ALL SELECT 'raw_time_factors', COUNT(*) FROM raw.raw_time_factors
UNION ALL SELECT 'raw_initial_inventory', COUNT(*) FROM raw.raw_initial_inventory;

-- RAW critical null checks (should be 0)
SELECT
  SUM(CASE WHEN order_id IS NULL THEN 1 ELSE 0 END) AS null_order_id,
  SUM(CASE WHEN ts_minute IS NULL THEN 1 ELSE 0 END) AS null_ts_minute,
  SUM(CASE WHEN date IS NULL THEN 1 ELSE 0 END) AS null_date,
  SUM(CASE WHEN store_id IS NULL THEN 1 ELSE 0 END) AS null_store_id
FROM raw.raw_orders_stream;

SELECT
  SUM(CASE WHEN order_id IS NULL THEN 1 ELSE 0 END) AS null_order_id,
  SUM(CASE WHEN product_id IS NULL THEN 1 ELSE 0 END) AS null_product_id,
  SUM(CASE WHEN ts_minute IS NULL THEN 1 ELSE 0 END) AS null_ts_minute,
  SUM(CASE WHEN date IS NULL THEN 1 ELSE 0 END) AS null_date,
  SUM(CASE WHEN unit_price IS NULL THEN 1 ELSE 0 END) AS null_unit_price,
  SUM(CASE WHEN unit_cogs IS NULL THEN 1 ELSE 0 END) AS null_unit_cogs
FROM raw.raw_order_items;

-- RAW join integrity
SELECT COUNT(*) AS orphan_items
FROM raw.raw_order_items oi
LEFT JOIN raw.raw_orders_stream os ON os.order_id = oi.order_id
WHERE os.order_id IS NULL;

-- RAW discount and cogs sanity
SELECT MIN(discount_pct) AS min_discount_pct, MAX(discount_pct) AS max_discount_pct
FROM raw.raw_order_items;

SELECT COUNT(*) AS cogs_ge_price_rows
FROM raw.raw_order_items
WHERE unit_cogs >= list_price;

-- RAW date range quick view
SELECT
  MIN(date) AS min_date,
  MAX(date) AS max_date
FROM raw.raw_orders_stream;

-- Step1 checks (run_id required)
SELECT
  COUNT(*) AS lines,
  SUM(requested_qty) AS req_units,
  SUM(fulfilled_qty) AS ful_units,
  SUM(lost_qty) AS lost_units,
  SUM(fulfilled_qty)::DOUBLE PRECISION / NULLIF(SUM(requested_qty), 0) AS unit_fill_rate
FROM step1.step1_order_items
WHERE run_id = :'run_id';

SELECT
  COUNT(*) AS orders,
  AVG(order_gmv) AS aov_gmv,
  AVG(order_gp) AS aov_gp
FROM step1.step1_orders
WHERE run_id = :'run_id';
