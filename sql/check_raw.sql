-- Row counts
SELECT 'raw_orders_stream' AS table_name, COUNT(*) AS rows FROM raw.raw_orders_stream
UNION ALL SELECT 'raw_order_items', COUNT(*) FROM raw.raw_order_items
UNION ALL SELECT 'raw_time_factors', COUNT(*) FROM raw.raw_time_factors
UNION ALL SELECT 'raw_initial_inventory', COUNT(*) FROM raw.raw_initial_inventory;

-- Uniqueness
SELECT COUNT(*) AS duplicate_order_id
FROM (
  SELECT order_id, COUNT(*) c
  FROM raw.raw_orders_stream
  GROUP BY order_id
  HAVING COUNT(*) > 1
) t;

-- Discount pct must be 0.0 in Step 0
SELECT COUNT(*) AS discount_not_zero
FROM raw.raw_order_items
WHERE discount_pct <> 0.0;

-- COGS < list_price
SELECT COUNT(*) AS cogs_ge_price
FROM raw.raw_products
WHERE unit_cogs >= list_price;

-- Perishable must have expiry_days
SELECT COUNT(*) AS perish_missing_expiry
FROM raw.raw_products
WHERE is_perishable = 1 AND expiry_days IS NULL;

-- Critical null checks (should be 0)
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

-- Join integrity: every item has a matching order
SELECT COUNT(*) AS orphan_items
FROM raw.raw_order_items oi
LEFT JOIN raw.raw_orders_stream os ON os.order_id = oi.order_id
WHERE os.order_id IS NULL;

-- discount_pct must be 0 in Step 0
SELECT MIN(discount_pct) AS min_discount_pct, MAX(discount_pct) AS max_discount_pct
FROM raw.raw_order_items;

-- unit_cogs < list_price (violations should be 0)
SELECT COUNT(*) AS cogs_ge_price_rows
FROM raw.raw_order_items
WHERE unit_cogs >= list_price;

-- Date range quick view (sanity)
SELECT
  MIN(date) AS min_date,
  MAX(date) AS max_date
FROM raw.raw_orders_stream;

-- raw_customers: initial_status/home_store_id not null and valid values
SELECT
  SUM(CASE WHEN initial_status IS NULL THEN 1 ELSE 0 END) AS null_initial_status,
  SUM(CASE WHEN home_store_id IS NULL THEN 1 ELSE 0 END) AS null_home_store_id
FROM raw.raw_customers;

SELECT
  COUNT(*) AS invalid_initial_status
FROM raw.raw_customers
WHERE initial_status NOT IN ('active', 'reserve');

SELECT
  COUNT(*) AS invalid_home_store_id
FROM raw.raw_customers
WHERE home_store_id NOT IN ('A', 'B');

-- Time range sanity (orders)
SELECT MIN(ts_minute) AS min_ts, MAX(ts_minute) AS max_ts
FROM raw.raw_orders_stream;

-- Time range sanity (time_factors)
SELECT MIN(ts) AS min_ts, MAX(ts) AS max_ts
FROM raw.raw_time_factors;
