-- ADMIN ONLY: schema/migration step. Do NOT run as part of daily pipeline.
DROP SCHEMA IF EXISTS raw CASCADE;
CREATE SCHEMA raw;

CREATE TABLE raw.raw_categories (
  category_id TEXT PRIMARY KEY,
  category_name TEXT,
  storage_type TEXT,
  perishable_policy TEXT
);

CREATE TABLE raw.raw_products (
  product_id TEXT PRIMARY KEY,
  product_name TEXT,
  category_id TEXT,
  category_name TEXT,
  storage_type TEXT,
  unit TEXT,
  substitute_group_id TEXT,
  is_perishable INT,
  expiry_days INT,
  list_price NUMERIC(12,4),
  unit_cogs NUMERIC(12,4),
  max_discount_pct DOUBLE PRECISION,
  weight_kg DOUBLE PRECISION,
  popularity_weight DOUBLE PRECISION
);

CREATE TABLE raw.raw_customers (
  customer_id TEXT PRIMARY KEY,
  customer_segment TEXT,
  activity_weight DOUBLE PRECISION,
  initial_status TEXT,
  home_store_id TEXT
);

CREATE TABLE raw.raw_day_scenarios (
  date DATE,
  season TEXT,
  is_weekend INT,
  is_holiday INT,
  is_preholiday INT,
  weather_bad INT,
  local_event INT,
  scenario_type TEXT,
  intensity DOUBLE PRECISION,
  affected_store TEXT
);

CREATE TABLE raw.raw_intraday_shocks (
  date DATE,
  store_id TEXT,
  shock_start_ts TIMESTAMP,
  shock_end_ts TIMESTAMP,
  shock_intensity DOUBLE PRECISION,
  shock_class TEXT,
  shock_type TEXT
);

CREATE TABLE raw.raw_time_factors (
  ts TIMESTAMP,
  date DATE,
  store_id TEXT,
  hour INT,
  season TEXT,
  is_weekend INT,
  is_holiday INT,
  is_preholiday INT,
  weather_bad INT,
  local_event INT,
  hourly_multiplier DOUBLE PRECISION,
  day_multiplier DOUBLE PRECISION,
  shock_multiplier DOUBLE PRECISION,
  demand_multiplier DOUBLE PRECISION
);

CREATE TABLE raw.raw_orders_stream (
  ts_minute TIMESTAMP,
  date DATE,
  store_id TEXT,
  order_id TEXT PRIMARY KEY,
  customer_id TEXT,
  customer_segment TEXT,
  base_intent_value DOUBLE PRECISION,
  budget_signal DOUBLE PRECISION,
  is_floor_fill INT,
  basket_size INT,
  units_total INT
);

CREATE TABLE raw.raw_order_items (
  order_id TEXT,
  product_id TEXT,
  requested_qty INT,
  is_perishable INT,
  category_id TEXT,
  store_id TEXT,
  ts_minute TIMESTAMP,
  date DATE,
  list_price NUMERIC(12,4),
  unit_cogs NUMERIC(12,4),
  discount_pct DOUBLE PRECISION,
  unit_price NUMERIC(12,4),
  line_gmv_requested NUMERIC(12,4),
  line_gp_requested NUMERIC(12,4)
);

CREATE TABLE raw.raw_initial_inventory (
  as_of_date DATE,
  store_id TEXT,
  product_id TEXT,
  initial_qty INT
);

CREATE INDEX idx_orders_store_ts ON raw.raw_orders_stream (store_id, ts_minute);
CREATE INDEX idx_orders_date_store ON raw.raw_orders_stream (date, store_id);

CREATE INDEX idx_items_order ON raw.raw_order_items (order_id);
CREATE INDEX idx_items_store_ts ON raw.raw_order_items (store_id, ts_minute);
CREATE INDEX idx_items_product ON raw.raw_order_items (product_id);

CREATE INDEX idx_inventory_store_product ON raw.raw_initial_inventory (store_id, product_id);

CREATE INDEX idx_products_category ON raw.raw_products (category_id);
