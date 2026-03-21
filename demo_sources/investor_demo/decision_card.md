# One-Page Decision Card (Sprint-2 POC) — mass_test_003_risk_007

- Generated at: `2026-03-10T17:10:21.216328+00:00`
- Hypothesis: `Run flash discounts on high-turnover SKUs to boost conversion this week. Variant 4.`
- Final Decision: `HOLD_NEED_DATA`
- Provisional local fallback: `false`

## Captain Sanity Check
- Sanity status: PASS
- needs_clarification

## Executive Summary
Flash discounts on high-turnover SKUs pose material risks to margin, inventory availability, and fulfillment performance based on historical analogs. Requires validation of guardrail resilience before proceeding.

## Doctor Causal Analysis
- Analysis note: Flash discounts on high-turnover SKUs risk margin erosion and inventory strain, as seen in historical analogs where promotions caused margin dilution or fulfillment bottlenecks.
- Causal story: Discounts may temporarily boost conversion by reducing price sensitivity, but could accelerate margin compression if customers prioritize discounted items over full-price purchases. High turnover SKUs might also face stockout risks if demand spikes exceed inventory buffers.
- Risk signals:
  - Margin dilution from discounted pricing
  - Inventory strain on high-turnover SKUs
  - Potential cannibalization of full-price sales

## Retrieved Historical Evidence
- `exp_hist_001` similarity=`0.2325` primary_metric=`aov` guardrail_breach=`gp_margin`
- `exp_hist_004` similarity=`0.2265` primary_metric=`gmv` guardrail_breach=`fill_rate_units`
- `exp_hist_003` similarity=`0.1231` primary_metric=`delivered_orders_per_day` guardrail_breach=`oos_lost_gmv_rate`

## Commander Rationale
- Historical promotions show margin erosion (e.g., free-shipping threshold test reduced GP margin by 17%)
- High-turnover SKUs in prior tests caused fill-rate degradation (-24% in premium SKU promotion)
- Discounting risks accelerating stockout losses as seen in courier-speed optimization failure
- No evidence provided that inventory buffers can absorb demand spikes from price-sensitive customers

## Next Steps
- Establish real-time margin monitoring dashboard for discounted SKUs
- Validate inventory replenishment lead times against projected velocity increases
- Instrument CLV tracking to detect cannibalization of full-price sales
- Stress-test fulfillment network with 20% demand surge scenarios