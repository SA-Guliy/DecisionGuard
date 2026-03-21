# DecisionGuard: 40-Second Elevator Pitch (Storyboard)

This document outlines the frame-by-frame script for the DecisionGuard animated GIF used in the main `README.md`.

## Frame 1: The Trap (0–5 sec)
**Visual:** Clean DecisionGuard UI. Empty agent slots.
**Hypothesis Input:** "Flash discounts on high-margin SKUs to boost conversion +15%"
**Goal:** `unit_economics_guard`

![Frame 1](assets/pitch/frame_1.png)

---

## Frame 2: Captain's Cynicism (5–7 sec)
**Visual:** Character Cut-scene. Captain (Onion with green sprout, pilot hat). No eyes, dark-grey thin plasticine lips forming an asymmetrical, cynical smirk. 
**Action:** Stamping "✓ PASS" with a skeptical vibe.

![Frame 2](assets/pitch/frame_2.png)

---

## Frame 3: Captain Status (7–15 sec)
**Visual:** UI Flow. 
**Action:** The `CAPTAIN (Validation)` card populates with a green `✓ PASS` stamp and a short JSON validation snippet. Arrow points to the next agent.

![Frame 3](assets/pitch/frame_3.png)

---

## Frame 4: Doctor's Diagnosis (15–17 sec)
**Visual:** Character Cut-scene. Doctor (Pea pod in a white lab coat with a stethoscope). No eyes, dark-grey thin plasticine lips forming a deep frown.
**Action:** Pointing a pea-finger at the `Similarity: 0.91` data point.

![Frame 4](assets/pitch/frame_4.png)

---

## Frame 5: Doctor Status (17–25 sec)
**Visual:** UI Flow.
**Action:** The `DOCTOR (Historical Risk)` card populates with amber status `⚠ WEAK`. 
**Alert text:** "Historical match found (Similarity: 0.91). Goodhart's Law violation risk detected in historical precedent."

![Frame 5](assets/pitch/frame_5.png)

---

## Frame 6: Commander's Veto (25–27 sec)
**Visual:** Character Cut-scene. Commander (Tomato with black Salvador Dali mustaches). No eyes, dark-grey thin plasticine lips set in a firm, resolute line.
**Action:** Decisively planting a red `✗ HOLD` flag. Pointing to the `RISK: GP_MARGIN` policy.

![Frame 6](assets/pitch/frame_6.png)

---

## Frame 7: Final Verdict (27–35 sec)
**Visual:** UI Flow.
**Action:** The `COMMANDER (Final Verdict)` card populates with red status `✗ HOLD`.
**Rationale text:** `HOLD_NEED_DATA due to high risk of margin erosion and fill-rate stress... Requesting inventory and LTV analysis before re-submission.`

![Frame 7](assets/pitch/frame_7.png)

---

## Frame 8: The Business Value (35–40 sec)
**Visual:** UI Overlay over the completed dashboard.
**Action:** Pop-up metric cards appear.
* `Decision cost: ~$0.002`
* `Estimated P&L protected: $50,000+`
**Ending:** DecisionGuard logo fades in.

![Frame 8](assets/pitch/frame_8.png)