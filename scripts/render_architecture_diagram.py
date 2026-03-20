#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from html import escape
from pathlib import Path


def _dot_source() -> str:
    return r'''
digraph MultiAgentRetail {
  graph [
    rankdir=LR,
    newrank=true,
    splines=spline,
    bgcolor="white",
    pad="0.35",
    nodesep="0.45",
    ranksep="0.75",
    fontname="Helvetica"
  ];

  node [
    shape=box,
    style="rounded,filled",
    fontname="Helvetica",
    fontsize=12,
    color="#243447",
    penwidth=1.4,
    margin="0.16,0.10"
  ];

  edge [
    color="#52606D",
    penwidth=1.6,
    arrowsize=0.7,
    fontname="Helvetica",
    fontsize=10
  ];

  // Main title
  title [shape=plaintext, margin=0, label=<
    <TABLE BORDER="0" CELLBORDER="0" CELLPADDING="2">
      <TR><TD><FONT POINT-SIZE="20"><B>Multi-Agent Retail Decision System</B></FONT></TD></TR>
      <TR><TD><FONT POINT-SIZE="11" COLOR="#52606D">3 agents + AB validity + HITL + production sandbox</FONT></TD></TR>
    </TABLE>
  >];

  // Core flow cluster
  subgraph cluster_core {
    label="Core Decision Flow";
    labelloc=t;
    fontsize=13;
    fontname="Helvetica-Bold";
    color="#D7E3F4";
    style="rounded,filled";
    fillcolor="#F7FAFF";

    data_verifier [label="Agent 1: Captain\n(Data Verifier)", fillcolor="#E8F1FF"];
    experiment_designer [label="Agent 2: Doctor\n(Experiment Designer)", fillcolor="#EAFBF3"];
    decision_gatekeeper [label="Agent 3: Commander\n(Decision Gatekeeper)", fillcolor="#FFF2E8"];
    hitl [label="HITL Approval\n(Human Review Gate)", fillcolor="#FFF7D6", color="#B58900"];
    sandbox [label="Retail Prod Sandbox\n(Protected Execution)", fillcolor="#FFECEC", color="#B03030"];
  }

  // Data + AB path
  subgraph cluster_data {
    label="Data / AB Validity Path";
    labelloc=t;
    fontsize=13;
    fontname="Helvetica-Bold";
    color="#E2E8F0";
    style="rounded,filled";
    fillcolor="#FBFCFE";

    postgres [shape=cylinder, label="Postgres / SQL\n(step1 + AB artifacts)", fillcolor="#EEF2FF", color="#4C51BF"];
    preflight [label="AB Preflight\n(schema • grain • assignment • joins)", fillcolor="#F3F7FF"];
    ab_analysis [label="AB Analysis\n(stats + validity outputs)", fillcolor="#F3F7FF"];
    cohort_pack [label="Cohort Evidence Pack\n(spend/frequency cuts)", fillcolor="#F3F7FF"];
    evidence_pack [label="Evidence Pack\n(aggregated refs)", fillcolor="#F3F7FF"];
  }

  // Transparency + reports
  subgraph cluster_transparency {
    label="Transparency / Diagnostics";
    labelloc=t;
    fontsize=13;
    fontname="Helvetica-Bold";
    color="#E8E0F8";
    style="rounded,filled";
    fillcolor="#FCFAFF";

    reasoning_trace [label="AGENT_REASONING_TRACE\n(per-run reasoning + provenance)", fillcolor="#F4EEFF", color="#6B46C1"];
    friction_report [label="AGENT_INTERACTION_FRICTION_REPORT\n(cross-run frictions / fallbacks)", fillcolor="#F4EEFF", color="#6B46C1"];
    ab_failure_registry [label="AB Failure Registry\n(root-cause counts)", fillcolor="#F4EEFF", color="#6B46C1"];
  }

  // Stack / protocols
  subgraph cluster_stack {
    label="Stack / Runtime";
    labelloc=t;
    fontsize=13;
    fontname="Helvetica-Bold";
    color="#D9EFE1";
    style="rounded,filled";
    fillcolor="#F8FFFB";

    python_orch [label="Python Orchestrator\n(run_all + scripts/*)", fillcolor="#EFFFF6", color="#2F855A"];
    groq_llm [label="LLM (Groq)\nCaptain / Doctor / Commander", fillcolor="#EFFFF6", color="#2F855A"];
    react_proto [label="ReAct + Contracts + Validators\n(JSON schema • safety gates)", fillcolor="#EFFFF6", color="#2F855A"];
  }

  title -> python_orch [style=invis];

  // Main human-facing flow
  data_verifier -> experiment_designer [label="sanity signals"];
  experiment_designer -> decision_gatekeeper [label="hypotheses + methodology + data requests"];
  decision_gatekeeper -> hitl [label="decision proposal\n+ risks + rationale", color="#C05621"];
  hitl -> sandbox [label="approved action", color="#B83280"];

  // Data feeds
  postgres -> preflight [label="run_id / experiment_id"];
  preflight -> ab_analysis [label="PASS only", color="#2F855A"];
  postgres -> cohort_pack [label="customer-grain facts"];
  ab_analysis -> evidence_pack;
  cohort_pack -> evidence_pack;
  evidence_pack -> experiment_designer [label="AB + evidence"];
  evidence_pack -> decision_gatekeeper [label="decision evidence"];
  preflight -> decision_gatekeeper [label="root-cause blockers", color="#C53030"];

  // Captain data hooks
  postgres -> data_verifier [label="DQ / metrics snapshot"];

  // LLM + runtime hooks
  python_orch -> data_verifier [style=dashed, color="#2F855A"];
  python_orch -> experiment_designer [style=dashed, color="#2F855A"];
  python_orch -> decision_gatekeeper [style=dashed, color="#2F855A"];

  groq_llm -> data_verifier [style=dashed, color="#2F855A"];
  groq_llm -> experiment_designer [style=dashed, color="#2F855A"];
  groq_llm -> decision_gatekeeper [style=dashed, color="#2F855A"];

  react_proto -> experiment_designer [style=dashed, color="#2F855A"];
  react_proto -> decision_gatekeeper [style=dashed, color="#2F855A"];

  // Transparency outputs
  data_verifier -> reasoning_trace [style=dotted, label="provenance"];
  experiment_designer -> reasoning_trace [style=dotted, label="method provenance"];
  decision_gatekeeper -> reasoning_trace [style=dotted, label="decision trace"];
  decision_gatekeeper -> friction_report [style=dotted, label="handoff signals"];
  ab_analysis -> ab_failure_registry [style=dotted, label="failure_meta"];
  preflight -> ab_failure_registry [style=dotted, label="preflight error codes"];

}
'''.strip() + "\n"


def _render_with_graphviz(output_stem: Path, fmt: str) -> Path:
    from graphviz import Source  # type: ignore

    src = Source(_dot_source(), filename=str(output_stem), format=fmt)
    rendered = Path(src.render(cleanup=True))
    return rendered


def _native_svg_source() -> str:
    width, height = 1700, 980

    clusters = [
        {"x": 60, "y": 110, "w": 980, "h": 350, "title": "Core Decision Flow", "fill": "#F7FAFF", "stroke": "#D7E3F4"},
        {"x": 60, "y": 485, "w": 980, "h": 410, "title": "Data / AB Validity Path", "fill": "#FBFCFE", "stroke": "#E2E8F0"},
        {"x": 1080, "y": 110, "w": 560, "h": 310, "title": "Stack / Runtime", "fill": "#F8FFFB", "stroke": "#D9EFE1"},
        {"x": 1080, "y": 445, "w": 560, "h": 450, "title": "Transparency / Diagnostics", "fill": "#FCFAFF", "stroke": "#E8E0F8"},
    ]

    blocks = [
        {"id": "captain", "x": 100, "y": 180, "w": 230, "h": 78, "title": "Agent 1: Captain", "subtitle": "Data Verifier", "fill": "#E8F1FF", "stroke": "#3B82F6"},
        {"id": "doctor", "x": 385, "y": 180, "w": 250, "h": 78, "title": "Agent 2: Doctor", "subtitle": "Experiment Designer", "fill": "#EAFBF3", "stroke": "#22A06B"},
        {"id": "commander", "x": 690, "y": 180, "w": 280, "h": 78, "title": "Agent 3: Commander", "subtitle": "Decision Gatekeeper", "fill": "#FFF2E8", "stroke": "#DD6B20"},
        {"id": "hitl", "x": 420, "y": 320, "w": 230, "h": 72, "title": "HITL Approval", "subtitle": "Human Review Gate", "fill": "#FFF7D6", "stroke": "#B58900"},
        {"id": "sandbox", "x": 700, "y": 320, "w": 250, "h": 72, "title": "Retail Prod Sandbox", "subtitle": "Protected Execution", "fill": "#FFECEC", "stroke": "#C53030"},

        {"id": "postgres", "x": 110, "y": 560, "w": 240, "h": 82, "title": "Postgres / SQL", "subtitle": "step1 + AB artifacts", "fill": "#EEF2FF", "stroke": "#4C51BF"},
        {"id": "preflight", "x": 405, "y": 540, "w": 250, "h": 92, "title": "AB Preflight", "subtitle": "schema • grain • assignment • joins", "fill": "#F3F7FF", "stroke": "#4A5568"},
        {"id": "ab", "x": 700, "y": 540, "w": 250, "h": 92, "title": "AB Analysis", "subtitle": "stats + validity outputs", "fill": "#F3F7FF", "stroke": "#4A5568"},
        {"id": "cohort", "x": 405, "y": 675, "w": 250, "h": 92, "title": "Cohort Evidence Pack", "subtitle": "spend / frequency cuts", "fill": "#F3F7FF", "stroke": "#4A5568"},
        {"id": "evidence", "x": 700, "y": 675, "w": 250, "h": 92, "title": "Evidence Pack", "subtitle": "aggregated refs", "fill": "#F3F7FF", "stroke": "#4A5568"},

        {"id": "python", "x": 1120, "y": 175, "w": 220, "h": 80, "title": "Python", "subtitle": "run_all + scripts/*", "fill": "#EFFFF6", "stroke": "#2F855A"},
        {"id": "groq", "x": 1375, "y": 175, "w": 220, "h": 80, "title": "LLM (Groq)", "subtitle": "Captain / Doctor / Commander", "fill": "#EFFFF6", "stroke": "#2F855A"},
        {"id": "react", "x": 1248, "y": 285, "w": 220, "h": 90, "title": "ReAct + Validators", "subtitle": "JSON schema • safety gates", "fill": "#EFFFF6", "stroke": "#2F855A"},

        {"id": "trace", "x": 1120, "y": 520, "w": 475, "h": 84, "title": "AGENT_REASONING_TRACE", "subtitle": "per-run reasoning + provenance", "fill": "#F4EEFF", "stroke": "#6B46C1"},
        {"id": "friction", "x": 1120, "y": 635, "w": 475, "h": 84, "title": "AGENT_INTERACTION_FRICTION_REPORT", "subtitle": "cross-run frictions / fallbacks", "fill": "#F4EEFF", "stroke": "#6B46C1"},
        {"id": "abfail", "x": 1120, "y": 750, "w": 475, "h": 84, "title": "AB Failure Registry", "subtitle": "root-cause counts", "fill": "#F4EEFF", "stroke": "#6B46C1"},
    ]

    by_id = {b["id"]: b for b in blocks}

    def anchor(block_id: str, side: str) -> tuple[float, float]:
        b = by_id[block_id]
        x, y, w, h = b["x"], b["y"], b["w"], b["h"]
        return {
            "left": (x, y + h / 2),
            "right": (x + w, y + h / 2),
            "top": (x + w / 2, y),
            "bottom": (x + w / 2, y + h),
            "center": (x + w / 2, y + h / 2),
        }[side]

    edges = [
        ("captain", "right", "doctor", "left", "#52606D", "sanity signals"),
        ("doctor", "right", "commander", "left", "#52606D", "hypotheses + methodology"),
        ("commander", "bottom", "hitl", "top", "#C05621", "decision + risks"),
        ("hitl", "right", "sandbox", "left", "#B83280", "approved action"),

        ("postgres", "top", "captain", "bottom", "#52606D", "DQ / metrics"),
        ("postgres", "right", "preflight", "left", "#52606D", "run / exp"),
        ("preflight", "right", "ab", "left", "#2F855A", "PASS"),
        ("postgres", "right", "cohort", "left", "#52606D", "customer grain"),
        ("ab", "bottom", "evidence", "top", "#52606D", ""),
        ("cohort", "right", "evidence", "left", "#52606D", ""),
        ("evidence", "top", "doctor", "bottom", "#52606D", "AB + evidence"),
        ("evidence", "right", "commander", "bottom", "#52606D", "decision evidence"),
        ("preflight", "top", "commander", "bottom", "#C53030", "blockers"),

        ("python", "left", "captain", "right", "#2F855A", ""),
        ("python", "left", "doctor", "right", "#2F855A", ""),
        ("python", "left", "commander", "right", "#2F855A", ""),
        ("groq", "left", "captain", "right", "#2F855A", ""),
        ("groq", "left", "doctor", "right", "#2F855A", ""),
        ("groq", "left", "commander", "right", "#2F855A", ""),
        ("react", "left", "doctor", "right", "#2F855A", ""),
        ("react", "left", "commander", "right", "#2F855A", ""),

        ("captain", "right", "trace", "left", "#6B46C1", ""),
        ("doctor", "right", "trace", "left", "#6B46C1", ""),
        ("commander", "right", "trace", "left", "#6B46C1", ""),
        ("commander", "right", "friction", "left", "#6B46C1", ""),
        ("preflight", "right", "abfail", "left", "#6B46C1", ""),
        ("ab", "right", "abfail", "left", "#6B46C1", ""),
    ]

    def line(x1: float, y1: float, x2: float, y2: float, color: str, dashed: bool = False) -> str:
        dash = ' stroke-dasharray="6 5"' if dashed else ""
        return f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" stroke-width="2"{dash} marker-end="url(#arrow)"/>'

    def label(x: float, y: float, text: str, color: str = "#52606D", size: int = 11) -> str:
        if not text:
            return ""
        return f'<text x="{x:.1f}" y="{y:.1f}" text-anchor="middle" font-family="Helvetica" font-size="{size}" fill="{color}">{escape(text)}</text>'

    def rect_block(b: dict) -> str:
        x, y, w, h = b["x"], b["y"], b["w"], b["h"]
        title = escape(b["title"])
        subtitle = escape(b["subtitle"])
        return f'''
<g>
  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" ry="14" fill="{b["fill"]}" stroke="{b["stroke"]}" stroke-width="1.8"/>
  <text x="{x + w/2:.1f}" y="{y + h/2 - 6:.1f}" text-anchor="middle" font-family="Helvetica" font-size="14" font-weight="700" fill="#1F2937">{title}</text>
  <text x="{x + w/2:.1f}" y="{y + h/2 + 16:.1f}" text-anchor="middle" font-family="Helvetica" font-size="11" fill="#52606D">{subtitle}</text>
</g>'''.strip()

    def cluster_box(c: dict) -> str:
        x, y, w, h = c["x"], c["y"], c["w"], c["h"]
        return f'''
<g>
  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="18" ry="18" fill="{c["fill"]}" stroke="{c["stroke"]}" stroke-width="2"/>
  <text x="{x + 18}" y="{y + 26}" font-family="Helvetica" font-size="14" font-weight="700" fill="#243447">{escape(c["title"])}</text>
</g>'''.strip()

    parts: list[str] = []
    parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">')
    parts.append("""
  <defs>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="2" stdDeviation="2" flood-color="#CBD5E0" flood-opacity="0.65"/>
    </filter>
    <marker id="arrow" markerWidth="10" markerHeight="8" refX="8" refY="4" orient="auto">
      <path d="M0,0 L10,4 L0,8 z" fill="#52606D" />
    </marker>
  </defs>
""")
    parts.append(f'<rect x="0" y="0" width="{width}" height="{height}" fill="#FFFFFF"/>')
    parts.append('<text x="60" y="52" font-family="Helvetica" font-size="28" font-weight="700" fill="#1F2937">Multi-Agent Retail Decision System</text>')
    parts.append('<text x="60" y="78" font-family="Helvetica" font-size="13" fill="#52606D">3 agents + AB validity + HITL + protected sandbox execution</text>')

    for c in clusters:
        parts.append(cluster_box(c))

    # decorative background links
    for src, s_side, dst, d_side, color, text_val in edges:
        x1, y1 = anchor(src, s_side)
        x2, y2 = anchor(dst, d_side)
        dashed = src in {"python", "groq", "react"} or dst in {"trace", "friction", "abfail"}
        parts.append(line(x1, y1, x2, y2, color, dashed=dashed))
        if text_val:
            parts.append(label((x1 + x2) / 2, (y1 + y2) / 2 - 6, text_val, color=color if color != "#52606D" else "#52606D"))

    for b in blocks:
        parts.append(f'<g filter="url(#shadow)">{rect_block(b)}</g>')

    parts.append("</svg>")
    return "\n".join(parts)


def _render_native_svg(output_stem: Path) -> Path:
    out = output_stem.with_suffix(".svg")
    out.write_text(_native_svg_source(), encoding="utf-8")
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Render project architecture diagram (Graphviz)")
    parser.add_argument("--out", default="architecture", help="Output file stem (default: architecture)")
    parser.add_argument("--format", default="png", choices=["png", "svg", "pdf"], help="Render format")
    parser.add_argument("--dot-only", action="store_true", help="Only write DOT source, do not render")
    parser.add_argument(
        "--engine",
        default="auto",
        choices=["auto", "graphviz", "native-svg"],
        help="Render engine: graphviz (best routing), native-svg (no external deps), auto",
    )
    args = parser.parse_args()

    out_stem = Path(args.out)
    dot_path = out_stem.with_suffix(".dot")
    dot_path.write_text(_dot_source(), encoding="utf-8")
    print(f"ok: dot written -> {dot_path}")

    if args.dot_only:
        return

    if args.engine == "native-svg":
        rendered = _render_native_svg(out_stem)
        print(f"ok: diagram rendered (native-svg) -> {rendered}")
        return

    try:
        rendered = _render_with_graphviz(out_stem, args.format)
        print(f"ok: diagram rendered -> {rendered}")
    except ModuleNotFoundError:
        if args.engine == "auto":
            rendered = _render_native_svg(out_stem)
            print(f"WARN: graphviz Python package not installed. Fallback -> native-svg: {rendered}", file=sys.stderr)
            return
        print("WARN: Python package 'graphviz' is not installed in this environment.", file=sys.stderr)
        print("Install and rerun:", file=sys.stderr)
        print("  pip install graphviz", file=sys.stderr)
        print("  brew install graphviz   # macOS (provides 'dot')", file=sys.stderr)
        print(f"Then run: python3 {Path(__file__).name} --out {out_stem} --format {args.format}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as e:
        if args.engine == "auto":
            rendered = _render_native_svg(out_stem)
            print(f"WARN: graphviz render failed ({type(e).__name__}). Fallback -> native-svg: {rendered}", file=sys.stderr)
            return
        print(f"WARN: render failed: {type(e).__name__}: {e}", file=sys.stderr)
        print("Make sure Graphviz CLI ('dot') is installed and available in PATH.", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
