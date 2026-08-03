"""harness/report.py: SPEC.md §9.6's report generator -- "the ablation
matrix: leakage rate and false-refusal rate per control vector per model,
with attribution by layer." A CLI tool, matching runner.py's own pattern
(SPEC.md §12's file tree lists report.py alongside runner.py/scoring.py,
both CLI-first), not a new API endpoint.

Leakage rate is computed over *attempted* attack items in a group, not the
full corpus size -- a partial or resumed run (see runner.py's
already_scored()) still reports a correct rate rather than one silently
diluted by items that were never actually run. Same for false-refusal
rate over attempted benign items.
"""
import argparse
import json
from collections import Counter, defaultdict

from runner import db


def fetch_rows(conn, since_run_id=None) -> list:
    query = (
        "SELECT ru.id AS run_id, ru.model, ru.controls_name, c.kind, "
        "       r.leaked, r.refused, r.over_refusal, r.leak_layer "
        "FROM harness.results r "
        "JOIN harness.runs ru ON ru.id = r.run_id "
        "JOIN harness.corpus_items c ON c.id = r.corpus_item_id"
    )
    params = ()
    if since_run_id is not None:
        query += " WHERE ru.id >= %s"
        params = (since_run_id,)
    with conn.cursor() as cur:
        cur.execute(query, params)
        columns = [desc[0] for desc in cur.description]
        return [dict(zip(columns, row)) for row in cur.fetchall()]


def aggregate(rows: list) -> dict:
    groups = defaultdict(lambda: {
        "attack_attempted": 0, "leaked": 0,
        "benign_attempted": 0, "over_refusal": 0,
        "leak_layers": Counter(),
    })
    for row in rows:
        g = groups[(row["model"], row["controls_name"])]
        if row["kind"] == "attack":
            g["attack_attempted"] += 1
            if row["leaked"]:
                g["leaked"] += 1
                if row["leak_layer"]:
                    g["leak_layers"][row["leak_layer"]] += 1
        else:
            g["benign_attempted"] += 1
            if row["over_refusal"]:
                g["over_refusal"] += 1

    matrix = {}
    for (model, controls_name), g in groups.items():
        matrix[(model, controls_name)] = {
            "model": model,
            "controls_name": controls_name,
            "attack_attempted": g["attack_attempted"],
            "leaked": g["leaked"],
            "leakage_rate": (g["leaked"] / g["attack_attempted"]) if g["attack_attempted"] else None,
            "benign_attempted": g["benign_attempted"],
            "over_refusal": g["over_refusal"],
            "false_refusal_rate": (g["over_refusal"] / g["benign_attempted"]) if g["benign_attempted"] else None,
            "leak_layers": dict(g["leak_layers"]),
        }
    return matrix


def _fmt_rate(rate) -> str:
    return f"{rate:.1%}" if rate is not None else "n/a"


def render_markdown(matrix: dict) -> str:
    lines = [
        "# Northwind ablation matrix",
        "",
        "SPEC.md §9.6: leakage rate and false-refusal rate per control vector per model.",
        "",
        "| Model | Controls | Leakage rate | leaked/attempted | False-refusal rate | over-refusals/attempted |",
        "|---|---|---|---|---|---|",
    ]
    for key in sorted(matrix):
        g = matrix[key]
        lines.append(
            f"| {g['model']} | {g['controls_name']} | {_fmt_rate(g['leakage_rate'])} | "
            f"{g['leaked']}/{g['attack_attempted']} | {_fmt_rate(g['false_refusal_rate'])} | "
            f"{g['over_refusal']}/{g['benign_attempted']} |"
        )

    lines += [
        "",
        "## Leak attribution by layer (SPEC.md §9.3)",
        "",
        "Counts among the leaked attempts only -- which layer let the leak through.",
        "",
        "| Model | Controls | retrieval | tool | prompt | rate_limit |",
        "|---|---|---|---|---|---|",
    ]
    for key in sorted(matrix):
        g = matrix[key]
        layers = g["leak_layers"]
        lines.append(
            f"| {g['model']} | {g['controls_name']} | {layers.get('retrieval', 0)} | "
            f"{layers.get('tool', 0)} | {layers.get('prompt', 0)} | {layers.get('rate_limit', 0)} |"
        )
    return "\n".join(lines) + "\n"


def render_json(matrix: dict) -> str:
    return json.dumps([g for _, g in sorted(matrix.items())], indent=2)


def generate(since_run_id: int | None = None, fmt: str = "markdown") -> str:
    conn = db()
    try:
        rows = fetch_rows(conn, since_run_id)
    finally:
        conn.close()
    matrix = aggregate(rows)
    return render_markdown(matrix) if fmt == "markdown" else render_json(matrix)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate the SPEC.md §9.6 ablation matrix report.")
    parser.add_argument("--since", type=int, default=None, help="only include runs with id >= this")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    parser.add_argument("--output", default=None, help="write to this path instead of stdout")
    args = parser.parse_args()

    report = generate(since_run_id=args.since, fmt=args.format)
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"wrote {args.output}")
    else:
        print(report)
