"""Command line.

    gauntlet run --defense none              # attack-success-rate for one target
    gauntlet run --defense shield
    gauntlet compare --a none --b shield     # does the defense actually help?

`compare` is the point: it shows the attack-success-rate drop when you add a
defense AND what it costs in over-refusal on benign traffic — the security
tradeoff, quantified. Needs ANTHROPIC_API_KEY (it calls the target model).
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from assay import report
from assay.runner import run as run_eval

from gauntlet.suite import build_suite, format_summary, summarize


def _run(defense: str, model: str, out: str):
    target, dataset, scorers = build_suite(defense, model=model)
    return run_eval(
        target, dataset, scorers,
        config={"defense": defense}, out_dir=out, progress=True,
    )


def cmd_run(args: argparse.Namespace) -> int:
    run = _run(args.defense, args.model, args.out)
    print(report.format_run(run))
    print()
    print(format_summary(summarize(run)))
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    print(f"Running defense={args.a} …", file=sys.stderr)
    run_a = _run(args.a, args.model, args.out)
    print(f"Running defense={args.b} …", file=sys.stderr)
    run_b = _run(args.b, args.model, args.out)

    sa, sb = summarize(run_a), summarize(run_b)
    print(format_summary(sa))
    print()
    print(format_summary(sb))

    asr_delta = sb.attack_success_rate - sa.attack_success_rate
    benign_delta = sb.benign_answer_rate - sa.benign_answer_rate
    print("\n" + "=" * 52)
    print(f"ASR   {args.a} → {args.b}:  {sa.attack_success_rate:.1%} → "
          f"{sb.attack_success_rate:.1%}  ({asr_delta:+.1%})")
    print(f"Benign {args.a} → {args.b}:  {sa.benign_answer_rate:.1%} → "
          f"{sb.benign_answer_rate:.1%}  ({benign_delta:+.1%})")
    verdict = (
        "defense reduced attack success"
        if asr_delta < 0
        else "no improvement" if asr_delta == 0 else "defense made it WORSE"
    )
    print(f"Verdict: {verdict}.")
    print("=" * 52)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gauntlet", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="attack-success-rate for one defense level")
    r.add_argument("--defense", default="none", choices=("none", "guard", "shield"))
    r.add_argument("--model", default="claude-opus-4-8")
    r.add_argument("-o", "--out", default="runs")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("compare", help="compare two defense levels (ASR + benign cost)")
    c.add_argument("--a", default="none", choices=("none", "guard", "shield"))
    c.add_argument("--b", default="shield", choices=("none", "guard", "shield"))
    c.add_argument("--model", default="claude-opus-4-8")
    c.add_argument("-o", "--out", default="runs")
    c.set_defaults(func=cmd_compare)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
