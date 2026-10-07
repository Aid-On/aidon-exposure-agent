from __future__ import annotations
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from .agent import DEFAULT_ENGINE, ROOT, assess, comparison, recheck, render
from .boundary import InputError, load


def write_outputs(report, directory, prefix="report"):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"{prefix}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    (directory / f"{prefix}.txt").write_text(render(report))


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline, fixture-only exposure inspection agent; no network capability")
    parser.add_argument("--engine", default=str(DEFAULT_ENGINE), help="Path to the trusted, locally built Almide engine")
    sub = parser.add_subparsers(dest="command", required=True)
    assess_cmd = sub.add_parser("assess")
    assess_cmd.add_argument("snapshot")
    assess_cmd.add_argument("--manifest", required=True)
    assess_cmd.add_argument("--at", help="Explicit evaluation clock; defaults to current UTC")
    assess_cmd.add_argument("--out", default="output")
    demo_cmd = sub.add_parser("demo")
    demo_cmd.add_argument("--out", default="output/demo")
    check = sub.add_parser("recheck")
    check.add_argument("before")
    check.add_argument("after")
    check.add_argument("--manifest", required=True)
    check.add_argument("--before-at", required=True)
    check.add_argument("--after-at", required=True)
    check.add_argument("--out", default="output/recheck")
    args = parser.parse_args(argv)
    try:
        if args.command == "assess":
            report = assess(load(args.manifest), load(args.snapshot), args.at or datetime.now(timezone.utc), args.engine)
            write_outputs(report, args.out)
            print(render(report), end="")
        else:
            demo = args.command == "demo"
            fixtures = ROOT / "fixtures"
            manifest = load(fixtures / "manifest.json" if demo else args.manifest)
            before = assess(manifest, load(fixtures / "before.json" if demo else args.before), "2026-10-07T09:30:00Z" if demo else args.before_at, args.engine)
            after = assess(manifest, load(fixtures / "after.json" if demo else args.after), "2026-10-07T10:30:00Z" if demo else args.after_at, args.engine)
            write_outputs(before, args.out, "before")
            write_outputs(after, args.out, "after")
            results = recheck(before, after)
            if demo:
                results["comparison"] = comparison(before, load(fixtures / "ground_truth.json"))
                results["clock"] = "Fixed synthetic clocks, not current-world observations"
            (Path(args.out) / "recheck.json").write_text(json.dumps(results, indent=2) + "\n")
            print(json.dumps(results, indent=2))
    except (InputError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"Inspection failed closed: {exc}", file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
