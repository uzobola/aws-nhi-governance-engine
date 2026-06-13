# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


from __future__ import annotations
import argparse
import json
import sys
from .models import Config, Severity
from .collectors import AwsCollector, DemoCollector
from .engine import run_detectors
from .reporting import build_report
from .policy import READONLY_POLICY



def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Cloud NHI Governance Engine (Phase 1)")
    p.add_argument("--demo", action="store_true", help="run offline against fixtures")
    p.add_argument("--profile", help="AWS profile name")
    p.add_argument("--region", help="AWS region")
    p.add_argument("--output", default="-", help="output JSON path ('-' = stdout)")
    p.add_argument("--print-policy", action="store_true",
                   help="print the read-only IAM policy the engine needs and exit")
    args = p.parse_args(argv)

    if args.print_policy:
        print(json.dumps(READONLY_POLICY, indent=2))
        return 0

    cfg = Config()
    collector: BaseCollector = DemoCollector() if args.demo else \
        AwsCollector(profile=args.profile, region=args.region)

    records = collector.collect()
    findings = run_detectors(records, cfg)
    report = build_report(records, findings, collector.account_id())

    out = json.dumps(report, indent=2)
    if args.output == "-":
        print(out)
    else:
        with open(args.output, "w") as fh:
            fh.write(out)
        print(f"Wrote {len(findings)} findings across {len(records)} NHIs "
              f"-> {args.output}", file=sys.stderr)

    # Non-zero exit if anything HIGH/CRITICAL, so this can gate a pipeline later.
    severe = sum(1 for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL))
    return 1 if severe else 0


if __name__ == "__main__":
    raise SystemExit(main())