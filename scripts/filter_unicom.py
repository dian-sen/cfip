#!/usr/bin/env python3
"""Generate api/Unicom.txt from the offline Unicom CFData upload."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

# Reuse the validated parser and column inference used by preferred.txt.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import filter_ips as base  # noqa: E402

TARGETS = {"JP": 20, "SG": 10, "US": 30}
OTHER_LIMIT = 0

# ISO 3166-1 alpha-2 assigned country/territory codes. Unknown labels must
# never become an "other" result merely because they contain two letters.
ISO_COUNTRIES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY
MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY
QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ
VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
""".split())
COUNTRY_ALIASES = {
    "GB": ("UK", "United Kingdom", "Great Britain", "Britain", "英国", "英國"),
    "NL": ("Netherlands", "Holland", "荷兰", "荷蘭"),
    "AU": ("Australia", "澳大利亚", "澳大利亞", "澳洲"),
    "CA": ("Canada", "加拿大"), "FR": ("France", "法国", "法國"),
    "IN": ("India", "印度"), "CN": ("China", "中国", "中國"),
    "MO": ("Macao", "Macau", "澳门", "澳門"),
    "NZ": ("New Zealand", "新西兰", "紐西蘭"),
    "RU": ("Russia", "Russian Federation", "俄罗斯", "俄羅斯"),
    "BR": ("Brazil", "巴西"), "ZA": ("South Africa", "南非"),
    "CH": ("Switzerland", "瑞士"), "SE": ("Sweden", "瑞典"),
    "FI": ("Finland", "芬兰", "芬蘭"), "NO": ("Norway", "挪威"),
    "DK": ("Denmark", "丹麦", "丹麥"), "ES": ("Spain", "西班牙"),
    "IT": ("Italy", "意大利", "義大利"), "PL": ("Poland", "波兰", "波蘭"),
    "AT": ("Austria", "奥地利", "奧地利"), "TR": ("Turkey", "Türkiye", "土耳其"),
    "AE": ("United Arab Emirates", "UAE", "阿联酋", "阿聯酋"),
    "TH": ("Thailand", "泰国", "泰國"), "MY": ("Malaysia", "马来西亚", "馬來西亞"),
    "ID": ("Indonesia", "印度尼西亚", "印尼"), "PH": ("Philippines", "菲律宾", "菲律賓"),
    "VN": ("Vietnam", "越南"), "HU": ("Hungary", "匈牙利"),
}
COUNTRIES = {**base.COUNTRIES, **{code: code for code in ISO_COUNTRIES},
             **{base.normalize(alias): code for code, aliases in COUNTRY_ALIASES.items() for alias in aliases}}

# Colo codes are accepted only when explicitly mapped to a country.
COLO_TO_REGION = {
    **base.COLOS,
    "AMS": "NL", "LHR": "GB", "MAN": "GB", "CDG": "FR", "MAD": "ES",
    "WAW": "PL", "HEL": "FI", "ARN": "SE", "ZRH": "CH", "VIE": "AT",
    "IST": "TR", "DXB": "AE", "BOM": "IN", "DEL": "IN", "BKK": "TH",
    "KUL": "MY", "CGK": "ID", "MNL": "PH", "SYD": "AU", "MEL": "AU",
    "AKL": "NZ", "YVR": "CA", "YYZ": "CA", "GRU": "BR", "JNB": "ZA",
}


def other_region(value: str, *, allow_colo: bool = True) -> str | None:
    """Parse a known country/colo, including validated endpoint annotations."""
    return base.parse_region(value, allow_colo=allow_colo,
                             countries=COUNTRIES, colos=COLO_TO_REGION)


def filter_unicom(text: str, overrides: dict | None = None):
    header, rows, delimiter = base.read_csv(text)
    mapping = base.infer_mapping(header, rows, overrides, region_parser=other_region)
    dropped = Counter()
    best = {}
    conflicts = set()
    parsed = 0

    for row in rows:
        try:
            endpoint, annotation = base.parse_endpoint(
                row[mapping.endpoint], row[mapping.port] if mapping.port is not None else None
            )
            region_value = row[mapping.region] if mapping.region is not None else annotation
            region = other_region(region_value)
            if region is None:
                dropped["unknown_region"] += 1
                continue
            latency = (
                base.parse_latency(row[mapping.latency], default_unit=mapping.latency_unit)
                if mapping.latency is not None
                else base.annotation_latency(annotation, region_parser=other_region)
            )
            if latency is None:
                dropped["invalid_or_missing_latency"] += 1
                continue
        except IndexError:
            dropped["short_row"] += 1
            continue
        except ValueError as error:
            dropped[str(error)] += 1
            continue

        parsed += 1
        result = base.Result(endpoint, region, latency)
        if endpoint in best:
            old = best[endpoint]
            if old.region != region:
                conflicts.add(endpoint)
            if latency < old.latency:
                best[endpoint] = result
            dropped["duplicate_endpoint"] += 1
        else:
            best[endpoint] = result

    usable = [r for endpoint, r in best.items() if endpoint not in conflicts]
    selected = []
    for region, limit in TARGETS.items():
        selected.extend(sorted((r for r in usable if r.region == region), key=lambda r: (r.latency, r.endpoint))[:limit])

    target_endpoints = {r.endpoint for r in selected}
    others = sorted(
        (r for r in usable if r.endpoint not in target_endpoints and r.region not in TARGETS),
        key=lambda r: (r.latency, r.endpoint),
    )[:OTHER_LIMIT]
    selected.extend(others)
    selected.sort(key=lambda r: (r.latency, r.endpoint))

    if not selected:
        raise base.FilterError("no publishable results")
    stats = {
        "rows": len(rows), "delimiter": repr(delimiter), "mapping": mapping.report(header),
        "parsed": parsed, "selected": len(selected),
        "targets": dict(Counter(r.region for r in selected if r.region in TARGETS)),
        "other": len(others), "other_regions": dict(Counter(r.region for r in others)),
        "dropped": dict(dropped), "region_conflict_endpoints": len(conflicts),
    }
    return selected, stats


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("raw/results_unicom.csv"))
    parser.add_argument("--output", type=Path, default=Path("api/Unicom.txt"))
    for role in ("endpoint", "port", "region", "latency"):
        parser.add_argument(f"--{role}-column")
    args = parser.parse_args(argv)
    overrides = {role: getattr(args, role + "_column") for role in ("endpoint", "port", "region", "latency")}
    try:
        if args.input.resolve() == args.output.resolve() or (
                args.input.exists() and args.output.exists() and args.input.samefile(args.output)):
            raise base.FilterError("input and output must be different files")
        results, stats = filter_unicom(args.input.read_text(encoding="utf-8-sig"), overrides)
        base.atomic_write(args.output, results)
    except (base.FilterError, OSError, UnicodeError, csv.Error) as error:
        print(f"filter_unicom: error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(stats, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
