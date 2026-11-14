#!/usr/bin/env python3
"""Offline CFData CSV filtering. No DNS lookups or network probes.

Column overrides are 1-based indices or exact header names. Headerless inference
prefers unit-bearing latency and country labels over colo codes. Multiple bare
numeric candidates are an error, never resolved by position. Explicit source-IP
country takes precedence over generic country and landing colo, even if unknown.
Conflicting regions for the same endpoint quarantine that endpoint entirely.
"""
from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import os
import re
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from decimal import Decimal, DecimalException
from pathlib import Path

REGIONS = ("HK", "TW", "JP", "US", "KR", "SG", "DE")
ALIASES = {
    "HK": ("HK", "HONGKONG", "香港", "中国香港", "香港特别行政区"),
    "TW": ("TW", "TAIWAN", "台湾", "中国台湾", "臺灣"),
    "JP": ("JP", "JAPAN", "日本"),
    "US": ("US", "USA", "UNITEDSTATES", "UNITEDSTATESOFAMERICA", "美国", "美國"),
    "KR": ("KR", "KOREA", "SOUTHKOREA", "韩国", "韓國", "大韩民国"),
    "SG": ("SG", "SINGAPORE", "新加坡", "狮城"),
    "DE": ("DE", "GERMANY", "德国", "德國"),
}
COLOS = {
    "HKG": "HK", "TPE": "TW", "KHH": "TW", "NRT": "JP", "KIX": "JP",
    "FUK": "JP", "HND": "JP", "ICN": "KR", "GMP": "KR", "SIN": "SG",
    "FRA": "DE", "MUC": "DE", "HAM": "DE", "DUS": "DE", "BER": "DE",
    "LAX": "US", "SJC": "US", "SFO": "US", "SEA": "US", "ORD": "US",
    "DFW": "US", "IAD": "US", "EWR": "US", "JFK": "US", "ATL": "US",
    "MIA": "US", "BOS": "US", "DEN": "US", "PHX": "US", "PDX": "US",
}
NUMBER = r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?"
LATENCY_RE = re.compile(rf"^\s*({NUMBER})\s*(ms|us|µs|μs|s|毫秒|微秒|秒)?\s*$", re.I)
UNIT_FACTORS = {"ms": Decimal(1), "毫秒": Decimal(1), "s": Decimal(1000),
                "秒": Decimal(1000), "us": Decimal(".001"), "µs": Decimal(".001"),
                "μs": Decimal(".001"), "微秒": Decimal(".001")}


class FilterError(ValueError):
    """Input cannot be safely interpreted or published."""


def normalize(value: str) -> str:
    return re.sub(r"[\s_\-:：/()（）]+", "", value).upper()


COUNTRIES = {normalize(alias): region for region, aliases in ALIASES.items() for alias in aliases}


def parse_region(value: str, *, allow_colo: bool = True) -> str | None:
    value = value.strip()
    # Strip a complete, validated latency suffix before tokenizing country/colo
    # labels. This preserves exponent signs and never discards a negative sign.
    timed_label = re.fullmatch(rf"(.+?)-\s*({NUMBER}\s*(?:ms|us|µs|μs|s|毫秒|微秒|秒))", value, re.I)
    if timed_label:
        if parse_latency(timed_label[2], allow_bare=False) is None:
            return None
        value = timed_label[1]
    country = COUNTRIES.get(normalize(value))
    if country:
        return country
    # Annotated endpoints commonly use #HKG-HK or #HK-12ms.
    tokens = [token for token in re.split(r"[-/#|]+", value.upper()) if token]
    # Do not recognize arbitrary prose merely because it contains a country.
    if any(normalize(token) not in COUNTRIES and normalize(token) not in COLOS
           and parse_latency(token, allow_bare=False) is None for token in tokens):
        return None
    tokens = [normalize(token) for token in tokens]
    countries = {COUNTRIES[normalize(t)] for t in tokens if normalize(t) in COUNTRIES}
    if len(countries) == 1:
        return next(iter(countries))
    if len(countries) > 1:
        return None
    if allow_colo:
        regions = {COLOS[t] for t in tokens if t in COLOS}
        if len(regions) == 1:
            return next(iter(regions))
    return None


def parse_latency(value: str, *, allow_bare: bool = True, default_unit: str = "ms") -> Decimal | None:
    match = LATENCY_RE.fullmatch(value)
    if not match or (not allow_bare and not match[2]):
        return None
    try:
        number = Decimal(match[1])
        if number < 0:
            return None
        result = number * UNIT_FACTORS[(match[2] or default_unit).lower()]
    except (DecimalException, KeyError):
        return None
    if not result.is_finite() or result < 0:
        return None
    # Avoid pathological exponent expansion in the text output.
    if result > Decimal("1e12") or (result and result.adjusted() < -12):
        return None
    return result


def format_latency(value: Decimal) -> str:
    return format(value, "f").rstrip("0").rstrip(".") if value != value.to_integral() else str(int(value))


def parse_port(value: str) -> int:
    if not re.fullmatch(r"[0-9]{1,5}", value.strip()):
        raise ValueError("invalid_port")
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("invalid_port")
    return port


def parse_ip(value: str):
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    if "%" in value:
        raise ValueError("invalid_ip")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("invalid_ip") from None
    if not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_loopback:
        raise ValueError("non_public_ip")
    return ip


def parse_endpoint(value: str, port_value: str | None = None) -> tuple[str, str]:
    """Return canonical endpoint and optional #-annotation; never invent a port."""
    address, _, annotation = value.strip().partition("#")
    if port_value is not None:
        port = parse_port(port_value)
        # A redundant separate port is allowed, but must agree with the endpoint.
        try:
            combined, _ = parse_endpoint(address)
        except ValueError:
            combined = None
        if combined is not None:
            if int(combined.rsplit(":", 1)[1]) != port:
                raise ValueError("port_conflict")
            return combined, annotation
        ip = parse_ip(address)
    else:
        if address.startswith("["):
            match = re.fullmatch(r"\[([^\]]+)\]:([^:]+)", address)
            if not match:
                raise ValueError("invalid_endpoint")
            host, port_text = match.groups()
        else:
            if address.count(":") != 1:
                raise ValueError("missing_or_invalid_port")
            host, port_text = address.split(":")
        ip = parse_ip(host)
        port = parse_port(port_text)
    return (f"[{ip}]:{port}" if ip.version == 6 else f"{ip}:{port}"), annotation


def header_kind(value: str) -> str | None:
    name = normalize(value)
    if name in {"IPPORT", "ENDPOINT", "ADDRESSPORT", "地址端口", "IP端口"}:
        return "endpoint"
    if name in {"IP", "IPADDRESS", "ADDRESS", "IP地址", "地址"}:
        return "ip"
    if name in {"PORT", "端口", "端口号"}:
        return "port"
    if name in {"源IP位置", "源IP地区", "源IP国家", "源IP归属地", "IP所属地区", "IP位置", "IP地区", "IP国家",
                "SOURCEIPLOCATION", "SOURCEIPCOUNTRY", "SOURCEIPREGION", "SOURCECOUNTRY", "源地址地区"}:
        return "source_region"
    if name in {"REGION", "REGIONCODE", "COUNTRY", "COUNTRYCODE", "COUNTRYREGION", "国家", "国家代码", "地区", "国家地区", "位置", "地理位置"}:
        return "region"
    if name in {"COLO", "COLOCATION", "DATACENTER", "DATACENTRE", "数据中心", "机房", "落地", "落地地区", "落地位置", "落地国家", "落地COLO"}:
        return "colo"
    if any(token in name for token in ("LATENCY", "DELAY", "RTT", "延迟", "时延")):
        return "latency"
    if any(token in name for token in ("SPEED", "DOWNLOAD", "UPLOAD", "LOSS", "PERCENT", "速度", "速率", "丢包", "百分比", "成功率", "带宽")):
        return "ignore"
    return None


def header_unit(value: str) -> str:
    match = re.search(r"[（(\[]\s*(ms|us|µs|μs|s|毫秒|微秒|秒)\s*[）)\]]", value, re.I)
    return match[1].lower() if match else "ms"


def read_csv(text: str) -> tuple[list[str] | None, list[list[str]], str]:
    text = text.lstrip("\ufeff")
    if not text.strip():
        raise FilterError("empty input")
    # csv.Sniffer is fragile on malformed/heterogeneous rows. Try the supported
    # delimiters with the real CSV parser, choosing consistent useful widths.
    candidates = []
    for delimiter in (",", ";", "\t"):
        try:
            rows = [row for row in csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
                    if any(cell.strip() for cell in row)]
        except csv.Error:
            continue
        widths = Counter(len(row) for row in rows)
        useful = sum(count for width, count in widths.items() if width > 1)
        candidates.append((useful, widths.most_common(1)[0][1] if widths else 0, delimiter, rows))
    if not candidates:
        raise FilterError("invalid CSV quoting")
    _, _, delimiter, rows = max(candidates, key=lambda item: item[:2])
    if not rows:
        raise FilterError("empty input")
    kinds = [header_kind(cell) for cell in rows[0]]
    # An IP/endpoint header alone is sufficient; otherwise require two labels.
    has_header = any(k in {"endpoint", "ip"} for k in kinds) or sum(k is not None for k in kinds) >= 2
    return (rows[0], rows[1:], delimiter) if has_header else (None, rows, delimiter)


@dataclass(frozen=True)
class Mapping:
    endpoint: int
    port: int | None
    region: int | None
    latency: int | None
    latency_unit: str = "ms"
    endpoint_kind: str = "endpoint"
    region_kind: str = "embedded"

    def report(self, header: list[str] | None) -> dict:
        result = {}
        for name in ("endpoint", "port", "region", "latency"):
            index = getattr(self, name)
            result[name] = ({"column": index + 1, "name": header[index] if header and index < len(header) else None}
                            if index is not None else "embedded" if name in {"region", "latency"} else None)
        result.update(latency_unit=self.latency_unit, endpoint_kind=self.endpoint_kind, region_kind=self.region_kind)
        return result


def infer_mapping(header: list[str] | None, rows: list[list[str]], overrides: dict | None = None) -> Mapping:
    overrides = overrides or {}
    width = max([len(header or [])] + [len(row) for row in rows])
    if not width or not rows:
        raise FilterError("no data rows")
    kinds = {i: header_kind(name) for i, name in enumerate(header or [])}
    columns = {i: [row[i].strip() for row in rows if i < len(row) and row[i].strip()] for i in range(width)}

    def resolve(role):
        value = overrides.get(role)
        if value is None:
            return None
        value = str(value)
        if value.isdecimal():
            index = int(value) - 1
            if 0 <= index < width:
                return index
        elif header and header.count(value) == 1:
            return header.index(value)
        raise FilterError(f"invalid {role} column override: {value!r}; use a 1-based index or exact header")

    def unique(indices, role):
        if len(indices) > 1:
            raise FilterError(f"ambiguous {role} columns {[i + 1 for i in indices]}; use --{role}-column")
        return indices[0] if indices else None

    def named(role, alternatives):
        explicit = resolve(role)
        if explicit is not None:
            return explicit
        for kind in alternatives:
            indices = [i for i, k in kinds.items() if k == kind]
            if indices:
                return unique(indices, role)
        return None

    def count_valid(index, parser):
        count = 0
        for value in columns[index]:
            try:
                count += parser(value) is not None
            except ValueError:
                pass
        return count

    def content_candidates(indices, parser):
        """Ignore rare cross-type dirt only when another column is convincing.

        At least three observations and >=80% row support are required before
        rejecting a competing column with <=20% support. Otherwise retain all
        candidates and let ambiguity fail closed (particularly numeric fields).
        """
        counts = {i: count_valid(i, parser) for i in indices}
        strong = [i for i, count in counts.items() if count >= 3 and count * 5 >= len(rows) * 4]
        return [i for i, count in counts.items() if count and
                (not strong or i in strong or count * 5 > len(rows))]

    endpoint = named("endpoint", ("endpoint", "ip"))
    endpoint_kind = kinds.get(endpoint, "endpoint")
    if endpoint is None:
        candidates = content_candidates([i for i in columns if not kinds.get(i)], parse_endpoint)
        endpoint = unique(candidates, "endpoint")
        endpoint_kind = "endpoint"
        if endpoint is None:
            endpoint = unique(content_candidates([i for i in columns if not kinds.get(i)], parse_ip), "endpoint")
            endpoint_kind = "ip"
    if endpoint is None:
        raise FilterError("no usable IP/endpoint column")
    # An IP-labelled column may actually contain complete endpoints; an override
    # can likewise identify either representation.
    if endpoint_kind == "ip" or overrides.get("endpoint") is not None:
        endpoint_kind = "endpoint" if count_valid(endpoint, parse_endpoint) else "ip"
    port = named("port", ("port",))
    used = {endpoint}
    if port is not None:
        used.add(port)
    annotations = [value.partition("#")[2] for value in columns[endpoint] if "#" in value]
    embedded_country = any(parse_region(value, allow_colo=False) for value in annotations)
    embedded_latency = any(annotation_latency(value) is not None for value in annotations)
    region = named("region", ("source_region", "region", "colo"))
    region_kind = (kinds.get(region) or "inferred_country") if region is not None else "embedded"
    if region is None:
        available = [i for i in columns if i not in used and not kinds.get(i)]
        direct = content_candidates(available, lambda x: parse_region(x, allow_colo=False))
        indirect = content_candidates(available, parse_region)
        region = unique(direct or ([] if embedded_country else indirect), "region")
        if region is not None:
            region_kind = "inferred_country" if direct else "inferred_colo"
    if region is not None:
        used.add(region)
    latency = named("latency", ("latency",))
    if latency is None:
        available = [i for i in columns if i not in used and not kinds.get(i)]
        unit_parser = lambda x: parse_latency(x, allow_bare=False)
        unit_columns = content_candidates(available, unit_parser)
        # One stray unit token must not promote a mostly-bare speed/count field
        # above another bare numeric field. Mixed-unit/bare columns still work
        # when unambiguous, via the conservative numeric-candidate pass below.
        unit_columns = [i for i in unit_columns
                        if len(columns[i]) < 3 or
                        count_valid(i, unit_parser) * 5 >= count_valid(i, parse_latency) * 4]
        latency = unique(unit_columns, "latency")
        if latency is None and not embedded_latency:
            numeric = []
            for i in available:
                values = columns[i]
                if not values or not count_valid(i, parse_latency):
                    continue
                # A headerless port repeated beside a full endpoint isn't RTT.
                matching_ports = []
                for row in rows:
                    if i >= len(row) or endpoint >= len(row) or not row[i].strip():
                        continue
                    try:
                        ep, _ = parse_endpoint(row[endpoint])
                        matching_ports.append(parse_latency(row[i]) == Decimal(ep.rsplit(":", 1)[1]))
                    except ValueError:
                        pass
                if matching_ports and all(matching_ports):
                    continue
                numeric.append(i)
            latency = unique(numeric, "latency")
    if latency is not None:
        if latency in used:
            raise FilterError("latency column overlaps endpoint/port/region")
        used.add(latency)
    if endpoint_kind == "ip" and port is None:
        port = unique([i for i in columns if i not in used and not kinds.get(i) and count_valid(i, parse_port)], "port")
        if port is None:
            raise FilterError("separate IP needs a port column; use --port-column (no default port)")
    if port == endpoint or region == endpoint or (port is not None and region == port):
        raise FilterError("column roles overlap")
    unit = header_unit(header[latency]) if header and latency is not None and latency < len(header) else "ms"
    return Mapping(endpoint, port, region, latency, unit, endpoint_kind or "endpoint", region_kind)


@dataclass(frozen=True)
class Result:
    endpoint: str
    region: str
    latency: Decimal

    def line(self) -> str:
        return f"{self.endpoint}#{self.region}-{format_latency(self.latency)}ms"


def annotation_latency(annotation: str) -> Decimal | None:
    # Anchor the entire label: never restart a suffix search after a minus sign.
    match = re.fullmatch(rf"(.+?)-\s*({NUMBER}\s*(?:ms|us|µs|μs|s|毫秒|微秒|秒))", annotation.strip(), re.I)
    return (parse_latency(match[2], allow_bare=False)
            if match and parse_region(match[1]) is not None else None)


def filter_text(text: str, per_region: int = 10, overrides: dict | None = None) -> tuple[list[Result], dict]:
    if not 1 <= per_region <= 10:
        raise FilterError("per-region must be between 1 and 10")
    header, rows, delimiter = read_csv(text)
    mapping = infer_mapping(header, rows, overrides)
    stats = {"rows": len(rows), "delimiter": repr(delimiter), "mapping": mapping.report(header)}
    dropped = Counter()
    best = {}
    conflicts = set()
    parsed = 0
    for row in rows:
        try:
            endpoint, annotation = parse_endpoint(row[mapping.endpoint], row[mapping.port] if mapping.port is not None else None)
            region = parse_region(row[mapping.region]) if mapping.region is not None else parse_region(annotation)
            if region is None:
                dropped["unknown_region"] += 1
                continue
            latency = (parse_latency(row[mapping.latency], default_unit=mapping.latency_unit)
                       if mapping.latency is not None else annotation_latency(annotation))
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
        result = Result(endpoint, region, latency)
        if endpoint in best:
            previous = best[endpoint]
            if previous.region != region:
                conflicts.add(endpoint)
            if latency < previous.latency:
                best[endpoint] = result
            dropped["duplicate_endpoint"] += 1
        else:
            best[endpoint] = result
    dropped["region_conflict_endpoints"] = len(conflicts)
    usable = [result for endpoint, result in best.items() if endpoint not in conflicts]
    selected = []
    for region in REGIONS:
        selected.extend(sorted((r for r in usable if r.region == region), key=lambda r: (r.latency, r.endpoint))[:per_region])
    stats.update(parsed=parsed, unique_publishable=len(usable), selected=len(selected),
                 regions=dict(Counter(r.region for r in selected)), dropped=dict(dropped))
    if not selected:
        raise FilterError("no publishable results; " + json.dumps(stats, ensure_ascii=False, sort_keys=True))
    return selected, stats


def atomic_write(output: Path, results: list[Result]) -> None:
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", prefix=f".{output.name}.",
                                         suffix=".tmp", dir=output.parent, delete=False) as stream:
            path = Path(stream.name)
            stream.write("".join(result.line() + "\n" for result in results))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(path, output)
    finally:
        if path is not None and path.exists():
            path.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=Path("raw/results.csv"))
    parser.add_argument("--output", type=Path, default=Path("api/preferred.txt"))
    parser.add_argument("--per-region", type=int, default=10)
    for role in ("endpoint", "port", "region", "latency"):
        parser.add_argument(f"--{role}-column", help="1-based index or exact header name")
    args = parser.parse_args(argv)
    overrides = {role: getattr(args, role + "_column") for role in ("endpoint", "port", "region", "latency")}
    try:
        if args.input.resolve() == args.output.resolve():
            raise FilterError("input and output must be different files")
        results, stats = filter_text(args.input.read_text(encoding="utf-8-sig"), args.per_region, overrides)
        atomic_write(args.output, results)
    except (FilterError, OSError, UnicodeError, csv.Error) as error:
        print(f"filter_ips: error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(stats, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
