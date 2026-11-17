"""Offline Unicom parsing, selection and safe publishing regressions."""
import contextlib
import csv
import importlib.util
import io
import json
import os
import random
import sys
import tempfile
import unittest
from collections import Counter
from decimal import Decimal
from itertools import permutations
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("filter_unicom", ROOT / "scripts/filter_unicom.py")
u = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = u
spec.loader.exec_module(u)
b = u.base


def render(rows, header=None, delimiter=","):
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, delimiter=delimiter)
    if header is not None:
        writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue()


def lines(results):
    return [r.line() for r in results]


class RegionTests(unittest.TestCase):
    def test_complete_iso_codes_and_strict_unknowns(self):
        self.assertEqual(len(u.ISO_COUNTRIES), 249)
        for code in u.ISO_COUNTRIES:
            with self.subTest(code=code):
                self.assertEqual(u.other_region(code.lower()), code)
        for value in ("HUH", "ZZ", "XX", "AAA", "XYZ", "unknown", "not-GB", "hello AU", "GB-NL"):
            with self.subTest(value=value):
                self.assertIsNone(u.other_region(value))
        # The preferred parser retains its original seven-region vocabulary.
        self.assertIsNone(b.parse_region("GB"))
        self.assertIsNone(b.parse_region("AMS"))

    def test_aliases_colos_and_annotations(self):
        for value, expected in (("英国", "GB"), ("荷蘭", "NL"), ("Australia", "AU"),
                                ("United Kingdom", "GB"), ("新加坡", "SG"), ("日本", "JP"),
                                ("United States", "US"), ("LHR", "GB"), ("AMS", "NL"),
                                ("SYD", "AU"), ("HKG-HK", "HK"), ("LHR-GB-12ms", "GB"),
                                ("NL-1e-3ms", "NL"), ("NRT-US", "US")):
            with self.subTest(value=value):
                self.assertEqual(u.other_region(value), expected)
        self.assertIsNone(u.other_region("LHR", allow_colo=False))
        self.assertEqual(u.other_region("LHR-GB", allow_colo=False), "GB")
        for value in ("GB--5ms", "NL- -5ms", "AU-NaNms", "GB-1e999ms"):
            with self.subTest(value=value):
                self.assertIsNone(u.other_region(value))
                self.assertIsNone(b.annotation_latency(value, region_parser=u.other_region))


class FilterTests(unittest.TestCase):
    def test_real_unicom_source_quotas_and_minima(self):
        text = (ROOT / "raw/results_unicom.csv").read_text(encoding="utf-8-sig")
        results, stats = u.filter_unicom(text)
        self.assertEqual(stats["mapping"]["region"]["name"], "源IP位置")
        original = list(csv.DictReader(io.StringIO(text)))
        # Independent selection oracle from the real, explicitly named columns.
        best, conflicts = {}, set()
        for row in original:
            endpoint, _ = b.parse_endpoint(row["IP:PORT"])
            region, latency = u.other_region(row["源IP位置"]), b.parse_latency(row["网络延迟"])
            if region is None or latency is None:
                continue
            if endpoint in best and best[endpoint].region != region:
                conflicts.add(endpoint)
            if endpoint not in best or latency < best[endpoint].latency:
                best[endpoint] = b.Result(endpoint, region, latency)
        usable = [r for ep, r in best.items() if ep not in conflicts]
        expected = []
        for region, limit in u.TARGETS.items():
            group = sorted((r for r in usable if r.region == region), key=lambda r: (r.latency, r.endpoint))
            expected.extend(group[:limit])
            self.assertEqual(sum(r.region == region for r in results), min(limit, len(group)))
        other = sorted((r for r in usable if r.region not in u.TARGETS), key=lambda r: (r.latency, r.endpoint))[:10]
        expected.extend(other)
        expected.sort(key=lambda r: (r.latency, r.endpoint))
        self.assertEqual(results, expected)
        # Current source has 32 JP, 670 US, 13 NL, 10 CA and only 1 SG.
        self.assertEqual(stats["targets"], {"JP": 20, "SG": 1, "US": 20})
        self.assertEqual(stats["other"], 10)
        self.assertEqual(len(results), 51)
        rows = [[row[name] for name in original[0]] for row in original]
        random.Random(9).shuffle(rows)
        self.assertEqual(lines(u.filter_unicom(render(rows, list(original[0])))[0]), lines(results))

    def test_headerless_pure_other_countries_all_column_orders(self):
        rows = [["31ms", "GB", "8.8.8.8:443"], [".02s", "NL", "1.1.1.1:8443"],
                ["10000us", "AU", "9.9.9.9:443"]]
        for order in permutations(range(3)):
            for delimiter in (",", ";", "\t"):
                with self.subTest(order=order, delimiter=delimiter):
                    shuffled = [[row[i] for i in order] for row in reversed(rows)]
                    results, stats = u.filter_unicom(render(shuffled, delimiter=delimiter))
                    self.assertEqual([r.region for r in results], ["AU", "NL", "GB"])
                    self.assertEqual([r.latency for r in results], [Decimal(10), Decimal(20), Decimal(31)])
                    self.assertEqual(stats["other"], 3)

    def test_headerless_aliases_and_country_precedes_colo(self):
        rows = [["LAX", "英国", "8.8.8.8:443", "3ms"],
                ["NRT", "Netherlands", "1.1.1.1:443", "2ms"],
                ["SIN", "Australia", "9.9.9.9:443", "1ms"]]
        results, stats = u.filter_unicom(render(rows))
        self.assertEqual([r.region for r in results], ["AU", "NL", "GB"])
        self.assertEqual(stats["mapping"]["region_kind"], "inferred_country")
        results, stats = u.filter_unicom(render([["SYD", "8.8.8.8:443", "1ms"],
                                                 ["AMS", "1.1.1.1:443", "2ms"]]))
        self.assertEqual([r.region for r in results], ["AU", "NL"])
        self.assertEqual(stats["mapping"]["region_kind"], "inferred_colo")

    def test_embedded_countries_latency_and_colo(self):
        text = "8.8.8.8:443#LHR-GB-12ms\n1.1.1.1:443#AMS-NL-10ms\n9.9.9.9:443#HKG-HK-8ms\n"
        results, stats = u.filter_unicom(text)
        self.assertEqual([r.region for r in results], ["HK", "NL", "GB"])
        self.assertEqual(stats["mapping"]["latency"], "embedded")
        results, stats = u.filter_unicom("8.8.8.8:443#GB-12ms,NRT,999\n")
        self.assertEqual(lines(results), ["8.8.8.8:443#GB-12ms"])
        self.assertEqual(stats["mapping"]["region"], "embedded")
        self.assertEqual(lines(u.filter_unicom("8.8.8.8:443#HKG-HK,1ms\n")[0]),
                         ["8.8.8.8:443#HK-1ms"])
        # An explicit country takes precedence over an embedded annotation.
        self.assertEqual(u.filter_unicom("8.8.8.8:443#JP-12ms,GB\n")[0][0].region, "GB")

    def test_explicit_source_region_never_falls_back(self):
        text = render([
            ["8.8.8.8:443#JP-1ms", "NRT", "GB", "US", "8ms"],
            ["1.1.1.1:443#SG-1ms", "SIN", "HUH", "JP", "2ms"],
            ["9.9.9.9:443#HK-1ms", "HKG", "", "HK", "3ms"],
        ], ["IP:PORT", "colo", "源IP位置", "region", "latency"])
        results, stats = u.filter_unicom(text)
        self.assertEqual(lines(results), ["8.8.8.8:443#GB-8ms"])
        self.assertEqual(stats["dropped"]["unknown_region"], 2)
        self.assertEqual(stats["mapping"]["region_kind"], "source_region")
        self.assertEqual({r.region for r in u.filter_unicom(text, {"region": "region"})[0]}, {"US", "JP", "HK"})
        self.assertEqual({r.region for r in u.filter_unicom(text, {"region": "colo"})[0]}, {"JP", "SG", "HK"})
        # Explicit generic region likewise precedes colo/annotation, even unknown.
        with self.assertRaises(b.FilterError):
            u.filter_unicom("endpoint,region,colo,latency\n8.8.8.8:443#JP-1ms,ZZ,SIN,2ms\n")

    def test_ambiguities_fail_closed_and_overrides(self):
        cases = [("8.8.8.8:443,GB,10,100\n", "latency"),
                 ("8.8.8.8:443,GB,NL,1ms\n", "region"),
                 ("8.8.8.8:443,1.1.1.1:443,AU,1ms\n", "endpoint"),
                 ("8.8.8.8:443,AU,1ms,2ms\n", "latency")]
        for text, role in cases:
            with self.subTest(text=text), self.assertRaisesRegex(b.FilterError, "ambiguous " + role):
                u.filter_unicom(text)
        results, _ = u.filter_unicom(cases[0][0], {"latency": "3"})
        self.assertEqual(results[0].latency, Decimal(10))

    def test_bad_rows_and_unknowns(self):
        rows = [["8.8.8.8:443", "GB", "1ms"], ["1.1.1.1:443", "HUH", "2ms"],
                ["9.9.9.9:443", "ZZ", "3ms"], ["8.8.4.4:443", "GB", "-1ms"],
                ["1.0.0.1:0", "JP", "1ms"], ["10.0.0.1:443", "US", "2ms"],
                ["2606:4700::1111:443", "NL", "3ms"], ["8.8.4.4:443", "AU"],
                ["8.8.4.4:443", "AU", "NaN"], ["8.8.4.4:443", "AU", "10MB/s"]]
        results, stats = u.filter_unicom(render(rows, ["endpoint", "region", "latency"]))
        self.assertEqual(lines(results), ["8.8.8.8:443#GB-1ms"])
        self.assertEqual(stats["dropped"], {"unknown_region": 2, "invalid_or_missing_latency": 3,
                                          "invalid_port": 1, "non_public_ip": 1,
                                          "missing_or_invalid_port": 1, "short_row": 1})

    def test_duplicates_conflicts_and_ties_order_independent(self):
        rows = [["8.8.8.8:443", "GB", "9ms"], ["8.8.8.8:443", "GB", "2ms"],
                ["9.9.9.9:443", "NL", "1ms"], ["9.9.9.9:443", "AU", "2ms"],
                ["1.1.1.1:443", "JP", "2ms"], ["1.0.0.1:443", "US", "2ms"]]
        expected = ["1.0.0.1:443#US-2ms", "1.1.1.1:443#JP-2ms", "8.8.8.8:443#GB-2ms"]
        for seed in range(6):
            random.Random(seed).shuffle(rows)
            results, stats = u.filter_unicom(render(rows, ["endpoint", "region", "latency"]))
            self.assertEqual(lines(results), expected)
            self.assertEqual(stats["region_conflict_endpoints"], 1)
            self.assertEqual(stats["dropped"]["duplicate_endpoint"], 2)

    def test_full_quotas_ties_and_global_order(self):
        rows = []
        for subnet, region, count in ((1, "JP", 25), (2, "SG", 15), (3, "US", 25),
                                      (4, "GB", 15), (5, "NL", 15)):
            rows.extend([[f"8.8.{subnet}.{i}:443", region, "1ms"] for i in range(1, count + 1)])
        expected = []
        for group, limit in (("JP", 20), ("SG", 10), ("US", 20), ("other", 10)):
            candidates = [row for row in rows if (row[1] == group if group != "other" else row[1] not in u.TARGETS)]
            expected.extend(sorted(candidates, key=lambda row: row[0])[:limit])
        expected.sort(key=lambda row: row[0])
        for seed in range(3):
            random.Random(seed).shuffle(rows)
            results, stats = u.filter_unicom(render(rows, ["endpoint", "region", "latency"]))
            self.assertEqual([r.endpoint for r in results], [row[0] for row in expected])
            self.assertEqual(stats["targets"], {"JP": 20, "SG": 10, "US": 20})
            self.assertEqual(stats["other"], 10)
            self.assertEqual(len(results), 60)

    def test_no_quota_transfer_and_other_pool_is_combined(self):
        rows = [["1.1.1.1:443", "SG", "999ms"]]
        for index in range(1, 36):
            rows.append([f"8.8.8.{index}:443", ("GB", "NL", "AU")[index % 3], f"{index}ms"])
        results, stats = u.filter_unicom(render(rows, ["endpoint", "region", "latency"]))
        self.assertEqual(len(results), 1)
        self.assertEqual(stats["targets"], {"SG": 1})
        self.assertEqual(stats["other"], 0)
        self.assertEqual([r.latency for r in results],[Decimal(999)])

    def test_separate_ports_units_ipv6_and_round_trip(self):
        text = "源IP位置,端口,延迟(s),IP\n英国,443,.012,8.8.8.8\n澳洲,8443,5MS,2606:4700:4700::1111\n"
        results, _ = u.filter_unicom(text)
        self.assertEqual(lines(results), ["[2606:4700:4700::1111]:8443#AU-5ms", "8.8.8.8:443#GB-12ms"])
        self.assertEqual(lines(u.filter_unicom("\n".join(lines(results)))[0]), lines(results))
        for text in ("8.8.8.8,GB,12ms\n", "8.8.8.8:443,GB,443\n"):
            with self.subTest(text=text), self.assertRaises(b.FilterError):
                u.filter_unicom(text)


class CLITests(unittest.TestCase):
    def run_main(self, args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = u.main(args)
        return status, out.getvalue(), err.getvalue()

    def test_default_input_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "raw").mkdir()
            (root / "raw/results_unicom.csv").write_text("8.8.8.8:443#GB-12ms\n")
            old_cwd = Path.cwd()
            try:
                os.chdir(root)
                status, out, err = self.run_main([])
            finally:
                os.chdir(old_cwd)
            self.assertEqual((status, err), (0, ""))
            self.assertEqual(json.loads(out)["other"], 1)
            self.assertEqual((root / "api/Unicom.txt").read_text(), "8.8.8.8:443#GB-12ms\n")

    def test_failures_preserve_output_and_report_exception(self):
        for data, message in ((b"", "empty input"), (b"endpoint,region,latency\n8.8.8.8:443,HUH,1ms\n", "no publishable"),
                              (b"8.8.8.8:443,GB,10,100\n", "ambiguous latency"), (b"\xff", "decode")):
            with self.subTest(data=data), tempfile.TemporaryDirectory() as directory:
                source, output = Path(directory) / "input", Path(directory) / "output"
                source.write_bytes(data)
                output.write_bytes(b"original\n")
                status, out, err = self.run_main(["--input", str(source), "--output", str(output)])
                self.assertEqual((status, out), (1, ""))
                self.assertIn(message, err)
                self.assertEqual(output.read_bytes(), b"original\n")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "missing"
            status, _, err = self.run_main(["--input", str(source)])
            self.assertEqual(status, 1)
            self.assertIn("No such file", err)

    def test_reject_same_file_including_links(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_text("8.8.8.8:443#GB-1ms\n")
            symlink, hardlink = source.with_name("symlink"), source.with_name("hardlink")
            symlink.symlink_to(source)
            os.link(source, hardlink)
            for target in (source, symlink, hardlink):
                with self.subTest(target=target):
                    status, _, err = self.run_main(["--input", str(source), "--output", str(target)])
                    self.assertEqual(status, 1)
                    self.assertIn("input and output must be different files", err)
                    self.assertEqual(source.read_text(), "8.8.8.8:443#GB-1ms\n")

    def test_atomic_failure_cleanup_preserves_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "input", Path(directory) / "output"
            source.write_text("8.8.8.8:443#GB-1ms\n")
            output.write_text("original\n")
            with patch.object(b.os, "replace", side_effect=OSError("replace blocked")):
                status, _, err = self.run_main(["--input", str(source), "--output", str(output)])
            self.assertEqual(status, 1)
            self.assertIn("replace blocked", err)
            self.assertEqual(output.read_text(), "original\n")
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()), ["input", "output"])


if __name__ == "__main__":
    unittest.main()
