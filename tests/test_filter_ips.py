"""Run with: python3 -m unittest discover -s tests -v"""
import contextlib
import csv
import hashlib
import importlib.util
import io
import os
from collections import Counter
from decimal import Decimal
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("filter_ips", ROOT / "scripts" / "filter_ips.py")
f = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = f
spec.loader.exec_module(f)


class PrimitiveTests(unittest.TestCase):
    def test_latency_units_and_format(self):
        for text, expected in (("12MS", "12"), (".012 S", "12"), ("12000Us", "12"),
                               ("12000µs", "12"), ("12000μs", "12"), ("0", "0"),
                               ("1e2 ms", "100"), ("12.500ms", "12.5"),
                               ("0.5微秒", "0.0005"), (".12秒", "120")):
            with self.subTest(text=text):
                self.assertEqual(f.format_latency(f.parse_latency(text)), expected)
        self.assertEqual(f.parse_latency(".5", default_unit="s"), Decimal(500))

    def test_invalid_latency(self):
        for text in ("", "NaN", "inf", "Infinityms", "-1ms", "12%", "12MB/s", "12Mbps", "12junk", "1 2ms", "--1", "1e10000ms"):
            with self.subTest(text=text):
                self.assertIsNone(f.parse_latency(text))
        self.assertIsNone(f.parse_latency("12", allow_bare=False))

    def test_endpoint_validation_and_canonical_ipv6(self):
        self.assertEqual(f.parse_endpoint("[2606:4700:4700:0:0:0:0:1111]:443#HK-12ms"),
                         ("[2606:4700:4700::1111]:443", "HK-12ms"))
        self.assertEqual(f.parse_endpoint("8.8.8.8", "0053"), ("8.8.8.8:53", ""))
        self.assertEqual(f.parse_endpoint("2606:4700:4700::1111", "443"), ("[2606:4700:4700::1111]:443", ""))
        for text in ("8.8.8.8", "8.8.8.8:0", "8.8.8.8:65536", "8.8.8.8:1.5", "8.8.8.8:+443",
                     "999.8.8.8:443", "010.0.0.1:443", "localhost:443", "https://8.8.8.8:443",
                     "2606:4700:4700::1111:443", "[fe80::1%eth0]:443", "[::1]:443",
                     "192.168.1.1:443", "10.0.0.1:443", "127.0.0.1:443", "0.0.0.0:443",
                     "224.0.0.1:443", "169.254.1.1:443", "100.64.0.1:443", "[fd00::1]:443"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                f.parse_endpoint(text)

    def test_regions(self):
        for text, expected in (("hk", "HK"), ("中国香港", "HK"), ("Taiwan", "TW"),
                               ("臺灣", "TW"), ("日本", "JP"), ("United States", "US"),
                               ("South Korea", "KR"), ("新加坡", "SG"), ("德国", "DE"),
                               ("HKG", "HK"), ("NRT", "JP"), ("HKG-HK", "HK"),
                               ("HK-12ms", "HK"), ("LAX-US", "US")):
            with self.subTest(text=text):
                self.assertEqual(f.parse_region(text), expected)
        for text in ("", "GB", "LHR", "CHINA", "HK-JP", "this-is-not-HongKong-location"):
            self.assertIsNone(f.parse_region(text))


class FilterTests(unittest.TestCase):
    def run_filter(self, text, **kwargs):
        return f.filter_text(text, **kwargs)

    def test_fixture(self):
        raw = (ROOT / "raw/results.csv").read_bytes()
        # This file is also the user's mutable upload destination. Pin the
        # historical 3716-row regression by content, not just by filename, so a
        # legitimate new upload does not break CI's otherwise format-agnostic tests.
        if hashlib.sha256(raw).hexdigest() != "1c5ff9448c5faaf90ed5935615557d0be361a6445ba85ccf47651d4aecc92a39":
            self.skipTest("original 3716-row repository fixture has been replaced by a new upload")
        text = raw.decode("utf-8-sig")
        results, stats = self.run_filter(text)
        self.assertEqual(len(text.splitlines()), 3717)
        self.assertEqual(stats["rows"], 3716)
        self.assertEqual(len(results), 67)
        self.assertEqual(Counter(r.region for r in results), {"HK": 10, "TW": 7, "JP": 10, "US": 10, "KR": 10, "SG": 10, "DE": 10})
        original = list(csv.DictReader(io.StringIO(text)))
        source = {(row["IP:PORT"], row["源IP位置"], f.parse_latency(row["网络延迟"])) for row in original}
        for result in results:
            self.assertIn((result.endpoint, result.region, result.latency), source)
        reference = (ROOT / "api/preferred.txt").read_text().splitlines()
        # Equal-latency endpoint tie order is deliberately canonical, not input order.
        def fields(line):
            endpoint, annotation = line.split("#")
            region, delay = annotation.split("-")
            return region, f.parse_latency(delay)
        self.assertEqual(Counter((r.region, r.latency) for r in results), Counter(fields(line) for line in reference))
        self.assertEqual(stats["mapping"]["region"]["name"], "源IP位置")
        self.assertEqual(stats["mapping"]["latency"]["name"], "网络延迟")
        for region in f.REGIONS:
            group = [r for r in results if r.region == region]
            self.assertEqual(group, sorted(group, key=lambda r: (r.latency, r.endpoint)))

    def test_bom_crlf_quotes_all_delimiters(self):
        for delimiter in (",", ";", "\t"):
            buffer = io.StringIO(newline="")
            writer = csv.writer(buffer, delimiter=delimiter, lineterminator="\r\n", quoting=csv.QUOTE_ALL)
            writer.writerow(["备注", "网络延迟", "源IP位置", "IP:PORT"])
            writer.writerow(["contains, comma; semicolon\ttab\nnewline", "1.25MS", "HK", "8.8.8.8:443"])
            results, stats = self.run_filter("\ufeff" + buffer.getvalue())
            self.assertEqual(results[0].line(), "8.8.8.8:443#HK-1.25ms")
            self.assertEqual(stats["rows"], 1)

    def test_headerless_reordered_unit_columns(self):
        results, stats = self.run_filter("12ms;JP;8.8.8.8:443\n.01s;HK;1.1.1.1:8443\n")
        self.assertEqual([r.line() for r in results], ["1.1.1.1:8443#HK-10ms", "8.8.8.8:443#JP-12ms"])
        self.assertEqual(stats["mapping"]["latency"]["column"], 1)
        self.assertEqual(stats["mapping"]["endpoint"]["column"], 3)

    def test_headerless_bare_single_candidate(self):
        results, _ = self.run_filter("HK,12.5,8.8.8.8:443\nJP,0,1.1.1.1:443\n")
        self.assertEqual([r.latency for r in results], [Decimal("12.5"), Decimal(0)])

    def test_ambiguous_bare_numeric_fails_and_override(self):
        text = "8.8.8.8:443,HK,10,100\n1.1.1.1:443,JP,11,200\n"
        with self.assertRaisesRegex(f.FilterError, "ambiguous latency"):
            self.run_filter(text)
        results, stats = self.run_filter(text, overrides={"latency": "3"})
        self.assertEqual(results[0].latency, Decimal(10))
        self.assertEqual(stats["mapping"]["latency"]["column"], 3)

    def test_named_latency_precedes_other_units_and_numbers(self):
        results, stats = self.run_filter("IP:PORT,region,speed,port,loss,latency,ping2\n8.8.8.8:443,HK,100,443,50%,12,1ms\n")
        self.assertEqual(results[0].latency, Decimal(12))
        self.assertEqual(stats["mapping"]["latency"]["column"], 6)

    def test_speed_percentage_and_redundant_port_not_guessed(self):
        for other in ("443", "10MB/s", "95%"):
            with self.subTest(other=other), self.assertRaisesRegex(f.FilterError, "no publishable"):
                self.run_filter(f"8.8.8.8:443,HK,{other}\n")
        with self.assertRaisesRegex(f.FilterError, "no publishable"):
            self.run_filter("IP:PORT,region,speed,loss,port\n8.8.8.8:443,HK,900,0,443\n")

    def test_headerless_unit_beats_bare_speed(self):
        results, _ = self.run_filter("8.8.8.8:443,HK,100,12ms\n")
        self.assertEqual(results[0].latency, Decimal(12))

    def test_multiple_unit_columns_ambiguous(self):
        with self.assertRaisesRegex(f.FilterError, "ambiguous latency"):
            self.run_filter("8.8.8.8:443,HK,10ms,11ms\n")

    def test_separate_ip_port_headers_and_ipv6(self):
        results, _ = self.run_filter("地区,端口,网络延迟,IP\n香港,443,12ms,8.8.8.8\n日本,8443,13ms,2606:4700:4700::1111\n")
        self.assertEqual([r.endpoint for r in results], ["8.8.8.8:443", "[2606:4700:4700::1111]:8443"])

    def test_separate_headerless_ip_port(self):
        results, _ = self.run_filter("HK,443,8.8.8.8,12ms\n")
        self.assertEqual(results[0].line(), "8.8.8.8:443#HK-12ms")

    def test_separate_headerless_bare_numbers_require_override(self):
        text = "8.8.8.8,443,HK,12\n"
        with self.assertRaisesRegex(f.FilterError, "ambiguous latency"):
            self.run_filter(text)
        for overrides in ({"port": "2"}, {"latency": "4"}):
            results, _ = self.run_filter(text, overrides=overrides)
            self.assertEqual(results[0].line(), "8.8.8.8:443#HK-12ms")

    def test_missing_port_not_defaulted(self):
        with self.assertRaisesRegex(f.FilterError, "port"):
            self.run_filter("IP,region,latency\n8.8.8.8,HK,12ms\n")

    def test_annotation_region_latency(self):
        results, _ = self.run_filter("8.8.8.8:443#HK-12ms\n[2606:4700:4700::1111]:8443#JP-10MS\n")
        self.assertEqual([r.line() for r in results], ["8.8.8.8:443#HK-12ms", "[2606:4700:4700::1111]:8443#JP-10ms"])
        results, _ = self.run_filter("8.8.8.8:443#HKG-HK,12ms\n")
        self.assertEqual(results[0].region, "HK")

    def test_annotation_units_beat_bare_speed_and_colos(self):
        results, stats = self.run_filter("8.8.8.8:443#HK-12ms,NRT,100\n")
        self.assertEqual(results[0].line(), "8.8.8.8:443#HK-12ms")
        self.assertEqual(stats["mapping"]["latency"], "embedded")
        self.assertEqual(stats["mapping"]["region"], "embedded")

    def test_ip_header_with_combined_endpoint_and_redundant_port(self):
        results, _ = self.run_filter("IP,region,latency\n8.8.8.8:443,HK,12ms\n")
        self.assertEqual(results[0].endpoint, "8.8.8.8:443")
        results, stats = self.run_filter("IP:PORT,port,region,latency\n8.8.8.8:443,443,HK,12ms\n1.1.1.1:443,8443,JP,1ms\n")
        self.assertEqual([r.endpoint for r in results], ["8.8.8.8:443"])
        self.assertEqual(stats["dropped"]["port_conflict"], 1)

    def test_negative_annotation_never_becomes_positive(self):
        for label in ("HK--5ms", "HK- -5ms", "HK---5ms", "HKG-HK--5ms", "HK--.5s"):
            with self.subTest(label=label):
                self.assertIsNone(f.annotation_latency(label))
                with self.assertRaises(f.FilterError):
                    self.run_filter("8.8.8.8:443#" + label + "\n")
        self.assertEqual(f.annotation_latency("HK-1e-3ms"), Decimal(".001"))
        results, _ = self.run_filter("8.8.8.8:443#HK-1e-3ms\n")
        self.assertEqual(results[0].line(), "8.8.8.8:443#HK-0.001ms")

    def test_bare_separate_columns_ambiguous_in_any_order(self):
        from itertools import permutations
        for fields in permutations(("8.8.8.8", "443", "HK", "12")):
            with self.subTest(fields=fields), self.assertRaises(f.FilterError):
                self.run_filter(",".join(fields) + "\n")

    def test_header_seconds_unit_explicit_value_unit_wins(self):
        results, stats = self.run_filter("IP:PORT,region,latency(s)\n8.8.8.8:443,HK,.012\n1.1.1.1:443,JP,15MS\n")
        self.assertEqual([r.latency for r in results], [Decimal(12), Decimal(15)])
        self.assertEqual(stats["mapping"]["latency_unit"], "s")

    def test_rare_cross_type_dirt_does_not_poison_mapping(self):
        rows = [f"8.8.8.{i}:443,HK,{10 + i}ms,note" for i in range(1, 11)]
        rows[0] = "8.8.8.1:443,HK,1.1.1.1:8443,JP"
        results, stats = self.run_filter("\n".join(rows))
        self.assertEqual(len(results), 9)
        self.assertEqual(stats["mapping"]["endpoint"]["column"], 1)
        self.assertEqual(stats["mapping"]["region"]["column"], 2)
        self.assertEqual(stats["mapping"]["latency"]["column"], 3)
        self.assertEqual(stats["dropped"]["invalid_or_missing_latency"], 1)

    def test_stray_unit_token_must_not_select_wrong_bare_column(self):
        rows = [f"8.8.8.{i}:443,HK,{10 + i},{100 + i}" for i in range(1, 11)]
        rows[0] = "8.8.8.1:443,HK,11,1ms"
        with self.assertRaisesRegex(f.FilterError, "ambiguous latency"):
            self.run_filter("\n".join(rows))
        results, _ = self.run_filter("\n".join(rows), overrides={"latency": "3"})
        self.assertEqual(results[0].latency, Decimal(11))

    def test_mixed_bare_and_units_still_works_when_unambiguous(self):
        rows = [f"8.8.8.{i}:443,HK,{10 + i}" for i in range(1, 11)]
        rows[0] += "ms"
        results, _ = self.run_filter("\n".join(rows))
        self.assertEqual(len(results), 10)

    def test_source_region_precedes_colo_and_unknown_not_fallback(self):
        text = "IP:PORT,colo,源IP位置,region,latency\n8.8.8.8:443,NRT,HK,US,12ms\n1.1.1.1:443,HKG,GB,HK,13ms\n"
        results, stats = self.run_filter(text)
        self.assertEqual([r.region for r in results], ["HK"])
        self.assertEqual(stats["dropped"]["unknown_region"], 1)
        self.assertEqual(stats["mapping"]["region_kind"], "source_region")
        results, _ = self.run_filter(text, overrides={"region": "colo"})
        self.assertEqual([r.region for r in results], ["HK", "JP"])

    def test_colo_only_and_headerless_country_preference(self):
        results, _ = self.run_filter("IP:PORT,colo,latency\n8.8.8.8:443,NRT,12ms\n")
        self.assertEqual(results[0].region, "JP")
        results, _ = self.run_filter("8.8.8.8:443,NRT,HK,12ms\n")
        self.assertEqual(results[0].region, "HK")

    def test_header_unit(self):
        for header, number in (("latency(s)", ".012"), ("延迟（微秒）", "12000")):
            results, _ = self.run_filter(f"IP:PORT,region,{header}\n8.8.8.8:443,HK,{number}\n")
            self.assertEqual(results[0].latency, Decimal(12))

    def test_missing_latency_is_not_99999_or_annotation_fallback(self):
        results, stats = self.run_filter("IP:PORT,region,latency\n8.8.8.8:443#HK-1ms,HK,\n1.1.1.1:443,HK,12ms\n")
        self.assertEqual([r.endpoint for r in results], ["1.1.1.1:443"])
        self.assertEqual(stats["dropped"]["invalid_or_missing_latency"], 1)

    def test_invalid_rows_are_counted(self):
        text = "IP:PORT,region,latency\n8.8.8.8:443,HK,1ms\n8.8.4.4:443,GB,2ms\n1.1.1.1:0,JP,3ms\n10.0.0.1:443,HK,1ms\n9.9.9.9:443,JP,NaN\n1.0.0.1:443,HK\n"
        results, stats = self.run_filter(text)
        self.assertEqual(len(results), 1)
        self.assertEqual(stats["rows"], 6)
        for reason in ("unknown_region", "invalid_port", "non_public_ip", "invalid_or_missing_latency", "short_row"):
            self.assertEqual(stats["dropped"][reason], 1)

    def test_duplicates_and_conflicts_order_independent(self):
        rows = ["8.8.8.8:443,HK,12ms", "8.8.8.8:443,HK,10ms",
                "1.1.1.1:443,HK,9ms", "1.1.1.1:443,JP,1ms", "1.1.1.1:443,HK,0ms"]
        for order in (rows, rows[::-1]):
            results, stats = self.run_filter("IP:PORT,region,latency\n" + "\n".join(order))
            self.assertEqual([r.line() for r in results], ["8.8.8.8:443#HK-10ms"])
            self.assertEqual(stats["dropped"]["duplicate_endpoint"], 3)
            self.assertEqual(stats["dropped"]["region_conflict_endpoints"], 1)

    def test_stable_ties_and_limits(self):
        rows = [f"8.8.8.{i}:443,HK,10ms" for i in range(20, 0, -1)]
        text = "IP:PORT,region,latency\n" + "\n".join(rows)
        a, _ = self.run_filter(text)
        b, _ = self.run_filter("IP:PORT,region,latency\n" + "\n".join(rows[::-1]))
        self.assertEqual(a, b)
        self.assertEqual(len(a), 10)
        self.assertEqual(len(self.run_filter(text, per_region=3)[0]), 3)
        for limit in (0, -1, 11):
            with self.assertRaises(f.FilterError):
                self.run_filter(text, per_region=limit)

    def test_all_regions_order_and_output_roundtrip(self):
        text = "IP:PORT,region,latency\n" + "\n".join(f"8.8.8.{i + 1}:443,{r},0.012s" for i, r in enumerate(reversed(f.REGIONS)))
        results, _ = self.run_filter(text)
        self.assertEqual(tuple(r.region for r in results), f.REGIONS)
        roundtrip, _ = self.run_filter("\n".join(r.line() for r in results))
        self.assertEqual(results, roundtrip)

    def test_empty_and_no_results(self):
        for text in ("", "\ufeff\r\n", "IP:PORT,region,latency\n", "IP:PORT,region,latency\n8.8.8.8:443,GB,12ms\n"):
            with self.subTest(text=text), self.assertRaises(f.FilterError):
                self.run_filter(text)

    def test_overrides_exact_name_and_bad_values(self):
        text = "IP:PORT,region,timer,throughput\n8.8.8.8:443,HK,12,100\n"
        results, _ = self.run_filter(text, overrides={"latency": "timer"})
        self.assertEqual(results[0].latency, Decimal(12))
        for value in ("0", "99", "missing"):
            with self.assertRaisesRegex(f.FilterError, "override"):
                self.run_filter(text, overrides={"latency": value})
        with self.assertRaisesRegex(f.FilterError, "overlap"):
            self.run_filter(text, overrides={"latency": "2"})

    def test_ambiguous_endpoint_and_region(self):
        for text, role in (("8.8.8.8:443,1.1.1.1:443,HK,12ms\n", "endpoint"),
                           ("8.8.8.8:443,HK,JP,12ms\n", "region")):
            with self.assertRaisesRegex(f.FilterError, "ambiguous " + role):
                self.run_filter(text)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.input = Path(self.temp.name) / "input.csv"
        self.output = Path(self.temp.name) / "api" / "preferred.txt"
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()

    def call(self, extra=()):
        with contextlib.redirect_stdout(self.stdout), contextlib.redirect_stderr(self.stderr):
            return f.main(["--input", str(self.input), "--output", str(self.output), *extra])

    def test_cli_success_and_stats(self):
        self.input.write_text("IP:PORT,region,latency\n8.8.8.8:443,HK,12ms\n")
        self.assertEqual(self.call(), 0)
        self.assertEqual(self.output.read_bytes(), b"8.8.8.8:443#HK-12ms\n")
        self.assertIn('"selected": 1', self.stdout.getvalue())
        self.assertIn('"mapping"', self.stdout.getvalue())
        self.assertEqual(self.stderr.getvalue(), "")

    def test_failure_preserves_existing_output(self):
        self.output.parent.mkdir()
        for text in ("", "IP:PORT,region,latency\n8.8.8.8:443,HK,NaN\n", "8.8.8.8:443,HK,10,20\n"):
            self.output.write_bytes(b"previous bytes\r\n")
            self.input.write_text(text)
            self.assertNotEqual(self.call(), 0)
            self.assertEqual(self.output.read_bytes(), b"previous bytes\r\n")
        self.assertIn("ambiguous latency", self.stderr.getvalue())

    def test_cli_override(self):
        self.input.write_text("8.8.8.8:443,HK,10,20\n")
        self.assertEqual(self.call(["--latency-column", "3", "--per-region", "1"]), 0)
        self.assertEqual(self.output.read_text(), "8.8.8.8:443#HK-10ms\n")

    def test_missing_or_bad_encoding(self):
        self.assertEqual(self.call(), 1)
        self.input.write_bytes(b"\xff\xfe")
        self.assertEqual(self.call(), 1)
        self.assertFalse(self.output.exists())

    def test_reject_same_input_output(self):
        text = "8.8.8.8:443#HK-12ms\n"
        self.input.write_text(text)
        with contextlib.redirect_stderr(self.stderr):
            self.assertEqual(f.main(["--input", str(self.input), "--output", str(self.input)]), 1)
        self.assertEqual(self.input.read_text(), text)

    def test_atomic_replace_and_cleanup_on_failure(self):
        self.output.parent.mkdir()
        self.output.write_text("original\n")
        results = [f.Result("8.8.8.8:443", "HK", Decimal(12))]
        real_replace = os.replace
        observed = []

        def replace(source, destination):
            observed.append((Path(source), Path(destination)))
            self.assertEqual(self.output.read_text(), "original\n")
            self.assertEqual(Path(source).parent, self.output.parent)
            self.assertEqual(Path(source).read_text(), "8.8.8.8:443#HK-12ms\n")
            return real_replace(source, destination)

        with patch.object(f.os, "replace", side_effect=replace):
            f.atomic_write(self.output, results)
        self.assertEqual(len(observed), 1)
        self.assertEqual(self.output.read_text(), "8.8.8.8:443#HK-12ms\n")
        self.output.write_text("original\n")
        with patch.object(f.os, "replace", side_effect=OSError("simulated")):
            with self.assertRaises(OSError):
                f.atomic_write(self.output, results)
        self.assertEqual(self.output.read_text(), "original\n")
        self.assertEqual(list(self.output.parent.glob("*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
