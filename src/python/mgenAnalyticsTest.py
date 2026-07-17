#!/usr/bin/env python3
#
# mgenAnalyticsTest.py - end-to-end tests for the MGEN analytics features added
# on the analytics-tx-reports and tx-wire-rate branches:
#
#   * RX analytics  (analytics    -> REPORT log lines)
#   * TX analytics  (txAnalytics  -> TXREPORT log lines)
#   * quantizeWindow {on|off}     (analytics window-size quantization)
#   * txWireRate {on|off}         (TCP wire-rate accounting via SIOCOUTQ)
#   * timer-driven, whole-second-aligned reporting with no drift
#
# Unlike the older src/python scripts (Python 2, protokit control pipe,
# trpr/gnuplot plotting) this is a self-contained Python 3 harness: it launches
# a receiver and a sender `mgen` process on loopback with everything specified
# on the command line, then PARSES the text logs and ASSERTS on the results.
# No protokit/trpr/gnuplot/X dependencies - suitable for headless CI.
#
# Usage:
#   python3 mgenAnalyticsTest.py [--mgen /path/to/mgen] [--duration SECS]
#                                [--keep] [--verbose]
#   (defaults: --mgen ../../makefiles/mgen, --duration 7)
#
# Exit code 0 = all scenarios passed, non-zero = at least one failure.

from __future__ import print_function
import argparse
import math
import os
import shutil
import subprocess
import sys
import tempfile
import time

# --------------------------------------------------------------------------- #
# Log parsing
# --------------------------------------------------------------------------- #

class Report(object):
    """A parsed REPORT (rx) or TXREPORT (tx) log line."""
    def __init__(self, kind, ts, fields):
        self.kind    = kind                       # "REPORT" or "TXREPORT"
        self.ts      = ts                         # leading timestamp (float, epoch)
        self.proto   = fields.get("proto")
        self.flow    = int(fields.get("flow", "0"))
        self.window  = _to_float(fields.get("window"))
        self.rate    = _to_float(fields.get("rate"))    # kbps
        self.count   = int(fields.get("count", "0"))
        self.loss    = _to_float(fields.get("loss"))    # REPORT only
        self.lat_ave = _to_float(fields.get("ave"))     # REPORT only
        self.lat_min = _to_float(fields.get("min"))     # REPORT only
        self.lat_max = _to_float(fields.get("max"))     # REPORT only

    @property
    def bytes_est(self):
        # rate is kbps (bytes/sec * 8 / 1000) over a "window"-second interval
        if self.rate is None or self.window is None:
            return 0.0
        return self.rate * 1000.0 / 8.0 * self.window


def _to_float(s):
    if s is None:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def parse_reports(log_text):
    """Return list of Report objects (REPORT and TXREPORT lines) from a log."""
    reports = []
    for line in log_text.splitlines():
        toks = line.split()
        if len(toks) < 2:
            continue
        kind = toks[1]
        if kind not in ("REPORT", "TXREPORT"):
            continue
        ts = _to_float(toks[0])
        if ts is None:
            continue
        # The remote/in-band REPORT variant carries reporter>/offset> fields and
        # no count>; skip it (only the local analytics REPORT is under test).
        if kind == "REPORT" and ("offset>" in line or "reporter>" in line):
            continue
        fields = {}
        for t in toks[2:]:
            if ">" in t:
                k, v = t.split(">", 1)
                fields[k] = v.rstrip(",")
        reports.append(Report(kind, ts, fields))
    return reports


def by_flow(reports, kind):
    """{flow_id: [Report, ...]} for the given kind, preserving order."""
    out = {}
    for r in reports:
        if r.kind == kind:
            out.setdefault(r.flow, []).append(r)
    return out


# --------------------------------------------------------------------------- #
# Assertion helper
# --------------------------------------------------------------------------- #

class Checker(object):
    def __init__(self):
        self.checks = 0
        self.failures = 0
        self._scenario = ""

    def scenario(self, name):
        self._scenario = name
        print("\n=== %s ===" % name)

    def check(self, cond, msg):
        self.checks += 1
        if cond:
            print("  ok   : %s" % msg)
        else:
            self.failures += 1
            print("  FAIL : %s" % msg)

    def near(self, actual, expected, tol, msg):
        ok = (actual is not None) and (abs(actual - expected) <= tol)
        got = "None" if actual is None else ("%.6f" % actual)
        self.check(ok, "%s (got %s, want %.6f +/- %.6f)" % (msg, got, expected, tol))

    def between(self, actual, lo, hi, msg):
        ok = (actual is not None) and (lo <= actual <= hi)
        got = "None" if actual is None else ("%.6f" % actual)
        self.check(ok, "%s (got %s, want [%.4f, %.4f])" % (msg, got, lo, hi))

    def ge(self, actual, threshold, msg):
        ok = (actual is not None) and (actual >= threshold)
        self.check(ok, "%s (got %s, want >= %s)" % (msg, actual, threshold))


# --------------------------------------------------------------------------- #
# mgen process orchestration
# --------------------------------------------------------------------------- #

class MgenRunner(object):
    def __init__(self, binary, workdir, verbose=False):
        self.binary = binary
        self.workdir = workdir
        self.verbose = verbose

    def run_pair(self, recv_args, send_args, duration, stop_flows=(),
                 startup=1.0, settle=2.5, tag="run"):
        """Launch a receiver then a sender mgen on loopback.  Each flow in
        `stop_flows` is turned OFF at t=`duration` (sender script time) so its
        final analytics window is finalized/flushed cleanly; both processes are
        then given `settle` seconds to emit their last reports before shutdown.
        Returns (recv_log_text, send_log_text)."""
        recv_log = os.path.join(self.workdir, "%s-recv.log" % tag)
        send_log = os.path.join(self.workdir, "%s-send.log" % tag)
        for p in (recv_log, send_log):
            if os.path.exists(p):
                os.remove(p)

        off_events = []
        for fid in stop_flows:
            off_events += ["event", "%.1f OFF %d" % (duration, fid)]

        base = [self.binary, "flush", "epochtimestamp"]
        recv_cmd = base + ["output", recv_log] + recv_args
        send_cmd = base + ["output", send_log] + send_args + off_events
        if self.verbose:
            print("  recv: %s" % " ".join(recv_cmd))
            print("  send: %s" % " ".join(send_cmd))

        recv_proc = subprocess.Popen(recv_cmd, cwd=self.workdir,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        try:
            time.sleep(startup)                     # let LISTEN sockets come up
            send_proc = subprocess.Popen(send_cmd, cwd=self.workdir,
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
            try:
                # flow runs `duration`s, then OFF fires; settle lets both sides
                # finalize and flush the final window(s)
                time.sleep(duration + settle)
            finally:
                _stop(send_proc)
            time.sleep(0.5)
        finally:
            _stop(recv_proc)

        return _read(recv_log), _read(send_log)


def _stop(proc):
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def _read(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except IOError:
        return ""


# --------------------------------------------------------------------------- #
# Shared assertions
# --------------------------------------------------------------------------- #

def assert_cadence(chk, reports, window, label, min_reports=3):
    """Reports must land on whole-`window` boundaries with a steady cadence and
    no gaps (consecutive timestamps differ by exactly `window`)."""
    chk.ge(len(reports), min_reports, "%s: produced at least %d reports" % (label, min_reports))
    if len(reports) < 2:
        return
    # Whole-`window` alignment: (ts / window) is (near) integer for every report.
    max_off = 0.0
    for r in reports:
        frac = r.ts / window
        off = abs(frac - round(frac)) * window
        max_off = max(max_off, off)
    chk.check(max_off < 0.10,
              "%s: all report timestamps aligned to %.4fs boundary (max offset %.4fs)"
              % (label, window, max_off))
    # Steady cadence, no gaps: every consecutive delta == window.
    deltas = [reports[i + 1].ts - reports[i].ts for i in range(len(reports) - 1)]
    worst = max(abs(d - window) for d in deltas)
    chk.check(worst < 0.10,
              "%s: consecutive reports exactly %.4fs apart, no gaps (worst delta err %.4fs)"
              % (label, window, worst))


def nonempty(reports):
    """Windows that actually carried messages (count > 0).

    Per-window counts are unreliable on loopback/VMs because the receiver reads
    datagrams in bursts (a whole second's traffic can land in one window, the
    next window empty).  Aggregate totals are the reliable signal; loss/latency
    are only meaningful on windows that carried messages."""
    return [r for r in reports if r.count > 0]


def total_count(reports):
    return sum(r.count for r in reports)


def total_bytes(reports):
    return sum(r.bytes_est for r in reports)


def assert_throughput(chk, tx, rx, rate_pps, size, duration, label):
    """Aggregate throughput checks: the sender achieved ~the offered rate, and
    (loopback) the receiver got ~everything the sender reported sending."""
    tx_n = total_count(tx)
    rx_n = total_count(rx)
    expected = rate_pps * duration
    chk.between(tx_n, expected * 0.7, expected * 1.2,
                "%s: TX total count %d ~= offered rate*duration (%d)"
                % (label, tx_n, int(expected)))
    if tx_n:
        chk.between(rx_n, tx_n * 0.85, tx_n * 1.15,
                    "%s: RX total count %d ~= TX total count %d (delivery)"
                    % (label, rx_n, tx_n))


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #

def scenario_udp_analytics(chk, mgen, duration):
    """TX + RX analytics on a UDP loopback flow (quantizeWindow off).  Verifies
    REPORT and TXREPORT are generated on an exact 1s whole-second interval with
    no gaps, window is 1.0, throughput matches the offered load, loss is zero,
    and latency is ordered/plausible."""
    chk.scenario("UDP: tx + rx analytics, 1s cadence, throughput/loss/latency")
    port = 5000
    rate_pps, size = 100, 1024
    recv, send = mgen.run_pair(
        recv_args=["analytics", "quantizeWindow", "off",
                   "event", "LISTEN UDP %d" % port],
        send_args=["txAnalytics", "quantizeWindow", "off",
                   "event", "ON 1 UDP DST 127.0.0.1/%d PERIODIC [%d %d]"
                   % (port, rate_pps, size)],
        duration=duration, stop_flows=[1], tag="udp")

    rx = by_flow(parse_reports(recv), "REPORT").get(1, [])
    tx = by_flow(parse_reports(send), "TXREPORT").get(1, [])

    # Core feature: both report streams on an exact 1s whole-second grid, no gaps
    assert_cadence(chk, rx, 1.0, "RX REPORT")
    assert_cadence(chk, tx, 1.0, "TX TXREPORT")

    # window field is exactly 1.000000 with quantizeWindow off (no window cmd)
    if rx:
        chk.near(rx[0].window, 1.0, 1e-6, "RX window == 1.000000 (quantize off)")
    if tx:
        chk.near(tx[0].window, 1.0, 1e-6, "TX window == 1.000000 (quantize off)")

    # Aggregate throughput matches the offered load; delivery is lossless
    assert_throughput(chk, tx, rx, rate_pps, size, duration, "UDP")

    # Loss zero and latency ordered/plausible on windows that carried messages
    for r in nonempty(rx):
        chk.near(r.loss, 0.0, 1e-9, "RX loss == 0 on clean loopback")
    chk.ge(len(nonempty(rx)), 1, "RX had non-empty windows to latency-check")
    for r in nonempty(rx):
        chk.check(r.lat_min <= r.lat_ave <= r.lat_max,
                  "RX latency min<=ave<=max (%.6f<=%.6f<=%.6f)"
                  % (r.lat_min, r.lat_ave, r.lat_max))
        chk.between(r.lat_ave, 0.0, 0.5, "RX latency ave plausible (< 0.5s)")


def scenario_quantize_window(chk, mgen, duration):
    """quantizeWindow flag: off -> window 1.000000, on -> quantized 1.011211."""
    chk.scenario("quantizeWindow flag: on vs off window-size")
    port = 5010
    rate_pps, size = 50, 512
    dur = min(duration, 4.0)  # only the window-size field matters here
    ev_send = "event", "ON 1 UDP DST 127.0.0.1/%d PERIODIC [%d %d]" % (port, rate_pps, size)
    ev_recv = "event", "LISTEN UDP %d" % port

    # OFF -> raw 1.0
    recv_off, send_off = mgen.run_pair(
        recv_args=["analytics", "quantizeWindow", "off", ev_recv[0], ev_recv[1]],
        send_args=["txAnalytics", "quantizeWindow", "off", ev_send[0], ev_send[1]],
        duration=dur, stop_flows=[1], tag="qoff")
    rx_off = by_flow(parse_reports(recv_off), "REPORT").get(1, [])
    tx_off = by_flow(parse_reports(send_off), "TXREPORT").get(1, [])
    chk.ge(len(rx_off), 1, "quantize off: got RX reports")
    if rx_off:
        chk.near(rx_off[0].window, 1.0, 1e-6, "quantize OFF: RX window == 1.000000")
    if tx_off:
        chk.near(tx_off[0].window, 1.0, 1e-6, "quantize OFF: TX window == 1.000000")

    # ON -> quantized value for a 1.0s window is 1.011211
    recv_on, send_on = mgen.run_pair(
        recv_args=["analytics", "quantizeWindow", "on", ev_recv[0], ev_recv[1]],
        send_args=["txAnalytics", "quantizeWindow", "on", ev_send[0], ev_send[1]],
        duration=dur, stop_flows=[1], tag="qon")
    rx_on = by_flow(parse_reports(recv_on), "REPORT").get(1, [])
    tx_on = by_flow(parse_reports(send_on), "TXREPORT").get(1, [])
    chk.ge(len(rx_on), 1, "quantize on: got RX reports")
    if rx_on:
        chk.near(rx_on[0].window, 1.011211, 1e-4, "quantize ON: RX window == 1.011211")
    if tx_on:
        chk.near(tx_on[0].window, 1.011211, 1e-4, "quantize ON: TX window == 1.011211")


def scenario_tx_wire_rate(chk, mgen, duration):
    """txWireRate on a TCP loopback flow.  With wire-rate ON the reported TX
    bytes must accurately track what the receiver actually got (and the nominal
    offered load).  Also confirm cadence and that OFF (offered-load) still works."""
    chk.scenario("txWireRate: TCP wire-rate accuracy vs offered-load")
    port = 5020
    rate_pps, size = 100, 1024
    nominal_bytes = None  # derived from TX count below
    ev_recv = ("event", "LISTEN TCP %d" % port)
    ev_send = ("event", "ON 1 TCP DST 127.0.0.1/%d PERIODIC [%d %d]" % (port, rate_pps, size))

    for wire in ("on", "off"):
        recv, send = mgen.run_pair(
            recv_args=["analytics", "quantizeWindow", "off", ev_recv[0], ev_recv[1]],
            send_args=["txAnalytics", "txWireRate", wire, "quantizeWindow", "off",
                       ev_send[0], ev_send[1]],
            duration=duration, stop_flows=[1], tag="tcp-%s" % wire)
        rx = by_flow(parse_reports(recv), "REPORT").get(1, [])
        tx = by_flow(parse_reports(send), "TXREPORT").get(1, [])

        assert_cadence(chk, rx, 1.0, "TCP RX REPORT (wire %s)" % wire)
        assert_cadence(chk, tx, 1.0, "TCP TX TXREPORT (wire %s)" % wire)

        tx_count = total_count(tx)
        rx_count = total_count(rx)
        tx_bytes = total_bytes(tx)
        rx_bytes = total_bytes(rx)
        chk.ge(tx_count, 1, "TCP wire %s: TX produced messages" % wire)

        # All sent TCP data is received (reliable transport) -> counts converge
        if tx_count:
            chk.between(rx_count, tx_count * 0.85, tx_count * 1.15,
                        "TCP wire %s: RX count (%d) ~= TX count (%d)"
                        % (wire, rx_count, tx_count))
        # The key wire-rate claim: reported TX bytes accurately track the bytes
        # the receiver actually got, and the nominal offered load.
        nominal = tx_count * size
        if tx_count:
            chk.between(tx_bytes, nominal * 0.80, nominal * 1.20,
                        "TCP wire %s: TX reported bytes (%d) ~= nominal (%d)"
                        % (wire, int(tx_bytes), int(nominal)))
            chk.between(rx_bytes, tx_bytes * 0.80, tx_bytes * 1.20,
                        "TCP wire %s: RX bytes (%d) ~= TX reported bytes (%d)"
                        % (wire, int(rx_bytes), int(tx_bytes)))


def scenario_all_combined(chk, mgen, duration):
    """All features on together, with a UDP flow and a TCP flow in the SAME run,
    to confirm the settings coexist: analytics + txAnalytics + txWireRate on +
    quantizeWindow off, both flows reported on a steady 1s whole-second grid."""
    chk.scenario("Combined: UDP(flow1) + TCP(flow2), all analytics features on")
    uport, tport = 5030, 5031
    rate_pps, size = 100, 1024
    recv, send = mgen.run_pair(
        recv_args=["analytics", "quantizeWindow", "off",
                   "event", "LISTEN UDP %d" % uport,
                   "event", "LISTEN TCP %d" % tport],
        send_args=["txAnalytics", "txWireRate", "on", "quantizeWindow", "off",
                   "event", "ON 1 UDP DST 127.0.0.1/%d PERIODIC [%d %d]" % (uport, rate_pps, size),
                   "event", "ON 2 TCP DST 127.0.0.1/%d PERIODIC [%d %d]" % (tport, rate_pps, size)],
        duration=duration, stop_flows=[1, 2], tag="combined")

    rx = by_flow(parse_reports(recv), "REPORT")
    tx = by_flow(parse_reports(send), "TXREPORT")

    for flow, proto in ((1, "UDP"), (2, "TCP")):
        rxf = rx.get(flow, [])
        txf = tx.get(flow, [])
        assert_cadence(chk, rxf, 1.0, "combined %s RX (flow %d)" % (proto, flow))
        assert_cadence(chk, txf, 1.0, "combined %s TX (flow %d)" % (proto, flow))
        if rxf:
            chk.near(rxf[0].window, 1.0, 1e-6, "combined %s RX window == 1.0" % proto)
        for r in nonempty(rxf):
            chk.near(r.loss, 0.0, 1e-9, "combined %s RX loss == 0" % proto)
        assert_throughput(chk, txf, rxf, rate_pps, size, duration,
                          "combined %s (flow %d)" % (proto, flow))


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main():
    here = os.path.dirname(os.path.abspath(__file__))
    default_mgen = os.path.normpath(os.path.join(here, "..", "..", "makefiles", "mgen"))

    ap = argparse.ArgumentParser(description="MGEN analytics end-to-end tests")
    ap.add_argument("--mgen", default=os.environ.get("MGEN", default_mgen),
                    help="path to the mgen binary (default: %s)" % default_mgen)
    ap.add_argument("--duration", type=float, default=7.0,
                    help="active flow duration per scenario, seconds (default: 7)")
    ap.add_argument("--keep", action="store_true", help="keep the temp log dir")
    ap.add_argument("--verbose", action="store_true", help="print mgen command lines")
    args = ap.parse_args()

    if not (os.path.isfile(args.mgen) and os.access(args.mgen, os.X_OK)):
        print("ERROR: mgen binary not found/executable at: %s" % args.mgen)
        print("Build it first (see makefiles/) or pass --mgen /path/to/mgen.")
        return 2
    # Resolve to an absolute path: each mgen runs with cwd set to the temp dir.
    args.mgen = os.path.abspath(args.mgen)

    workdir = tempfile.mkdtemp(prefix="mgen-e2e-")
    print("mgenAnalyticsTest: binary=%s duration=%.1fs workdir=%s"
          % (args.mgen, args.duration, workdir))

    chk = Checker()
    mgen = MgenRunner(args.mgen, workdir, verbose=args.verbose)
    try:
        scenario_udp_analytics(chk, mgen, args.duration)
        scenario_quantize_window(chk, mgen, args.duration)
        scenario_tx_wire_rate(chk, mgen, args.duration)
        scenario_all_combined(chk, mgen, args.duration)
    finally:
        if args.keep:
            print("\n(kept logs in %s)" % workdir)
        else:
            shutil.rmtree(workdir, ignore_errors=True)

    print("\nmgenAnalyticsTest: %d checks, %d failure(s)" % (chk.checks, chk.failures))
    if chk.failures:
        print("RESULT: FAIL")
        return 1
    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
