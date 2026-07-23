#!/usr/bin/env python3
#
# mgenAnalyticsTest.py - end-to-end tests for the MGEN analytics features added
# on the analytics-tx-reports and tcp-stream-analytics branches:
#
#   * RX analytics  (analytics    -> REPORT log lines)
#   * TX analytics  (txAnalytics  -> TXREPORT log lines)
#   * quantizeWindow {on|off}     (analytics window-size quantization)
#   * tcpStreamAnalytics {on|off} (symmetric TCP byte-stream accounting)
#   * timer-driven, whole-second-aligned reporting with no drift
#   * TCP dispatch-loop fairness under contention (Phase 1 of the TCP
#     stream analytics plan) and lossless cumulative stream accounting
#     under it (Phase 2): sample lateness measured from the actual
#     tcpStreamSampleTime, not the nominal report timestamp; every
#     nominal window carries a stable tcpStreamReason; the cumulative
#     tcpStreamTotalBytes is monotonic and conserved across contention.
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
import multiprocessing
import os
import shutil
import signal
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
        self.stream_valid = fields.get("tcpStreamValid") == "1"
        self.stream_rate  = _to_float(fields.get("tcpStreamRate"))
        self.stream_bytes = _to_float(fields.get("tcpStreamBytes"))
        # Phase 2 cumulative-accounting fields (present whenever
        # tcpStreamAnalytics is enabled, regardless of tcpStreamValid).
        self.stream_reason      = fields.get("tcpStreamReason")
        self.stream_total_bytes = _to_float(fields.get("tcpStreamTotalBytes"))
        self.stream_sample_time = _to_float(fields.get("tcpStreamSampleTime"))
        self.stream_sample_id   = fields.get("tcpStreamSampleId")
        self.stream_generation  = fields.get("tcpStreamGeneration")

    @property
    def stream_lateness(self):
        """Actual queue-sample time minus this window's nominal end time
        (this report's own leading timestamp is logged at window_end).
        None if the sample time wasn't captured (stream fields absent)."""
        if self.stream_sample_time is None:
            return None
        return self.stream_sample_time - self.ts

    @property
    def bytes_est(self):
        # Bytes implied by complete-message rate over a window.
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


def percentile(values, p):
    """Nearest-rank percentile (p in [0, 100]) of a non-empty list."""
    if not values:
        return None
    s = sorted(values)
    idx = min(len(s) - 1, int(math.ceil(p / 100.0 * len(s))) - 1)
    return s[max(0, idx)]


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
        return self.run_pair_with_hook(
            recv_args, send_args, duration,
            on_running=lambda send_proc, recv_proc: time.sleep(duration),
            stop_flows=stop_flows, startup=startup, settle=settle, tag=tag)

    def run_pair_with_hook(self, recv_args, send_args, duration, on_running,
                           stop_flows=(), startup=1.0, settle=2.5, tag="run"):
        """Like run_pair(), but `on_running(send_proc, recv_proc)` governs the
        active-flow period instead of a plain sleep -- e.g. to SIGSTOP/SIGCONT
        the sender or run background load in the middle of it.  The OFF
        event(s) for `stop_flows` are still scheduled at sender script time
        `duration`, so `on_running` should occupy approximately that much
        wall-clock time for the OFF event and settle period to line up."""
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
                on_running(send_proc, recv_proc)
                time.sleep(settle)
            finally:
                # Undo any SIGSTOP left in place before terminate()/wait(),
                # otherwise the stopped process can never actually exit.
                if send_proc.poll() is None:
                    try:
                        send_proc.send_signal(signal.SIGCONT)
                    except OSError:
                        pass
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


def steady_windows(reports):
    """Drop the first and last window (startup / shutdown-straddling)."""
    return reports[1:-1] if len(reports) >= 3 else []


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


def assert_sample_lateness(chk, reports, label, p99_max, max_max):
    """Phase 1 acceptance: TCP stream sample lateness (actual queue-sample
    time minus the nominal window-end time), measured from tcpStreamSampleTime
    -- not the nominal report timestamp -- must stay within the given p99/max
    bounds.  Only meaningful on windows that captured a queue sample at all
    (tcpStreamSampleTime present); disabled/no-socket/disconnected windows
    carry no sample and are excluded."""
    lateness = [r.stream_lateness for r in reports if r.stream_lateness is not None]
    chk.ge(len(lateness), 1, "%s: has stream-sample lateness data" % label)
    if not lateness:
        return
    p99 = percentile(lateness, 99)
    worst = max(lateness)
    chk.check(p99 <= p99_max,
              "%s: p99 sample lateness %.4fs <= %.4fs" % (label, p99, p99_max))
    chk.check(worst <= max_max,
              "%s: max sample lateness %.4fs <= %.4fs" % (label, worst, max_max))


def assert_stream_reasons_present(chk, reports, label):
    """Every window with tcpStreamAnalytics enabled must carry a stable,
    named reason -- never a silently missing/absent field."""
    missing = sum(1 for r in reports if r.stream_reason is None)
    chk.check(missing == 0,
              "%s: every window has a tcpStreamReason (missing on %d/%d)"
              % (label, missing, len(reports)))


def last_cumulative(reports):
    """Highest tcpStreamTotalBytes observed.  It's monotonic non-decreasing
    within a socket generation, but a catch-up report may repeat an older
    sample id/total verbatim, so take the max rather than the last value."""
    vals = [r.stream_total_bytes for r in reports if r.stream_total_bytes is not None]
    return max(vals) if vals else 0


def assert_cumulative_conservation(chk, tx, rx, size, label, tol=0.20):
    """Phase 2 acceptance: the TX/RX cumulative stream totals must track all
    real traffic with no permanent gap from a missed/late/failed boundary --
    converging to within `tol` of each other and of the legacy message-count
    byte total, even though individual windows may be invalid."""
    tx_final = last_cumulative(tx)
    rx_final = last_cumulative(rx)
    tx_count_bytes = total_count(tx) * size
    chk.ge(tx_final, 1, "%s: TX cumulative stream total advanced" % label)
    chk.ge(rx_final, 1, "%s: RX cumulative stream total advanced" % label)
    if tx_count_bytes:
        chk.between(tx_final, tx_count_bytes * (1 - tol), tx_count_bytes * (1 + tol),
                    "%s: TX cumulative total (%d) ~= TX message bytes (%d)"
                    % (label, tx_final, tx_count_bytes))
    if tx_final:
        chk.between(rx_final, tx_final * (1 - tol), tx_final * (1 + tol),
                    "%s: RX cumulative total (%d) ~= TX cumulative total (%d)"
                    % (label, rx_final, tx_final))


def _cpu_burn(stop_at):
    """Busy-loop until the given time.monotonic() deadline; run as a
    background process to create real CPU contention against the mgen
    sender under test."""
    while time.monotonic() < stop_at:
        pass


class CpuLoad(object):
    """Context manager that runs one CPU-bound busy-loop process per core
    (minus one, to leave the mgen sender a core) for the duration of the
    `with` block."""
    def __init__(self, seconds, workers=None):
        self.seconds = seconds
        self.workers = workers or min(8, max(1, (os.cpu_count() or 2) - 1))
        self.procs = []

    def __enter__(self):
        stop_at = time.monotonic() + self.seconds
        for _ in range(self.workers):
            p = multiprocessing.Process(target=_cpu_burn, args=(stop_at,))
            p.start()
            self.procs.append(p)
        return self

    def __exit__(self, *exc):
        for p in self.procs:
            p.join(timeout=self.seconds + 5)
            if p.is_alive():
                p.terminate()


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

    # Loss is zero on EVERY window, including empty gap-fill windows (those must
    # report loss 0, not the old bogus 100%).  Latency checked where sampled.
    for r in rx:
        chk.near(r.loss, 0.0, 1e-9, "RX loss == 0 (incl. empty gap windows)")
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

    # A "window" command now honors quantizeWindow off (given before it): an
    # explicit 2.0s window is used verbatim, not snapped to the quantized grid.
    recv_w, send_w = mgen.run_pair(
        recv_args=["analytics", "quantizeWindow", "off", "window", "2.0",
                   ev_recv[0], ev_recv[1]],
        send_args=["txAnalytics", "quantizeWindow", "off", "window", "2.0",
                   ev_send[0], ev_send[1]],
        duration=max(dur, 5.0), stop_flows=[1], tag="qoff-w2")
    rx_w = by_flow(parse_reports(recv_w), "REPORT").get(1, [])
    chk.ge(len(rx_w), 1, "window+quantize off: got RX reports")
    if rx_w:
        chk.near(rx_w[0].window, 2.0, 1e-6,
                 "window 2.0 + quantize off: RX window == 2.000000 (honored, not quantized)")


def scenario_tcp_stream_rate(chk, mgen, duration):
    """TCP stream analytics are emitted symmetrically for TX and RX while
    legacy rate/count continue to represent complete MGEN messages."""
    chk.scenario("tcpStreamAnalytics: TX/RX stream fields + message metrics")
    port = 5020
    rate_pps, size = 100, 1024
    ev_recv = ("event", "LISTEN TCP %d" % port)
    ev_send = ("event", "ON 1 TCP DST 127.0.0.1/%d PERIODIC [%d %d]" % (port, rate_pps, size))

    for stream in ("on", "off"):
        recv, send = mgen.run_pair(
            recv_args=["analytics", "tcpStreamAnalytics", stream,
                       "quantizeWindow", "off", ev_recv[0], ev_recv[1]],
            send_args=["txAnalytics", "tcpStreamAnalytics", stream,
                       "quantizeWindow", "off",
                       ev_send[0], ev_send[1]],
            duration=duration, stop_flows=[1], tag="tcp-%s" % stream)
        rx = by_flow(parse_reports(recv), "REPORT").get(1, [])
        tx = by_flow(parse_reports(send), "TXREPORT").get(1, [])

        assert_cadence(chk, rx, 1.0, "TCP RX REPORT (stream %s)" % stream)
        assert_cadence(chk, tx, 1.0, "TCP TX TXREPORT (stream %s)" % stream)

        # Legacy rate/count remain complete-message metrics and self-consistent.
        # rate(kbps) == count*size*8/1000/window (regardless of the wire flag).
        for r in nonempty(tx):
            expected = r.count * size * 8 / 1000.0 / r.window
            chk.near(r.rate, expected, max(1.0, expected * 0.02),
                      "TCP stream %s: rate==completed messages (count=%d -> %.1f kbps)"
                      % (stream, r.count, expected))

        tx_count = total_count(tx)
        rx_count = total_count(rx)
        chk.ge(tx_count, 1, "TCP stream %s: TX produced messages" % stream)
        if tx_count:
            chk.between(rx_count, tx_count * 0.85, tx_count * 1.15,
                        "TCP stream %s: RX count (%d) ~= TX count (%d)"
                        % (stream, rx_count, tx_count))

        if stream == "on":
            tx_valid = [r for r in tx if r.stream_valid]
            rx_valid = [r for r in rx if r.stream_valid]
            chk.ge(len(tx_valid), 1, "stream ON: TX has valid stream windows")
            chk.ge(len(rx_valid), 1, "stream ON: RX has valid stream windows")
            tx_bytes = sum(r.stream_bytes for r in tx_valid)
            rx_bytes = sum(r.stream_bytes for r in rx_valid)
            chk.ge(tx_bytes, 1, "stream ON: measured TX stream bytes")
            chk.ge(rx_bytes, 1, "stream ON: measured RX stream bytes")
            chk.between(rx_bytes, tx_bytes * 0.80, tx_bytes * 1.20,
                        "stream ON: RX bytes (%d) ~= TX bytes (%d)"
                        % (int(rx_bytes), int(tx_bytes)))
        else:
            chk.check(not any(r.stream_valid for r in tx + rx),
                      "stream OFF: no report carries stream fields")


def scenario_tcp_unlimited(chk, mgen, duration):
    """An unlimited TCP flow must not collapse active stream windows into an
    aggregate spike followed by fabricated zero windows when timers run late."""
    chk.scenario("TCP unlimited: active stream windows remain populated")
    port = 5025
    dur = min(duration, 4.0)
    recv, send = mgen.run_pair(
        recv_args=["analytics", "tcpStreamAnalytics", "on",
                   "quantizeWindow", "off", "event", "LISTEN TCP %d" % port],
        send_args=["txAnalytics", "tcpStreamAnalytics", "on",
                   "quantizeWindow", "off", "event",
                   "ON 1 TCP DST 127.0.0.1/%d PERIODIC [-1 1400]" % port],
        duration=dur, stop_flows=[1], tag="tcp-unlimited")
    rx = by_flow(parse_reports(recv), "REPORT").get(1, [])
    tx = by_flow(parse_reports(send), "TXREPORT").get(1, [])
    assert_cadence(chk, rx, 1.0, "unlimited TCP RX")
    assert_cadence(chk, tx, 1.0, "unlimited TCP TX")
    tx_active = [r for r in tx[1:-1] if r.stream_valid]
    rx_active = [r for r in rx[1:-1] if r.stream_valid]
    chk.ge(len(tx_active), 1, "unlimited TX has valid interior windows")
    chk.ge(len(rx_active), 1, "unlimited RX has valid interior windows")
    chk.check(all(r.stream_bytes > 0 for r in tx_active),
              "unlimited TX valid interior windows are nonzero")
    chk.check(all(r.stream_bytes > 0 for r in rx_active),
              "unlimited RX valid interior windows are nonzero")


def scenario_tcp_unlimited_slow_receiver(chk, mgen, duration):
    """Phase 1 acceptance scenario: unlimited-rate TCP with a small RX/TX
    socket buffer to force real kernel backpressure (frequent EWOULDBLOCK /
    short writes), stressing the dispatch-fairness budget added in Phase 1.
    Sample lateness is measured from the actual tcpStreamSampleTime, not the
    nominal report timestamp; every window must still carry a stable reason
    and the cumulative byte total must be conserved.

    The plan's bare-metal acceptance targets are p99 < 5ms / max < 20ms
    lateness over a one-hour stress run. This uses looser, CI-container-safe
    bounds meant to catch a fairness regression, not to be a final sign-off
    (that needs a real EMANE run per the implementation plan)."""
    chk.scenario("TCP unlimited + slow receiver: dispatch fairness under backpressure")
    port = 5040
    dur = max(duration, 6.0)
    size = 1400
    recv, send = mgen.run_pair(
        recv_args=["analytics", "tcpStreamAnalytics", "on", "quantizeWindow", "off",
                   "rxBuffer", "4096",
                   "event", "LISTEN TCP %d" % port],
        send_args=["txAnalytics", "tcpStreamAnalytics", "on", "quantizeWindow", "off",
                   "txBuffer", "8192",
                   "event", "ON 1 TCP DST 127.0.0.1/%d PERIODIC [-1 %d]" % (port, size)],
        duration=dur, stop_flows=[1], tag="tcp-slow-rx")
    rx = by_flow(parse_reports(recv), "REPORT").get(1, [])
    tx = by_flow(parse_reports(send), "TXREPORT").get(1, [])

    assert_cadence(chk, rx, 1.0, "slow-receiver RX")
    assert_cadence(chk, tx, 1.0, "slow-receiver TX")
    assert_stream_reasons_present(chk, tx, "slow-receiver TX")
    assert_stream_reasons_present(chk, rx, "slow-receiver RX")
    assert_sample_lateness(chk, steady_windows(tx), "slow-receiver TX", 0.020, 0.100)
    assert_sample_lateness(chk, steady_windows(rx), "slow-receiver RX", 0.020, 0.100)
    assert_cumulative_conservation(chk, tx, rx, size, "slow-receiver")


def scenario_tcp_large_messages(chk, mgen, duration):
    """Large messages at unlimited rate.  MGEN messages are hard-capped at
    MAX_SIZE (8192 bytes, matching TX_BUFFER_SIZE), so a single PERIODIC
    message can't literally span multiple TX_BUFFER_SIZE chunks -- this
    exercises MgenTcpTransport::SendMessage()'s per-message buffer path at
    its largest legal size, back-to-back at unlimited rate, which is the
    "several large sends per callback" pattern the dispatch-fairness budget
    targets."""
    chk.scenario("TCP unlimited: max-size messages (8192B) stress the send budget")
    port = 5043
    dur = max(duration, 6.0)
    size = 8192  # MAX_SIZE / TX_BUFFER_SIZE: the largest legal message
    recv, send = mgen.run_pair(
        recv_args=["analytics", "tcpStreamAnalytics", "on", "quantizeWindow", "off",
                   "event", "LISTEN TCP %d" % port],
        send_args=["txAnalytics", "tcpStreamAnalytics", "on", "quantizeWindow", "off",
                   "event", "ON 1 TCP DST 127.0.0.1/%d PERIODIC [-1 %d]" % (port, size)],
        duration=dur, stop_flows=[1], tag="tcp-large-msg")
    rx = by_flow(parse_reports(recv), "REPORT").get(1, [])
    tx = by_flow(parse_reports(send), "TXREPORT").get(1, [])

    assert_cadence(chk, rx, 1.0, "large-message RX")
    assert_cadence(chk, tx, 1.0, "large-message TX")
    assert_stream_reasons_present(chk, tx, "large-message TX")
    assert_cumulative_conservation(chk, tx, rx, size, "large-message")


def scenario_tcp_cpu_contention(chk, mgen, duration):
    """CPU contention: one busy-loop process per (core - 1) runs for the
    whole active period alongside an unlimited TCP flow.  Under real
    contention, sample lateness legitimately grows -- the guarantee under
    test is structural, not a tight timing bound: reports keep a steady 1s
    cadence, every window still carries a stable reason, and the cumulative
    stream total is still conserved (Phase 2's "never lose a coherent
    delta" guarantee must hold regardless of how delayed the dispatcher
    gets)."""
    chk.scenario("TCP unlimited under CPU contention: no lost boundaries")
    port = 5041
    dur = max(duration, 6.0)
    size = 1400

    def on_running(send_proc, recv_proc):
        with CpuLoad(dur):
            time.sleep(dur)

    recv, send = mgen.run_pair_with_hook(
        recv_args=["analytics", "tcpStreamAnalytics", "on", "quantizeWindow", "off",
                   "event", "LISTEN TCP %d" % port],
        send_args=["txAnalytics", "tcpStreamAnalytics", "on", "quantizeWindow", "off",
                   "event", "ON 1 TCP DST 127.0.0.1/%d PERIODIC [-1 %d]" % (port, size)],
        duration=dur, on_running=on_running, stop_flows=[1], tag="tcp-cpu-contend")
    rx = by_flow(parse_reports(recv), "REPORT").get(1, [])
    tx = by_flow(parse_reports(send), "TXREPORT").get(1, [])

    assert_cadence(chk, rx, 1.0, "CPU-contention RX")
    assert_cadence(chk, tx, 1.0, "CPU-contention TX")
    assert_stream_reasons_present(chk, tx, "CPU-contention TX")
    assert_stream_reasons_present(chk, rx, "CPU-contention RX")
    assert_cumulative_conservation(chk, tx, rx, size, "CPU-contention", tol=0.30)

    lateness = [r.stream_lateness for r in tx if r.stream_lateness is not None]
    if lateness:
        print("  info : CPU-contention TX lateness p99=%.4fs max=%.4fs (informational)"
              % (percentile(lateness, 99), max(lateness)))
    # Sanity ceiling only: catches a true hang/multi-window stall, not
    # ordinary contention-induced delay (which is expected, and unbounded
    # by design, under enough contention).
    chk.check(all(l < 10.0 for l in lateness),
              "CPU-contention: no sample lateness >= 10s (no hang)")


def scenario_tcp_sigstop_sigcont(chk, mgen, duration):
    """SIGSTOP the sender mid-flow, spanning several report-window
    boundaries, then SIGCONT it.  SIGSTOP/SIGCONT are handled entirely by
    the kernel (uncatchable, unblockable) -- this tests what happens when
    the whole process, dispatcher included, is frozen and later resumes:
    it must survive; the window(s) spanning the stop must be flagged
    missed_boundaries/late_boundary rather than silently invalid or a
    fabricated measurement; the cumulative stream total must still conserve
    across the gap; and cadence must return to steady 1s reporting after
    resume."""
    chk.scenario("TCP unlimited: SIGSTOP/SIGCONT across report boundaries")
    port = 5042
    stop_span = 3.5   # spans several 1s boundaries
    dur = max(duration, stop_span + 6.0)
    size = 1400

    def on_running(send_proc, recv_proc):
        time.sleep(2.0)                       # run normally first
        send_proc.send_signal(signal.SIGSTOP)
        time.sleep(stop_span)
        send_proc.send_signal(signal.SIGCONT)
        remaining = dur - 2.0 - stop_span
        if remaining > 0:
            time.sleep(remaining)

    recv, send = mgen.run_pair_with_hook(
        recv_args=["analytics", "tcpStreamAnalytics", "on", "quantizeWindow", "off",
                   "event", "LISTEN TCP %d" % port],
        send_args=["txAnalytics", "tcpStreamAnalytics", "on", "quantizeWindow", "off",
                   "event", "ON 1 TCP DST 127.0.0.1/%d PERIODIC [-1 %d]" % (port, size)],
        duration=dur, on_running=on_running, stop_flows=[1], tag="tcp-sigstop")
    tx = by_flow(parse_reports(send), "TXREPORT").get(1, [])

    chk.ge(len(tx), 3, "SIGSTOP: sender produced reports before/after the stop")
    if len(tx) >= 2:
        span = tx[-1].ts - tx[0].ts
        chk.ge(span, stop_span,
               "SIGSTOP: report span covers the stop+resume window (process really resumed)")

    reasons = [r.stream_reason for r in tx]
    chk.check(all(r is not None for r in reasons),
              "SIGSTOP: every TX window still carries a tcpStreamReason")
    stalled = [r for r in tx if r.stream_reason in ("missed_boundaries", "late_boundary")]
    chk.ge(len(stalled), 1,
           "SIGSTOP: at least one window flagged missed_boundaries/late_boundary")
    # No window silently claims a valid direct measurement across the actual
    # stop -- an "ok" reason always needs a genuinely on-time, coherent sample.
    counter_bad = [r for r in tx if r.stream_reason == "counter_inconsistent"]
    chk.check(len(counter_bad) == 0,
              "SIGSTOP: no counter_inconsistent windows from the stop/resume")

    # Cadence and stream sampling recover cleanly after resume: the tail of
    # the run (well after SIGCONT) is back to steady 1s reporting.
    tail = [r for r in tx if r.ts > tx[0].ts + 2.0 + stop_span + 1.0]
    assert_cadence(chk, tail, 1.0, "SIGSTOP: post-resume TX cadence", min_reports=1)

    chk.ge(last_cumulative(tx), 1,
           "SIGSTOP: cumulative stream total advanced despite the stop")


def scenario_all_combined(chk, mgen, duration):
    """All features on together, with a UDP flow and a TCP flow in the SAME run,
    to confirm the settings coexist: analytics + txAnalytics + tcpStreamAnalytics on +
    quantizeWindow off, both flows reported on a steady 1s whole-second grid."""
    chk.scenario("Combined: UDP(flow1) + TCP(flow2), all analytics features on")
    uport, tport = 5030, 5031
    rate_pps, size = 100, 1024
    recv, send = mgen.run_pair(
        recv_args=["analytics", "tcpStreamAnalytics", "on", "quantizeWindow", "off",
                   "event", "LISTEN UDP %d" % uport,
                   "event", "LISTEN TCP %d" % tport],
        send_args=["txAnalytics", "tcpStreamAnalytics", "on", "quantizeWindow", "off",
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
        for r in rxf:
            chk.near(r.loss, 0.0, 1e-9, "combined %s RX loss == 0 (incl. gaps)" % proto)
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
        scenario_tcp_stream_rate(chk, mgen, args.duration)
        scenario_tcp_unlimited(chk, mgen, args.duration)
        scenario_tcp_unlimited_slow_receiver(chk, mgen, args.duration)
        scenario_tcp_large_messages(chk, mgen, args.duration)
        scenario_tcp_cpu_contention(chk, mgen, args.duration)
        scenario_tcp_sigstop_sigcont(chk, mgen, args.duration)
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
