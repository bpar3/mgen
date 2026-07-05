# Fix TXREPORT/REPORT cadence and TX accuracy

## Context

With TX + RX analytics enabled for a TCP flow (`analytics txanalytics ...`), the
receive-side `REPORT` lines come out ~1 s apart but jittery, and the transmit-side
`TXREPORT` lines arrive in irregular bursts with gaps whose rates spike to the full
*offered* load (e.g. 11457.6 kbps) rather than what actually goes on the wire (the
receiver averages ~3–5 Mbps).

Confirmed root causes:

1. **No timer — purely event-driven.** A completed window is flushed only when the *next*
   packet crosses `window_end` (`MgenAnalytic::TxUpdate`/`Update`, `src/common/mgenAnalytic.cpp`).
   RX looks steady only because received TCP bytes stream in continuously; TX is bursty
   because sends are bursty. `window_start` is set to the first packet's time (not a nice
   boundary), and reports are logged at the triggering packet's time, so timestamps are
   jittery. The `case 0`/`case 1` branches + comment at `mgenAnalytic.cpp:125-126` show
   empty-window reporting was designed but never wired to a timer.
2. **Offered-load accounting (TCP).** `MgenTcpTransport::SendMessage` writes into the kernel
   send buffer via `socket.Send()`; mgen counts a message "transmitted" the instant the
   buffer accepts it (`UpdateSendAnalytics` at `mgenTransport.cpp:1398` sync, `:1816` async).
   With a large `SO_SNDBUF`, mgen writes at the offered rate until the buffer fills (burst),
   then `socket.Send()` returns 0 → `MSG_SEND_BLOCKED` and stalls (gap), repeat.

**Goal:** both TXREPORT and REPORT emitted on a steady whole-second cadence with no gaps,
and (opt-in) TXREPORT reporting true bytes drained onto the wire per window.

## Decisions (from user + review)

- **Timer-driven flush for BOTH TX and RX, aligned to whole seconds.** A single periodic
  `Mgen::analytic_timer` fires just after each whole-`window_size` boundary and finalizes/
  emits every elapsed window (including gap-filling zero-rate windows) for both directions.
  Reports are timestamped at `window_end`, so both TXREPORT and REPORT land on whole seconds.
  Steady cadence is the default behavior whenever analytics are enabled.
- **SIOCOUTQ wire-rate accounting: implemented entirely in mgen, no protolib change.**
  Use `ioctl(socket.GetHandle(), SIOCOUTQ, ...)` (`ProtoSocket::GetHandle()` is public,
  `protolib/include/protoSocket.h:132`; `Handle` == `int` fd on Unix, line 84), guarded by
  `#ifdef SIOCOUTQ`. Opt-in via a new `txWireRate {on|off}` command (default off →
  preserves current offered-load numbers). Non-Linux (no `SIOCOUTQ`): `txWireRate on` logs
  a warning and reverts to offered-load. **No fork, branch, submodule, or `.gitmodules`
  change.**
- **Add a separate TX table** (`tx_analytic_table`) to fix a latent shared-`analytic_table`
  collision (`FindFlow` key lacks direction/protocol, so a loopback / same-flowId
  bidirectional case would drive one `MgenAnalytic` from both `TxUpdate` and `Update`). RX
  keeps using `analytic_table` (**no rename**). The timer iterates both.
- **Minimize incidental churn:** no variable renames; keep RX latency/loss/dup logic intact.
  The only structural RX change is relocating the *flush/emit trigger* from the packet path
  to the timer (required by the chosen full-alignment behavior).

## Design — unified timer-driven, boundary-aligned reporting

### A. Accumulate-only per packet

Refactor `MgenAnalytic::TxUpdate` and `MgenAnalytic::Update` (mgenAnalytic.cpp:85-230,
267-469) so the per-packet path only **accumulates** into the current window
(`byte_count`, `msg_count`, `dup_mask`, and for RX `latency_*`/seq tracking) and, on the
very first packet, initializes the window with a **boundary-aligned** start:
```cpp
window_start = floor(pktTime.GetValue() / window_size) * window_size;  // nice boundary
window_end   = window_start + window_size;
```
Remove the inline "finalize + advance + return true" boundary block from both — window
rolling and report emission now happen only in the timer (below). Keep the loss/latency/dup
math exactly as-is, just moved into the shared finalize helper. (Consequence: a packet that
arrives in the brief interval between a boundary and the timer fire is binned into the
just-closing window; sub-timer-jitter ms error, acceptable for alignment.)

`Mgen::UpdateSendAnalytics` / `UpdateRecvAnalytics` (mgen.cpp:1027, 1058) no longer log or
emit on a return value — they just look up/create the analytic (TX → `tx_analytic_table`,
RX → `analytic_table`) and accumulate. For TX they also cache the socket + wire-rate flag
and add each accounted `msgSize` to `tx_written_total` (Change B).

### B. Shared finalize helper + wire-rate accounting

Add `void MgenAnalytic::FinalizeWindow(bool wireRate)` used for both directions, factoring
the existing boundary computation (mgenAnalytic.cpp:117-146 TX / 300-354 RX): set
`report_start = window_start`, `report_duration = window_size`, `report_msg_count`,
`report_rate_ave`, and (RX) `report_loss_ave`/`report_latency_*`; then reset counters and
advance `window_start/window_end += window_size`.

TCP wire rate inside `FinalizeWindow` (guarded so it only compiles on Linux and only
applies when enabled + a socket is present):
```cpp
#ifdef SIOCOUTQ
    if (tx_wire_rate && tx_socket && tx_socket->IsConnected()) {
        int q = 0;
        if (ioctl(tx_socket->GetHandle(), SIOCOUTQ, &q) >= 0) {
            unsigned long drained = (tx_written_total - tx_written_prev)
                                  - ((unsigned long)q - tx_queue_prev);
            report_rate_ave = (double)drained / report_duration;   // bytes on wire
            tx_written_prev = tx_written_total; tx_queue_prev = (unsigned long)q;
        }
    }
#endif
```
Otherwise keep `report_rate_ave = byte_count / report_duration` (offered). `report_msg_count`
stays = messages offered in the window (document: with wire-rate on, TCP `count` is
messages-offered while `rate` is bytes-on-wire). New members: `ProtoSocket* tx_socket;
bool tx_wire_rate; unsigned long tx_written_total, tx_written_prev, tx_queue_prev;` +
setters. `#include <sys/ioctl.h>` / `<linux/sockios.h>` in mgenAnalytic.cpp.

Expose small accessors the timer needs: `bool WindowElapsed(const ProtoTime& now)` (true if
`window_valid && now >= window_end`), `ProtoTime GetWindowEnd()`, `bool HasWindow()`.

### C. The timer (`Mgen`)

`include/mgen.h`: add near `drec_event_timer` (line 549):
```cpp
ProtoTimer  analytic_timer;
bool OnAnalyticTimeout(ProtoTimer& theTimer);
MgenAnalyticTable tx_analytic_table;   // added next to existing analytic_table (no rename)
```
`src/common/mgen.cpp`:
- Constructor: `analytic_timer.SetListener(this, &Mgen::OnAnalyticTimeout);`.
- Activate (phase-aligned to next boundary) when analytics get enabled — the ANALYTICS
  (~compute_analytics) and TXANALYTICS (~1947) command handlers and/or `Start()`:
  ```cpp
  if ((tx_analytics || compute_analytics) && !analytic_timer.IsActive()) {
      ProtoTime now; now.GetCurrentTime();
      double toBoundary = analytic_window - fmod(now.GetValue(), analytic_window);
      analytic_timer.SetInterval(toBoundary);
      analytic_timer.SetRepeat(0);          // one-shot; re-armed each fire
      timer_mgr.ActivateTimer(analytic_timer);
  }
  ```
  Deactivate in `Stop()` / alongside `drec_event_timer` teardown (~642).
- Callback finalizes all elapsed windows for both tables, then re-arms to the next boundary
  (self-correcting phase lock):
  ```cpp
  bool Mgen::OnAnalyticTimeout(ProtoTimer& theTimer)
  {
      ProtoTime now; now.GetCurrentTime();
      // TX: log TXREPORT at window_end for each elapsed window (incl. empty)
      MgenAnalyticTable::Iterator txit(tx_analytic_table); MgenAnalytic* a;
      while (NULL != (a = txit.GetNextItem()))
          while (a->WindowElapsed(now)) {
              ProtoTime we = a->GetWindowEnd();
              a->FinalizeWindow(true);
              a->TxLog(log_file, we, local_time);
          }
      // RX: replicate today's emit path (feedback + GUI + REPORT log), timestamped at boundary
      MgenAnalyticTable::Iterator rxit(analytic_table);
      while (NULL != (a = rxit.GetNextItem()))
          while (a->WindowElapsed(now)) {
              ProtoTime we = a->GetWindowEnd();
              a->FinalizeWindow(false);
              MgenFlow* f = flow_list.Head();
              while (NULL != f) { if (f->GetReportAnalytics()) f->UpdateAnalyticReport(*a); f = flow_list.GetNext(f); }
              const MgenAnalytic::Report& report = a->GetReport(we);
              if (NULL != controller) controller->OnUpdateReport(we, report);
              a->Log(log_file, we, we, local_time);
          }
      double toBoundary = analytic_window - fmod(now.GetValue(), analytic_window);
      if (toBoundary < (analytic_window * 0.01)) toBoundary += analytic_window; // avoid double-fire
      theTimer.SetInterval(toBoundary);
      return true;  // reschedules with updated interval
  }
  ```
- `SetAnalyticWindow()` (~1565): recompute the timer's next-boundary interval for the new
  window; additive iteration over `tx_analytic_table`. `RemoveAnalytic` (~1007) and `~Mgen()`
  (~138) additively handle `tx_analytic_table`.

### D. `txWireRate` command (opt-in, Change 2)

Mirror the `quantizeWindow` command (ea2914c):
- `include/mgen.h`: enum `TX_WIRE_RATE`, `bool tx_wire_rate;` + setter.
- `src/common/mgen.cpp`: register `{"+TXWIRERATE", TX_WIRE_RATE}` (~1486); parse ON/OFF
  (~2171 pattern). Graceful degradation when SIOCOUTQ is unavailable:
  ```cpp
  case TX_WIRE_RATE:
      if (on) {
  #ifdef SIOCOUTQ
          SetTxWireRate(true);
  #else
          PLOG(PL_WARN, "txWireRate unsupported on this platform (no SIOCOUTQ); "
                        "ignoring - TCP TXREPORT will use offered-load accounting\n");
  #endif
      } else SetTxWireRate(false);
      break;
  ```
- `src/common/mgenApp.cpp`: add `[txWireRate {on|off}]` to usage (~61).

### E. Threading socket + flag to the TX analytic

- `Mgen::UpdateSendAnalytics(..., ProtoSocket* txSocket = NULL)`; TCP callers pass `&socket`
  (`mgenTransport.cpp:1398`, `:1816`); UDP (`:1061`) passes NULL (stays offered==transmitted).
- `UpdateSendAnalytics` caches `analytic->SetTxSocket(txSocket)`, `SetTxWireRate(tx_wire_rate)`.
- **Socket lifetime:** clear the analytic's `tx_socket` on TCP transport shutdown/destructor
  (`mgenTransport.cpp:1424`) via a `Mgen` helper, so `FinalizeWindow`'s `IsConnected()` check
  never dereferences a freed socket. (Assumes one flow per TCP connection — SIOCOUTQ is
  per-socket; confirm during impl and restrict wire-accounting to that case.)

## Files to modify

- `include/mgen.h`, `src/common/mgen.cpp` — `analytic_timer` (+ boundary-aligned scheduling
  and dual-table finalize/emit), additive `tx_analytic_table`, `txWireRate` command, socket
  threading. (Existing `analytic_table` name and RX accumulation math unchanged.)
- `include/mgenAnalytic.h`, `src/common/mgenAnalytic.cpp` — make `TxUpdate`/`Update`
  accumulate-only with boundary-aligned init; add `FinalizeWindow`, `WindowElapsed`,
  `GetWindowEnd`, wire-rate members/accessors, SIOCOUTQ ioctl.
- `src/common/mgenTransport.cpp` — pass `&socket` to TCP `UpdateSendAnalytics`; clear analytic
  socket on shutdown.
- `src/common/mgenApp.cpp` — usage string.
- **No protolib / `.gitmodules` changes.**

## Verification

Build: `cd /home/binu/repos/mgen-nrl/makefiles && make -f Makefile.linux`

Functional (loopback receiver + sender, high-rate TCP flow reproducing ~11457.6 kbps
offered), sender flags: `rxlog off analytics txanalytics epochtimestamp precise off
quantizeWindow off flush` (+ `txWireRate on` for Change 2). Confirm in the logs:

1. **Cadence + alignment (default):** BOTH TXREPORT and REPORT appear every 1.0 s with no
   gaps (incl. zero-rate lines during stalls), and their timestamps land on (near) whole
   seconds.
2. **TX accuracy (`txWireRate on`):** TXREPORT `rate>` averages down to the real wire rate
   (~3–5 Mbps), tracking the receiver's REPORT `rate>`, not the 11457.6 kbps offered spikes.
   Cross-check TXREPORT vs REPORT rate and total bytes over the run — they should converge.
3. **Backward compat:** without `txWireRate on`, TCP TXREPORT `rate>` still equals offered
   load, now at steady aligned cadence.
4. **UDP:** TXREPORT rate unchanged (offered==transmitted), now steady + aligned.
5. **Collision fix:** loopback bidirectional test (same flowId both ways) yields distinct,
   uncorrupted TX and RX reports.
6. **Non-Linux graceful path:** on a build without `SIOCOUTQ`, mgen still compiles and
   `txWireRate on` logs the warning and reverts to offered-load accounting.
