/*
 * mgenAnalyticTest - standalone unit tests for MgenAnalytic window
 * accumulation / finalization logic (the timer-driven, whole-second-aligned
 * TX/RX message analytics and symmetric TCP stream accounting).
 *
 * This is a plain assertion-based driver in the style of protolib's
 * examples/unitTests.cpp (MGEN has no unit-test framework).  It exercises
 * MgenAnalytic directly - no sockets, timers, or dispatcher required - and
 * returns a non-zero exit code if any check fails (CI/script friendly).
 *
 * Build:  make -f Makefile.linux mgenAnalyticTest
 * Run:    ./mgenAnalyticTest        (exit 0 = all pass)
 */

#include "mgenAnalytic.h"
#include "protoSocket.h"

#include <stdio.h>
#include <math.h>   // for fabs()

static int failures = 0;
static int checks   = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        checks++;                                                         \
        if (!(cond)) {                                                    \
            failures++;                                                   \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                 \
    } while (0)

// Approximate equality for doubles
#define CHECK_NEAR(a, b, eps)                                             \
    do {                                                                  \
        checks++;                                                         \
        double _va = (double)(a), _vb = (double)(b);                      \
        if (fabs(_va - _vb) >= (eps)) {                                   \
            failures++;                                                   \
            fprintf(stderr, "  FAIL %s:%d: |%.9f - %.9f| >= %g\n",        \
                    __FILE__, __LINE__, _va, _vb, (double)(eps));         \
        }                                                                 \
    } while (0)

// Build a fresh 1.0s, non-quantized TCP analytic for flow 1 (10.1.0.1:49153 -> 10.1.0.2:5000)
static bool InitAnalytic(MgenAnalytic& a)
{
    ProtoAddress src, dst;
    if (!src.ResolveFromString("10.1.0.1")) return false;
    src.SetPort(49153);
    if (!dst.ResolveFromString("10.1.0.2")) return false;
    dst.SetPort(5000);
    // windowQuantize=false, windowSize=1.0 -> exact 1.0s window for clean asserts
    return a.Init(TCP, src, dst, 1, false, 1.0);
}

// ---- Test 1: TX/RX window boundaries align to whole-second multiples --------
static void test_boundary_alignment()
{
    printf("test_boundary_alignment\n");
    MgenAnalytic tx;
    CHECK(InitAnalytic(tx));
    tx.TxUpdate(1024, ProtoTime(118.137), 0);
    CHECK(tx.HasWindow());
    CHECK_NEAR(tx.GetWindowEnd().GetValue(), 119.0, 1e-9);  // floor(118.137)+1

    MgenAnalytic rx;
    CHECK(InitAnalytic(rx));
    rx.Update(ProtoTime(118.137), 1024, ProtoTime(118.100), 0);
    CHECK_NEAR(rx.GetWindowEnd().GetValue(), 119.0, 1e-9);
}

// ---- Test 2: WindowElapsed drives the timer's per-window flush loop ---------
static void test_window_elapsed()
{
    printf("test_window_elapsed\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));
    CHECK(!a.WindowElapsed(ProtoTime(50.0)));  // no window yet
    a.TxUpdate(100, ProtoTime(118.5), 0);      // window [118,119)
    CHECK(!a.WindowElapsed(ProtoTime(118.9)));
    CHECK(a.WindowElapsed(ProtoTime(119.0)));
    CHECK(a.WindowElapsed(ProtoTime(120.5)));
}

// ---- Test 3: TX complete-message rate & count over one window --------------
static void test_tx_message_rate()
{
    printf("test_tx_message_rate\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));
    for (UINT32 i = 0; i < 100; i++)
        a.TxUpdate(1000, ProtoTime(10.0 + 0.001 * i), i);  // all within [10,11)
    a.FinalizeTxWindow();
    CHECK(a.GetReportMessageCount() == 100);
    CHECK_NEAR(a.GetReportDuration(), 1.0, 1e-9);
    CHECK_NEAR(a.GetReportRateAverage(), 100000.0, 1e-6);  // 100*1000 bytes / 1.0s
}

// ---- Test 4: empty window yields a zero-rate report (steady gap-fill) ------
static void test_tx_gap_fill()
{
    printf("test_tx_gap_fill\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));
    a.TxUpdate(1000, ProtoTime(10.0), 0);
    a.FinalizeTxWindow();                        // window [10,11) had 1 msg
    double endAfterFirst = a.GetWindowEnd().GetValue();
    a.FinalizeTxWindow();                        // window [11,12): no messages
    CHECK(a.GetReportMessageCount() == 0);
    CHECK_NEAR(a.GetReportRateAverage(), 0.0, 1e-9);
    // window advanced by exactly one more window_size
    CHECK_NEAR(a.GetWindowEnd().GetValue(), endAfterFirst + 1.0, 1e-9);
}

// ---- Test 5: RX rate/count/latency, zero loss, in-order --------------------
static void test_rx_basic()
{
    printf("test_rx_basic\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));
    for (UINT32 i = 0; i < 50; i++)
    {
        double rxt = 20.0 + 0.001 * i;           // within [20,21)
        a.Update(ProtoTime(rxt), 500, ProtoTime(rxt - 0.010), i);  // latency 10ms
    }
    a.FinalizeRxWindow();
    CHECK(a.GetReportMessageCount() == 50);
    CHECK_NEAR(a.GetReportRateAverage(), 25000.0, 1e-6);  // 50*500 / 1.0s
    CHECK_NEAR(a.GetReportLossFraction(), 0.0, 1e-9);
    CHECK_NEAR(a.GetReportLatencyAverage(), 0.010, 1e-4);
}

// ---- Test 6: RX per-window loss with a dropped sequence number -------------
static void test_rx_loss_gap()
{
    printf("test_rx_loss_gap\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));
    UINT32 seqs[] = {0, 1, 2, 4};                // seq 3 missing
    for (int i = 0; i < 4; i++)
    {
        double rxt = 40.0 + 0.001 * i;
        a.Update(ProtoTime(rxt), 100, ProtoTime(rxt - 0.005), seqs[i]);
    }
    a.FinalizeRxWindow();
    CHECK(a.GetReportMessageCount() == 4);
    // loss = 1 - count/(seqDelta+1) = 1 - 4/(4+1) = 0.2
    CHECK_NEAR(a.GetReportLossFraction(), 0.2, 1e-9);
}

// ---- Test 7: RX loss is computed per-window (regression for seq_start reset) -
// Before the fix, seq_start was never reset at a window boundary, so the second
// window's seqDelta spanned since flow start and loss was wrongly ~0.5.
static void test_rx_loss_regression_across_windows()
{
    printf("test_rx_loss_regression_across_windows\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));
    // Window A: seq 0..9 (perfect)
    for (UINT32 i = 0; i < 10; i++)
    {
        double rxt = 30.0 + 0.001 * i;
        a.Update(ProtoTime(rxt), 100, ProtoTime(rxt - 0.005), i);
    }
    a.FinalizeRxWindow();
    CHECK_NEAR(a.GetReportLossFraction(), 0.0, 1e-9);   // window A: no loss
    // Window B: seq 10..19 (also perfect)
    for (UINT32 i = 10; i < 20; i++)
    {
        double rxt = 31.0 + 0.001 * (i - 10);
        a.Update(ProtoTime(rxt), 100, ProtoTime(rxt - 0.005), i);
    }
    a.FinalizeRxWindow();
    CHECK(a.GetReportMessageCount() == 10);
    CHECK_NEAR(a.GetReportLossFraction(), 0.0, 1e-9);   // the key assertion
}

// ---- Test 8: empty RX window reports case-0 semantics ----------------------
static void test_rx_empty_window()
{
    printf("test_rx_empty_window\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));
    a.Update(ProtoTime(60.0), 100, ProtoTime(59.99), 0);
    a.FinalizeRxWindow();          // window with 1 msg
    a.FinalizeRxWindow();          // next window: empty
    CHECK(a.GetReportMessageCount() == 0);
    CHECK_NEAR(a.GetReportRateAverage(), 0.0, 1e-9);
    // A gap-fill (empty) window is NOT loss -- must report 0, not 100%.
    CHECK_NEAR(a.GetReportLossFraction(), 0.0, 1e-9);
    CHECK_NEAR(a.GetReportLatencyAverage(), -1.0, 1e-9);    // no latency sample
}

// ---- Test 9: duplicate sequence numbers are not double-counted -------------
static void test_rx_duplicate()
{
    printf("test_rx_duplicate\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));
    a.Update(ProtoTime(70.000), 100, ProtoTime(69.995), 5);
    a.Update(ProtoTime(70.001), 100, ProtoTime(69.996), 5);  // duplicate
    a.Update(ProtoTime(70.002), 100, ProtoTime(69.997), 6);
    a.FinalizeRxWindow();
    CHECK(a.GetReportMessageCount() == 2);                   // dup not counted
    CHECK_NEAR(a.GetReportRateAverage(), 200.0, 1e-6);       // 2*100 / 1.0s
}

// ---- Test 10: TX and RX use separate tables (no key collision) -------------
static void test_table_separation()
{
    printf("test_table_separation\n");
    ProtoAddress src, dst;
    CHECK(src.ResolveFromString("10.1.0.1")); src.SetPort(49153);
    CHECK(dst.ResolveFromString("10.1.0.2")); dst.SetPort(5000);

    MgenAnalyticTable txTable;
    MgenAnalyticTable rxTable;
    MgenAnalytic* txA = new MgenAnalytic();
    MgenAnalytic* rxA = new MgenAnalytic();
    CHECK(txA->Init(TCP, src, dst, 1, false, 1.0));
    CHECK(rxA->Init(TCP, src, dst, 1, false, 1.0));  // identical flow key
    CHECK(txTable.Insert(*txA));
    CHECK(rxTable.Insert(*rxA));

    // Each table resolves the same flow key to its own distinct object
    CHECK(txTable.FindFlow(src, dst, 1) == txA);
    CHECK(rxTable.FindFlow(src, dst, 1) == rxA);
    CHECK(txA != rxA);

    txTable.Remove(*txA);
    rxTable.Remove(*rxA);
    delete txA;
    delete rxA;
}

// ---- Test 11: symmetric TCP stream queue arithmetic ------------------------
static void test_tcp_stream_bytes()
{
    printf("test_tcp_stream_bytes\n");
    CHECK(MgenAnalytic::ComputeTxStreamBytes(10000, 0) == 10000);
    CHECK(MgenAnalytic::ComputeTxStreamBytes(10000, 4000) == 6000);
    CHECK(MgenAnalytic::ComputeTxStreamBytes(2000, -3000) == 5000);
    CHECK(MgenAnalytic::ComputeTxStreamBytes(1000, 5000) == 0);
    CHECK(MgenAnalytic::ComputeRxStreamBytes(10000, 0) == 10000);
    CHECK(MgenAnalytic::ComputeRxStreamBytes(6000, 4000) == 10000);
    CHECK(MgenAnalytic::ComputeRxStreamBytes(10000, -4000) == 6000);
    CHECK(MgenAnalytic::ComputeRxStreamBytes(1000, -5000) == 0);
}

// ---- Helpers for Phase 2 TCP stream cumulative-accounting tests -----------
//
// FinalizeTcpStream() normally samples the live kernel's SIOCOUTQNSD/SIOCINQ
// queue depth via ioctl() on a real connected socket.  For deterministic,
// sleep-free tests we instead:
//   - fake a "connected" ProtoSocket with SetState() (no real fd/connection;
//     SetState() is a base-class hook explicitly documented as existing
//     "for tcp development testing")
//   - install a scripted queue-query function via
//     SetTcpQueueQueryFuncForTest() that returns a pre-programmed sequence
//     of (success, queueValue) results, one per queue sample taken (both
//     SetTcpStream()'s own immediate baseline read and each
//     FinalizeTcpStream() call consume one script step)
//   - drive window/report timing entirely through explicit ProtoTime values
//     passed to AddTcpStreamIoBytes()/FinalizeTxWindow()/FinalizeRxWindow()

struct TcpQueueScript
{
    enum {MAX_STEPS = 32};
    bool ok[MAX_STEPS];
    int  value[MAX_STEPS];
    int  count;
    int  index;
    TcpQueueScript() : count(0), index(0) {}
    void Step(bool success, int queueValue)
    {
        ok[count] = success;
        value[count] = queueValue;
        count++;
    }
};

static bool ScriptedQueueQuery(void* userData, bool /*isTx*/, int& queueValue)
{
    TcpQueueScript* script = static_cast<TcpQueueScript*>(userData);
    if (script->index >= script->count) return false;  // exhausted -> treat as failure
    int i = script->index++;
    queueValue = script->value[i];
    return script->ok[i];
}

static void FakeConnect(ProtoSocket& sock)
{
    sock.SetState(ProtoSocket::CONNECTED);
}

// ---- Test 13: direct on-time window match + initial baseline --------------
static void test_tcp_stream_direct_window()
{
    printf("test_tcp_stream_direct_window\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));  // 1.0s exact window

    ProtoSocket sock(ProtoSocket::TCP);
    FakeConnect(sock);

    TcpQueueScript script;
    script.Step(true, 0);  // consumed immediately by SetTcpStream()'s baseline read
    a.SetTcpQueueQueryFuncForTest(ScriptedQueueQuery, &script);
    a.SetTcpStream(&sock, true /*isTx*/, true /*enabled*/);
    CHECK(a.GetTcpStreamSocket() == &sock);

    // First FinalizeTcpStream(): the queue was already initialized by
    // SetTcpStream(), so this samples once more but has no prior *resolved*
    // sample to diff against -> initial_baseline, not a direct measurement.
    script.Step(true, 0);
    a.AddTcpStreamIoBytes(0, ProtoTime(10.0));   // starts window [10,11)
    a.FinalizeTxWindow(true, ProtoTime(11.0));   // on-time
    CHECK(MgenAnalytic::TCP_STREAM_INITIAL_BASELINE == a.GetReportTcpStreamReason());
    CHECK(!a.GetReportTcpStreamValid());
    CHECK(0 == a.GetReportTcpStreamTotalBytes());
    UINT32 firstSampleId = a.GetReportTcpStreamSampleId();
    CHECK(firstSampleId > 0);

    // Second window: 5000 bytes actually sent, queue drains back to 0 (a
    // typical fast-draining TX) -> a clean, on-time, single-window match.
    script.Step(true, 0);
    a.AddTcpStreamIoBytes(5000, ProtoTime(11.5));
    a.FinalizeTxWindow(true, ProtoTime(12.0));   // window_end for 2nd window is 12.0
    CHECK(MgenAnalytic::TCP_STREAM_OK == a.GetReportTcpStreamReason());
    CHECK(a.GetReportTcpStreamValid());
    CHECK(5000ULL == a.GetReportTcpStreamBytes());
    CHECK(5000ULL == a.GetReportTcpStreamTotalBytes());
    CHECK(a.GetReportTcpStreamSampleId() > firstSampleId);
    CHECK(0 == a.GetReportTcpStreamGeneration());
}

// ---- Test 14: late boundary and missed boundaries still conserve bytes ----
static void test_tcp_stream_late_and_missed_boundary()
{
    printf("test_tcp_stream_late_and_missed_boundary\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));

    ProtoSocket sock(ProtoSocket::TCP);
    FakeConnect(sock);
    TcpQueueScript script;
    script.Step(true, 0);  // SetTcpStream() baseline
    a.SetTcpQueueQueryFuncForTest(ScriptedQueueQuery, &script);
    a.SetTcpStream(&sock, false /*isTx (RX direction)*/, true);

    script.Step(true, 0);  // window 1: initial_baseline
    a.AddTcpStreamIoBytes(0, ProtoTime(20.0));
    a.FinalizeRxWindow(true, ProtoTime(21.0));
    CHECK(MgenAnalytic::TCP_STREAM_INITIAL_BASELINE == a.GetReportTcpStreamReason());

    // window 2: sample arrives 20ms after window_end (tolerance for a 1.0s
    // window is max(1ms, min(10ms, 1% * 1.0s)) = 10ms) -> late_boundary, but
    // the byte delta is still folded into the cumulative total.
    script.Step(true, 3000);
    a.AddTcpStreamIoBytes(0, ProtoTime(21.5));
    a.FinalizeRxWindow(true, ProtoTime(22.02));
    CHECK(MgenAnalytic::TCP_STREAM_LATE_BOUNDARY == a.GetReportTcpStreamReason());
    CHECK(!a.GetReportTcpStreamValid());
    CHECK(0 == a.GetReportTcpStreamBytes());          // no direct measurement
    CHECK(3000ULL == a.GetReportTcpStreamTotalBytes()); // but the delta is not lost

    // window 3: caller reports this flush as catching up more than one full
    // window late (sampleTcpStream=false) -> missed_boundaries, again still
    // conserving the byte delta.
    script.Step(true, 5000);
    a.AddTcpStreamIoBytes(0, ProtoTime(22.5));
    a.FinalizeRxWindow(false, ProtoTime(24.5));
    CHECK(MgenAnalytic::TCP_STREAM_MISSED_BOUNDARIES == a.GetReportTcpStreamReason());
    CHECK(!a.GetReportTcpStreamValid());
    CHECK((3000ULL + 2000ULL) == a.GetReportTcpStreamTotalBytes());  // 3000 + (5000-3000)
}

// ---- Test 15: cumulative total is lossless across mixed-reason windows ----
static void test_tcp_stream_cumulative_conservation()
{
    printf("test_tcp_stream_cumulative_conservation\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));

    ProtoSocket sock(ProtoSocket::TCP);
    FakeConnect(sock);
    TcpQueueScript script;
    script.Step(true, 0);  // SetTcpStream() baseline
    a.SetTcpQueueQueryFuncForTest(ScriptedQueueQuery, &script);
    a.SetTcpStream(&sock, true, true);

    script.Step(true, 0);
    a.AddTcpStreamIoBytes(0, ProtoTime(30.0));
    a.FinalizeTxWindow(true, ProtoTime(31.0));  // initial_baseline

    unsigned long long expectedTotal = 0;
    // Mix of on-time, late, and missed windows -- every queue-observed delta
    // (queue drains fully each window here, so streamBytes == bytes added)
    // must still land in the running total exactly once.
    struct { unsigned long long bytes; bool onTime; double sampleTime; } steps[] = {
        {1000, true,  32.0},   // on time -> ok
        {2500, true,  33.02},  // 20ms late -> late_boundary
        {4000, false, 35.5},   // caller says missed -> missed_boundaries
        {  50, true,  36.0},   // back on time -> ok
    };
    for (int i = 0; i < 4; i++)
    {
        script.Step(true, 0);  // queue fully drains back to 0 each window
        a.AddTcpStreamIoBytes(steps[i].bytes, ProtoTime(steps[i].sampleTime - 0.1));
        a.FinalizeTxWindow(steps[i].onTime, ProtoTime(steps[i].sampleTime));
        expectedTotal += steps[i].bytes;
        CHECK(expectedTotal == a.GetReportTcpStreamTotalBytes());
    }
}

// ---- Test 16: sample id is monotonic and frozen across ioctl failures -----
static void test_tcp_stream_sample_id_monotonic()
{
    printf("test_tcp_stream_sample_id_monotonic\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));

    ProtoSocket sock(ProtoSocket::TCP);
    FakeConnect(sock);
    TcpQueueScript script;
    script.Step(true, 0);  // SetTcpStream() baseline
    a.SetTcpQueueQueryFuncForTest(ScriptedQueueQuery, &script);
    a.SetTcpStream(&sock, true, true);

    script.Step(true, 0);
    a.AddTcpStreamIoBytes(0, ProtoTime(40.0));
    a.FinalizeTxWindow(true, ProtoTime(41.0));
    UINT32 id1 = a.GetReportTcpStreamSampleId();

    script.Step(true, 0);
    a.AddTcpStreamIoBytes(100, ProtoTime(41.5));
    a.FinalizeTxWindow(true, ProtoTime(42.0));
    UINT32 id2 = a.GetReportTcpStreamSampleId();
    CHECK(id2 > id1);

    // A failed ioctl does not consume/advance the sample id.
    script.Step(false, 0);
    a.AddTcpStreamIoBytes(100, ProtoTime(42.5));
    a.FinalizeTxWindow(true, ProtoTime(43.0));
    CHECK(MgenAnalytic::TCP_STREAM_IOCTL_FAILED == a.GetReportTcpStreamReason());
    CHECK(id2 == a.GetReportTcpStreamSampleId());

    // Recovery: the next successful sample gets a new, larger id.
    script.Step(true, 0);
    a.AddTcpStreamIoBytes(100, ProtoTime(43.5));
    a.FinalizeTxWindow(true, ProtoTime(44.0));
    CHECK(a.GetReportTcpStreamSampleId() > id2);
}

// ---- Test 17: transient ioctl failure preserves the delta for recovery ----
static void test_tcp_stream_ioctl_failed_recovery()
{
    printf("test_tcp_stream_ioctl_failed_recovery\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));

    ProtoSocket sock(ProtoSocket::TCP);
    FakeConnect(sock);
    TcpQueueScript script;
    script.Step(true, 0);  // SetTcpStream() baseline
    a.SetTcpQueueQueryFuncForTest(ScriptedQueueQuery, &script);
    a.SetTcpStream(&sock, true, true);

    script.Step(true, 0);
    a.AddTcpStreamIoBytes(0, ProtoTime(50.0));
    a.FinalizeTxWindow(true, ProtoTime(51.0));  // initial_baseline
    CHECK(0 == a.GetReportTcpStreamTotalBytes());

    // Window with a failed ioctl: 1000 bytes are successfully written at the
    // socket layer (AddTcpStreamIoBytes), but the queue can't be sampled.
    // The prior queue snapshot must NOT be advanced, so this interval's
    // bytes are not lost -- they get folded into the next successful delta.
    script.Step(false, 0);
    a.AddTcpStreamIoBytes(1000, ProtoTime(51.5));
    a.FinalizeTxWindow(true, ProtoTime(52.0));
    CHECK(MgenAnalytic::TCP_STREAM_IOCTL_FAILED == a.GetReportTcpStreamReason());
    CHECK(0 == a.GetReportTcpStreamTotalBytes());  // nothing resolved yet

    // Recovery: another 500 bytes written, queue drains to 0.  The resolved
    // delta must cover the FULL 1500 bytes accumulated since the last
    // successful snapshot (window 1's baseline), not just the most recent
    // window's 500.
    script.Step(true, 0);
    a.AddTcpStreamIoBytes(500, ProtoTime(52.5));
    a.FinalizeTxWindow(true, ProtoTime(53.0));
    CHECK(1500ULL == a.GetReportTcpStreamTotalBytes());
}

// ---- Test 18: impossible queue/IO pairing is flagged, not clamped to zero -
static void test_tcp_stream_counter_inconsistent()
{
    printf("test_tcp_stream_counter_inconsistent\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));

    ProtoSocket sock(ProtoSocket::TCP);
    FakeConnect(sock);
    TcpQueueScript script;
    script.Step(true, 0);  // SetTcpStream() baseline
    a.SetTcpQueueQueryFuncForTest(ScriptedQueueQuery, &script);
    a.SetTcpStream(&sock, true /*TX*/, true);

    script.Step(true, 0);
    a.AddTcpStreamIoBytes(0, ProtoTime(60.0));
    a.FinalizeTxWindow(true, ProtoTime(61.0));  // initial_baseline

    // TX queue growth (5000) exceeds recorded writes (100): not a coherent
    // pairing.  Must be reported as counter_inconsistent, not clamped to 0
    // and silently accepted as a "valid" empty window.
    script.Step(true, 5000);
    a.AddTcpStreamIoBytes(100, ProtoTime(61.5));
    a.FinalizeTxWindow(true, ProtoTime(62.0));
    CHECK(MgenAnalytic::TCP_STREAM_COUNTER_INCONSISTENT == a.GetReportTcpStreamReason());
    CHECK(!a.GetReportTcpStreamValid());
    CHECK(0 == a.GetReportTcpStreamTotalBytes());  // interval not folded in

    // Rebaseline at the inconsistent sample (queue=5000): a subsequent
    // coherent delta resolves normally from there.
    script.Step(true, 5000);
    a.AddTcpStreamIoBytes(200, ProtoTime(62.5));
    a.FinalizeTxWindow(true, ProtoTime(63.0));
    CHECK(MgenAnalytic::TCP_STREAM_OK == a.GetReportTcpStreamReason());
    CHECK(200ULL == a.GetReportTcpStreamTotalBytes());
}

// ---- Test 19: socket replacement isolates generation and cumulative total -
static void test_tcp_stream_generation_isolation()
{
    printf("test_tcp_stream_generation_isolation\n");
    MgenAnalytic a;
    CHECK(InitAnalytic(a));

    ProtoSocket sockA(ProtoSocket::TCP);
    FakeConnect(sockA);
    TcpQueueScript scriptA;
    scriptA.Step(true, 0);  // SetTcpStream() baseline
    a.SetTcpQueueQueryFuncForTest(ScriptedQueueQuery, &scriptA);
    a.SetTcpStream(&sockA, true, true);
    CHECK(0 == a.GetReportTcpStreamGeneration());

    scriptA.Step(true, 0);
    a.AddTcpStreamIoBytes(0, ProtoTime(70.0));
    a.FinalizeTxWindow(true, ProtoTime(71.0));  // initial_baseline on generation 0

    scriptA.Step(true, 0);
    a.AddTcpStreamIoBytes(900, ProtoTime(71.5));
    a.FinalizeTxWindow(true, ProtoTime(72.0));
    CHECK(900ULL == a.GetReportTcpStreamTotalBytes());
    CHECK(0 == a.GetReportTcpStreamGeneration());

    // Socket is torn down (detached) and replaced -- a genuine reconnect.
    // No queue arithmetic may cross this boundary: generation increments
    // and the cumulative total restarts at 0.
    a.ClearTcpStreamSocket();
    ProtoSocket sockB(ProtoSocket::TCP);
    FakeConnect(sockB);
    TcpQueueScript scriptB;
    scriptB.Step(true, 0);  // SetTcpStream() baseline on the new socket
    a.SetTcpQueueQueryFuncForTest(ScriptedQueueQuery, &scriptB);
    a.SetTcpStream(&sockB, true, true);
    // GetReportTcpStreamGeneration()/TotalBytes() are report-time snapshots
    // updated only by FinalizeTcpStream(), so the generation bump isn't
    // observable via those getters until the next Finalize call below.

    scriptB.Step(true, 0);
    a.AddTcpStreamIoBytes(0, ProtoTime(73.0));
    a.FinalizeTxWindow(true, ProtoTime(74.0));
    CHECK(MgenAnalytic::TCP_STREAM_INITIAL_BASELINE == a.GetReportTcpStreamReason());
    CHECK(1 == a.GetReportTcpStreamGeneration());

    scriptB.Step(true, 0);
    a.AddTcpStreamIoBytes(300, ProtoTime(74.5));
    a.FinalizeTxWindow(true, ProtoTime(75.0));
    CHECK(300ULL == a.GetReportTcpStreamTotalBytes());  // generation 0's 900 not carried over
    CHECK(1 == a.GetReportTcpStreamGeneration());
}

// ---- Test 20: disabled-attribution and disconnected reasons ---------------
static void test_tcp_stream_disabled_reasons()
{
    printf("test_tcp_stream_disabled_reasons\n");

    // Shared socket: attribution disabled with an explicit reason.
    {
        MgenAnalytic a;
        CHECK(InitAnalytic(a));
        ProtoSocket sock(ProtoSocket::TCP);
        FakeConnect(sock);
        TcpQueueScript script;
        script.Step(true, 0);
        a.SetTcpQueueQueryFuncForTest(ScriptedQueueQuery, &script);
        a.SetTcpStream(&sock, false, true);
        // Start the window (AddTcpStreamIoBytes early-returns once
        // attribution is disabled) before disabling attribution, matching
        // the real sequence: data is already flowing when the shared-socket
        // condition is discovered.
        a.AddTcpStreamIoBytes(0, ProtoTime(80.0));
        a.DisableTcpStreamAttribution(MgenAnalytic::TCP_STREAM_SHARED_SOCKET);
        a.FinalizeRxWindow(true, ProtoTime(81.0));
        CHECK(MgenAnalytic::TCP_STREAM_SHARED_SOCKET == a.GetReportTcpStreamReason());
        CHECK(!a.GetReportTcpStreamValid());
    }

    // Checksummed flow: attribution disabled with a distinct reason.
    {
        MgenAnalytic a;
        CHECK(InitAnalytic(a));
        ProtoSocket sock(ProtoSocket::TCP);
        FakeConnect(sock);
        TcpQueueScript script;
        script.Step(true, 0);
        a.SetTcpQueueQueryFuncForTest(ScriptedQueueQuery, &script);
        a.SetTcpStream(&sock, false, true);
        a.AddTcpStreamIoBytes(0, ProtoTime(80.0));
        a.DisableTcpStreamAttribution(MgenAnalytic::TCP_STREAM_CHECKSUM_AMBIGUOUS);
        a.FinalizeRxWindow(true, ProtoTime(81.0));
        CHECK(MgenAnalytic::TCP_STREAM_CHECKSUM_AMBIGUOUS == a.GetReportTcpStreamReason());
        CHECK(!a.GetReportTcpStreamValid());
    }

    // No socket ever attached: disconnected, not a silent zero.
    {
        MgenAnalytic a;
        CHECK(InitAnalytic(a));
        a.SetTcpStream(NULL, true, true);
        a.AddTcpStreamIoBytes(0, ProtoTime(80.0));
        a.FinalizeTxWindow(true, ProtoTime(81.0));
        CHECK(MgenAnalytic::TCP_STREAM_DISCONNECTED == a.GetReportTcpStreamReason());
        CHECK(!a.GetReportTcpStreamValid());
    }
}

// ---- Test 12: SetWindowSize honors the quantize flag ----------------------
static void test_set_window_size_quantize()
{
    printf("test_set_window_size_quantize\n");
    // Exact window when quantize == false
    MgenAnalytic a;
    CHECK(InitAnalytic(a));
    a.SetWindowSize(2.0, false);
    a.TxUpdate(100, ProtoTime(10.0), 0);
    a.FinalizeTxWindow();
    CHECK_NEAR(a.GetReportDuration(), 2.0, 1e-9);        // exact, not quantized
    // Quantized window when quantize == true (1.0 -> 1.011211)
    MgenAnalytic b;
    CHECK(InitAnalytic(b));
    b.SetWindowSize(1.0, true);
    b.TxUpdate(100, ProtoTime(10.0), 0);
    b.FinalizeTxWindow();
    CHECK_NEAR(b.GetReportDuration(), 1.011211, 1e-4);   // snapped to grid
}

int main(int /*argc*/, char* /*argv*/[])
{
    printf("mgenAnalyticTest: running...\n");
    test_boundary_alignment();
    test_window_elapsed();
    test_tx_message_rate();
    test_tx_gap_fill();
    test_rx_basic();
    test_rx_loss_gap();
    test_rx_loss_regression_across_windows();
    test_rx_empty_window();
    test_rx_duplicate();
    test_table_separation();
    test_tcp_stream_bytes();
    test_tcp_stream_direct_window();
    test_tcp_stream_late_and_missed_boundary();
    test_tcp_stream_cumulative_conservation();
    test_tcp_stream_sample_id_monotonic();
    test_tcp_stream_ioctl_failed_recovery();
    test_tcp_stream_counter_inconsistent();
    test_tcp_stream_generation_isolation();
    test_tcp_stream_disabled_reasons();
    test_set_window_size_quantize();

    printf("\nmgenAnalyticTest: %d checks, %d failure(s)\n", checks, failures);
    if (0 != failures)
    {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}  // end main()
