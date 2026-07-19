/*
 * mgenAnalyticTest - standalone unit tests for MgenAnalytic window
 * accumulation / finalization logic (the timer-driven, whole-second-aligned
 * TX/RX analytics and the txWireRate drain accounting).
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

// ---- Test 3: TX offered-load rate & count over one window ------------------
static void test_tx_offered_rate()
{
    printf("test_tx_offered_rate\n");
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

// ---- Test 11: wire-rate drain arithmetic (ComputeDrainedBytes) -------------
static void test_compute_drained_bytes()
{
    printf("test_compute_drained_bytes\n");
    // Steady state: everything written this window drained (queue unchanged)
    CHECK(MgenAnalytic::ComputeDrainedBytes(10000, 0) == 10000);
    // Buffer grew: offered 10000, but 4000 still sitting in the queue -> 6000 on wire
    CHECK(MgenAnalytic::ComputeDrainedBytes(10000, 4000) == 6000);
    // Buffer shrank: wrote 2000 this window, queue drained an extra 3000 -> 5000 on wire
    CHECK(MgenAnalytic::ComputeDrainedBytes(2000, -3000) == 5000);
    // Clamp: queue grew more than we wrote -> 0 (never a negative/underflowed rate)
    CHECK(MgenAnalytic::ComputeDrainedBytes(1000, 5000) == 0);
}

int main(int /*argc*/, char* /*argv*/[])
{
    printf("mgenAnalyticTest: running...\n");
    test_boundary_alignment();
    test_window_elapsed();
    test_tx_offered_rate();
    test_tx_gap_fill();
    test_rx_basic();
    test_rx_loss_gap();
    test_rx_loss_regression_across_windows();
    test_rx_empty_window();
    test_rx_duplicate();
    test_table_separation();
    test_compute_drained_bytes();

    printf("\nmgenAnalyticTest: %d checks, %d failure(s)\n", checks, failures);
    if (0 != failures)
    {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}  // end main()
