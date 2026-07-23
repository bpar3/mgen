/*
 * mgenDispatchBudgetTest - standalone unit tests for MgenDispatchBudget, the
 * TCP dispatch-loop fairness mechanism (Phase 1 of the TCP stream analytics
 * work): a shared work budget, bounded by both a wall-clock time slice and a
 * completed-operation count, that MgenTransport::SendPendingMessage() and
 * MgenTcpTransport::OnEvent()'s SEND/RECV loops use to yield back to
 * ProtoDispatcher instead of monopolizing the callback and delaying the
 * once-per-second analytics report boundary.
 *
 * This is a plain assertion-based driver in the style of protolib's
 * examples/unitTests.cpp and mgenAnalyticTest.cpp (MGEN has no unit-test
 * framework). Real elapsed-time behavior is exercised via
 * MgenDispatchBudget::SetClockFuncForTest(), a test-only seam that
 * overrides the monotonic clock so the wall-clock slice is deterministic
 * and the tests need no sleeping. NULL (the default) leaves production
 * code on the real monotonic clock, untouched by these tests.
 *
 * Build:  make -f Makefile.linux mgenDispatchBudgetTest
 * Run:    ./mgenDispatchBudgetTest        (exit 0 = all pass)
 */

#include "mgenGlobals.h"

#include <stdio.h>

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

// ---- Scripted clock: a fixed "now" that tests advance explicitly ----------
static double fake_now = 0.0;
static double FakeClock() {return fake_now;}

// Resets the shared fake clock and re-installs it.  Called at the top of
// every test so tests don't depend on execution order.
static void ResetFakeClock(double startTime)
{
    fake_now = startTime;
    MgenDispatchBudget::SetClockFuncForTest(FakeClock);
}

// ---- Test 1: an inactive (never-Start()ed) budget never expires -----------
static void test_inactive_budget_never_expires()
{
    printf("test_inactive_budget_never_expires\n");
    ResetFakeClock(100.0);
    MgenDispatchBudget budget;
    CHECK(!budget.IsExpired());
    fake_now += 1000.0;  // even a huge elapsed time doesn't matter pre-Start()
    CHECK(!budget.IsExpired());
}

// ---- Test 2: wall-clock slice expiry ---------------------------------------
static void test_time_slice_expiry()
{
    printf("test_time_slice_expiry\n");
    ResetFakeClock(200.0);
    MgenDispatchBudget budget;
    budget.Start(0.002 /*2ms*/, 64);
    CHECK(!budget.IsExpired());          // just started
    fake_now += 0.001;                   // 1ms elapsed: still within budget
    CHECK(!budget.IsExpired());
    fake_now += 0.0009;                  // 1.9ms elapsed: still just under
    CHECK(!budget.IsExpired());
    fake_now += 0.0002;                  // 2.1ms elapsed: budget spent
    CHECK(budget.IsExpired());
}

// ---- Test 3: op-count cap expiry, independent of elapsed time -------------
static void test_op_count_expiry()
{
    printf("test_op_count_expiry\n");
    ResetFakeClock(300.0);
    MgenDispatchBudget budget;
    budget.Start(10.0 /*generous time budget*/, 3);
    CHECK(!budget.IsExpired());
    budget.RecordOp();
    CHECK(!budget.IsExpired());
    budget.RecordOp();
    CHECK(!budget.IsExpired());
    budget.RecordOp();                   // 3rd op hits the cap
    CHECK(budget.IsExpired());
    // Recording further ops (as SendPendingMessage()'s loop would, if it
    // checked IsExpired() one iteration late) must not un-expire it.
    budget.RecordOp();
    CHECK(budget.IsExpired());
}

// ---- Test 4: whichever guard trips first governs ---------------------------
static void test_first_guard_wins()
{
    printf("test_first_guard_wins\n");

    // Time budget is tiny; op cap is generous -> time trips first.
    ResetFakeClock(400.0);
    MgenDispatchBudget a;
    a.Start(0.001, 1000);
    CHECK(!a.IsExpired());
    fake_now += 0.0015;
    CHECK(a.IsExpired());

    // Op cap is tiny; time budget is generous -> op count trips first.
    ResetFakeClock(400.0);
    MgenDispatchBudget b;
    b.Start(10.0, 1);
    CHECK(!b.IsExpired());
    b.RecordOp();
    CHECK(b.IsExpired());
    fake_now += 0.0001;  // time budget alone would not have expired yet
    CHECK(b.IsExpired());
}

// ---- Test 5: a fresh Start() resets both guards, mid-flight ---------------
static void test_restart_resets_state()
{
    printf("test_restart_resets_state\n");
    ResetFakeClock(500.0);
    MgenDispatchBudget budget;
    budget.Start(0.002, 2);
    budget.RecordOp();
    budget.RecordOp();
    CHECK(budget.IsExpired());           // op cap hit

    // A new callback re-uses the same local variable's lifetime pattern in
    // production (a fresh MgenDispatchBudget per SendPendingMessage()/
    // OnEvent() invocation), but this test also confirms explicit re-Start()
    // clears prior op_count/deadline state rather than accumulating it.
    budget.Start(0.002, 2);
    CHECK(!budget.IsExpired());
    fake_now += 0.0025;
    CHECK(budget.IsExpired());           // new deadline, not the old one
}

// ---- Test 6: zero op-limit means "no op-count guard", time-only -----------
static void test_zero_op_limit_disables_op_guard()
{
    printf("test_zero_op_limit_disables_op_guard\n");
    ResetFakeClock(600.0);
    MgenDispatchBudget budget;
    budget.Start(0.002, 0);
    for (int i = 0; i < 1000000; i++)
        budget.RecordOp();
    CHECK(!budget.IsExpired());          // op count never gates when limit==0
    fake_now += 0.0025;
    CHECK(budget.IsExpired());           // only the time slice governs
}

// ---- Test 7: real (unmocked) clock exercises the production code path -----
// Confirms SetClockFuncForTest(NULL) restores MgenMonotonicSeconds(), i.e.
// production behavior is unaffected by having a test-only seam at all.
static void test_real_clock_after_reset()
{
    printf("test_real_clock_after_reset\n");
    MgenDispatchBudget::SetClockFuncForTest(NULL);
    MgenDispatchBudget budget;
    budget.Start(60.0, 1000);            // generous real-time budget
    CHECK(!budget.IsExpired());          // true "now" is nowhere near 60s later
}

int main(int /*argc*/, char* /*argv*/[])
{
    printf("mgenDispatchBudgetTest: running...\n");
    test_inactive_budget_never_expires();
    test_time_slice_expiry();
    test_op_count_expiry();
    test_first_guard_wins();
    test_restart_resets_state();
    test_zero_op_limit_disables_op_guard();
    test_real_clock_after_reset();

    printf("\nmgenDispatchBudgetTest: %d checks, %d failure(s)\n", checks, failures);
    if (0 != failures)
    {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}  // end main()
