/*********************************************************************
 *
 * AUTHORIZATION TO USE AND DISTRIBUTE
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: 
 *
 * (1) source code distributions retain this paragraph in its entirety, 
 *  
 * (2) distributions including binary code include this paragraph in
 *     its entirety in the documentation or other materials provided 
 *     with the distribution, and 
 *
 * (3) all advertising materials mentioning features or use of this 
 *     software display the following acknowledgment:
 * 
 *      "This product includes software written and developed 
 *       by Brian Adamson and Joe Macker of the Naval Research 
 *       Laboratory (NRL)." 
 *         
 *  The name of NRL, the name(s) of NRL  employee(s), or any entity
 *  of the United States Government may not be used to endorse or
 *  promote  products derived from this software, nor does the 
 *  inclusion of the NRL written and developed software  directly or
 *  indirectly suggest NRL or United States  Government endorsement
 *  of this product.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 ********************************************************************/

#ifndef _MGEN_GLOBALS
#define _MGEN_GLOBALS

#ifdef WIN32
#include <windows.h>
#else
#include <time.h>
#endif  // if/else WIN32

enum LogEventType
  {
    INVALID_EVENT = 0,
    RECV_EVENT,
    RERR_EVENT,
    SEND_EVENT,
    LISTEN_EVENT,
    IGNORE_EVENT,
    JOIN_EVENT,
    LEAVE_EVENT,
    START_EVENT,
    STOP_EVENT,
    ON_EVENT,
    ACCEPT_EVENT,
    DISCONNECT_EVENT,
    CONNECT_EVENT,
    OFF_EVENT,
    SHUTDOWN_EVENT,
    RECONNECT_EVENT

  };

/**
 * Possible protocol types 
 */
enum Protocol
  {
    INVALID_PROTOCOL,
    UDP,
    TCP,
    SINK,
    SOURCE  // pseudo transport type so an mgen can have distinct source/sink transports
  }; 

enum 
  {
    MIN_SIZE = 28,
    MAX_SIZE = 8192,
    MSG_LEN_SIZE = 2,
    // TX_BUFFER_SIZE is the tcp tx buffer size, for now same as udp max_size
    TX_BUFFER_SIZE = 8192,
    MAX_FRAG_SIZE = 65535, // TCP max fragment size
    MIN_FRAG_SIZE = 76     // ljt what should this be? 
                           // we're going with IPV6 + gps max for now
  };
enum FragmentationStatus
{
   // We pass df to protoSockets setFragmentation() method which
   // reverses the bit setting.  

    DF_ON,      // setFragmentation(false) = do not allow fragmentation set DF bit OFF
    DF_OFF,     // setFragmentation(true) = allow fragmentation set DF bit ON
    DF_DEFAULT // leave socket DF option in its default state

};

enum MessageStatus
  {
    MSG_SEND_FAILED,
    MSG_SEND_BLOCKED,
    MSG_SEND_OK

  };

// TCP dispatch-loop fairness: bounds how long an unlimited-rate TCP flow's
// send/recv work can run inside a single dispatcher callback so it cannot
// delay the once-per-second analytics report boundary.  See
// MgenDispatchBudget below.
const double       MGEN_DISPATCH_BUDGET_SECONDS = 0.002;      // 2 ms wall-clock slice
const unsigned int MGEN_DISPATCH_BUDGET_OPS = 64;             // completed-op cap
const double       MGEN_ANALYTIC_BOUNDARY_THRESHOLD = 0.001;  // yield-ahead margin

/**
 * Returns a monotonic clock reading in seconds, immune to system clock
 * steps (NTP, manual adjustment).  Used only to measure elapsed time for
 * MgenDispatchBudget; unlike ProtoTime/ProtoSystemTime it is not tied to
 * wall-clock epoch and must not be used for reporting or logging.
 */
inline double MgenMonotonicSeconds()
{
#ifdef WIN32
    static LARGE_INTEGER frequency = {0};
    if (0 == frequency.QuadPart)
        QueryPerformanceFrequency(&frequency);
    LARGE_INTEGER count;
    QueryPerformanceCounter(&count);
    return (double)count.QuadPart / (double)frequency.QuadPart;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (1.0e-09 * (double)ts.tv_nsec);
#endif  // if/else WIN32
}  // end MgenMonotonicSeconds()

/**
 * @class MgenDispatchBudget
 *
 * @brief Bounds one dispatcher callback's TCP send/recv work loop by both a
 * wall-clock time slice and a completed-operation count.  Without this,
 * an unlimited-rate TCP flow's send or receive loop can monopolize the
 * single Protolib dispatcher callback long enough to skip a one-second
 * analytics report boundary, corrupting stream byte accounting.
 */
class MgenDispatchBudget
{
    public:
        // Test-only seam: when set, used instead of MgenMonotonicSeconds()
        // to obtain "now" for expiry checks.  This overrides the clock for
        // ALL MgenDispatchBudget instances -- there is no per-instance
        // state to distinguish, and production code constructs a fresh
        // budget per dispatcher callback rather than holding one across
        // calls.  NULL (the default) restores the real monotonic clock.
        typedef double (*ClockFunc)();
        static void SetClockFuncForTest(ClockFunc func) {clock_func = func;}

        MgenDispatchBudget()
          : active(false), op_count(0), op_limit(0), deadline(0.0) {}

        void Start(double wallClockBudgetSeconds, unsigned int opLimit)
        {
            active = true;
            op_count = 0;
            op_limit = opLimit;
            deadline = Now() + wallClockBudgetSeconds;
        }

        void RecordOp() {op_count++;}

        bool IsExpired() const
        {
            if (!active) return false;
            if ((op_limit > 0) && (op_count >= op_limit)) return true;
            return Now() >= deadline;
        }

    private:
        static double Now()
        {
            return (NULL != clock_func) ? clock_func() : MgenMonotonicSeconds();
        }

        bool          active;
        unsigned int  op_count;
        unsigned int  op_limit;
        double        deadline;
        static ClockFunc clock_func;
};  // end class MgenDispatchBudget

#endif // _MGEN_GLOBALS
