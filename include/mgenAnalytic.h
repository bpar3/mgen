#ifndef _MGEN_ANALYTIC
#define _MGEN_ANALYTIC

#include "protoQueue.h"
#include "protoTime.h"
#include "protoAddress.h"
#include "protoBitmask.h"
#include "protoPkt.h"
#include "mgenGlobals.h"  // for Protocol types
#include "mgenPayload.h"

#include <math.h>  // for fabs()

class ProtoSocket;  // forward declaration for TCP stream queue sampling

// MGEN_DATA analytic report format
// 
//       0                   1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      | type  | proto |      len      |flags|      windowOffset       |  
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                          dstAddr ...                          +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |                                                               |
//      +                          srcAddr ...                          +
//      |                                                               |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |             dstPort           |            srcPort            |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
//      |                       flowID  (optional)                      |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//      |   windowSize   |   latencyAve |  latencyMin   |  latencyMax   |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
//      |            rateAve            |          lossFraction         |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//
//  type        - report message type 
//  proto       - transport protocol type
//  len         - message length in bytes
//  flags:
//      FLAG_FLOW_ID indicates report contains optional flowID field
//      FLAG_LATENCY_SIGN indicates "latencyAve" is a negative value
//  alen - length of address fields (in bytes) minus one (i.e. range of 1 - 16 bytes)
//  windowId     - window offset relative to MGEN txTime timestamp (offset = windowOffset*windowSize)
//  dstAddr      - flow dest addr.
//  srcAddr      - flow src addr
//  dstPort      - flow dst port
//  srcPort      - flow src port
//  flowId       - 32-bit MGEN flow id (optional field)  
//  windowSize   - duration of measurement time window for this report*
//  latencyAve   - measured average message latency for given window
//  latencyMin   - minimum observed message latency for given window (negative offset from average)
//  latencyMax   - maximum observed message latency for given window (positive offset from average)
//  rateAve      - measured flow rx rate for given measurement window
//  lossFraction - measured message loss rate during measurement window


// Per-flow statistics tracking for rate, loss, and latency
// where a flow is identified by src addr/port : dst addr/port 
// and MGEN flowId

class MgenAnalytic : public ProtoQueue::Item
{
    public:
        static const double DEFAULT_WINDOW;      
        enum {DEFAULT_HISTORY = 1024};  // default duplicate message detection history depth
            
        MgenAnalytic();
        ~MgenAnalytic();
        
        class Report;  // forward declaration
       
        
        // Init() MUST be called before analytic can be updated
        bool Init(Protocol               protocol,
                  const ProtoAddress&    srcAddr,
                  const ProtoAddress&    dstAddr,
                  UINT32                 flowId,
                  bool                   windowQuantize,
                  double                 windowSize = MgenAnalytic::DEFAULT_WINDOW,
                  UINT32                 historyDepth = MgenAnalytic::DEFAULT_HISTORY);
        
        // When "quantize" is true (default), the window is snapped to MGEN's
        // compact time encoding; when false, the exact value is used (honors
        // the "quantizeWindow off" global for local measurement/logging).
        void SetWindowSize(double windowSize, bool quantize = true)
        {
            if (quantize)
            {
                UINT8 q = Report::QuantizeTimeValue(windowSize);
                window_size = MgenAnalytic::Report::UnquantizeTimeValue(q);
            }
            else if (windowSize > 0.0)
            {
                window_size = windowSize;
            }
        }
        
        // Accumulate a transmitted message into the current window.
        // Window boundaries are aligned to integral multiples of
        // "window_size" and rolling / report emission are driven by
        // the analytic timer via FinalizeTxWindow().  The return
        // value is retained for backward compatibility, but is
        // always "false" in timer-driven mode.
        bool TxUpdate(unsigned int     msgSize = 0,
                      const ProtoTime& txTime = ProtoTime(0.0),
                      UINT32           seqNum = 0);

        void TxLog(FILE*            filePtr,
                 const ProtoTime& txTime,
                 bool             localTime) const;

        // Accumulate a received message into the current window.
        // Window boundaries are aligned to integral multiples of
        // "window_size" and rolling / report emission are driven by
        // the analytic timer via FinalizeRxWindow().  The return
        // value is retained for backward compatibility, but is
        // always "false" in timer-driven mode.
        bool Update(const ProtoTime& rxTime,
                    unsigned int     msgSize = 0,
                    const ProtoTime& txTime = ProtoTime(0.0),
                    UINT32           seqNum = 0);

        void Log(FILE*            filePtr,
                 const ProtoTime& sentTime,
                 const ProtoTime& theTime,
                 bool             localTime) const;

        // Finalize the current window into the "report_*" results (and the
        // report_msg buffer), then reset counts and advance the window by
        // one window_size.  Called once per elapsed window by the timer.
        // "sampleTime" is the actual wall-clock time of this flush (not the
        // nominal window boundary); a zero/default ProtoTime means "assume
        // on-time" and falls back to the window's own end time, which is
        // what the analytic unit tests exercise.
        void FinalizeTxWindow(bool sampleTcpStream = true,
                              const ProtoTime& sampleTime = ProtoTime());
        void FinalizeRxWindow(bool sampleTcpStream = true,
                              const ProtoTime& sampleTime = ProtoTime());

        // True when the current window has fully elapsed as of "now"
        bool WindowElapsed(const ProtoTime& now) const
            {return (window_valid && (now >= window_end));}
        bool HasWindow() const
            {return window_valid;}

        // Stable diagnostic reason for a TCP stream sample's valid/invalid
        // nominal-window state.  Independent of whether the cumulative
        // total could still be advanced for the same window (see
        // GetReportTcpStreamReason() vs GetReportTcpStreamValid()).
        enum TcpStreamReason
        {
            TCP_STREAM_OK = 0,
            TCP_STREAM_INITIAL_BASELINE,
            TCP_STREAM_LATE_BOUNDARY,
            TCP_STREAM_MISSED_BOUNDARIES,
            TCP_STREAM_IOCTL_FAILED,
            TCP_STREAM_DISCONNECTED,
            TCP_STREAM_SOCKET_CHANGED,
            TCP_STREAM_SHARED_SOCKET,
            TCP_STREAM_CHECKSUM_AMBIGUOUS,
            TCP_STREAM_COUNTER_INCONSISTENT,
            TCP_STREAM_UNSUPPORTED
        };
        static const char* GetTcpStreamReasonString(TcpStreamReason reason);

        // Test-only seam: when set, used instead of the real
        // SIOCOUTQNSD/SIOCINQ ioctl() call to obtain the current queue
        // depth for this direction.  Production code (the default, NULL)
        // is unaffected; unit tests use this to deterministically drive
        // queue values, failures, and inconsistencies without depending on
        // real kernel timing over a live socket.  Returns false to
        // simulate an ioctl() failure.
        typedef bool (*TcpQueueQueryFunc)(void* userData, bool isTx, int& queueValue);
        void SetTcpQueueQueryFuncForTest(TcpQueueQueryFunc func, void* userData = NULL)
        {
            tcp_queue_query_func = func;
            tcp_queue_query_user_data = userData;
        }

        // TCP stream accounting is separate from complete-message analytics.
        // TX counts successful socket writes and samples SIOCOUTQNSD; RX counts
        // successful reads and samples SIOCINQ.
        void SetTcpStream(ProtoSocket* theSocket, bool isTx, bool enabled,
                          bool includeQueuedBytes = false);
        void ClearTcpStreamSocket();
        void DisableTcpStreamAttribution(TcpStreamReason reason = TCP_STREAM_SHARED_SOCKET)
        {
            tcp_stream_attributable = false;
            tcp_stream_disabled_reason = reason;
        }
        ProtoSocket* GetTcpStreamSocket() const
            {return tcp_stream_socket;}
        void AddTcpStreamIoBytes(unsigned long long byteCount,
                                 const ProtoTime& eventTime);

        static unsigned long long ComputeTxStreamBytes(unsigned long long ioDelta,
                                                       long long queueDelta)
        {
            long long streamBytes = (long long)ioDelta - queueDelta;
            return (streamBytes > 0) ? (unsigned long long)streamBytes : 0;
        }
        static unsigned long long ComputeRxStreamBytes(unsigned long long ioDelta,
                                                       long long queueDelta)
        {
            long long streamBytes = (long long)ioDelta + queueDelta;
            return (streamBytes > 0) ? (unsigned long long)streamBytes : 0;
        }

        const Report& GetReport(const ProtoTime& theTime);
        const ProtoTime& GetReportTime() const
            {return report_time;}

        const ProtoTime& GetWindowEnd() const
            {return window_end;}
        
        const ProtoTime& GetReportStartTime() const
            {return report_start;}
        double GetReportDuration() const
            {return report_duration;}
        unsigned long GetReportMessageCount() const
            {return report_msg_count;}
        double GetReportRateAverage() const     // bytes/sec
            {return report_rate_ave;}
        double GetReportLossFraction() const 
            {return report_loss_ave;}
        double GetReportLatencyAverage() const  // in seconds
            {return report_latency_ave;}
        double GetReportLatencyMin() const      // in seconds
            {return report_latency_min;}
        double GetReportLatencyMax() const      // in seconds
            {return report_latency_max;}
        bool GetReportTcpStreamValid() const
            {return report_tcp_stream_valid;}
        double GetReportTcpStreamRateAverage() const  // bytes/sec
            {return report_tcp_stream_rate_ave;}
        unsigned long long GetReportTcpStreamBytes() const
            {return report_tcp_stream_bytes;}
        TcpStreamReason GetReportTcpStreamReason() const
            {return report_tcp_stream_reason;}
        unsigned long long GetReportTcpStreamTotalBytes() const
            {return report_tcp_stream_total_bytes;}
        const ProtoTime& GetReportTcpStreamSampleTime() const
            {return report_tcp_stream_sample_time;}
        UINT32 GetReportTcpStreamSampleId() const
            {return report_tcp_stream_sample_id;}
        UINT32 GetReportTcpStreamGeneration() const
            {return report_tcp_stream_generation;}

        // Worst-case flow key length (in bytes):
        // IPv6 dstAddr + dstPort + IPv6 srcAddr + srcPort + flowId
        //      16      +    2    +      16      +    2    +    4
        enum {KEY_MAX = (16 + 2 + 16 + 2 + 4)};
        
        
        class Report : public MgenDataItem
        {
            public:
                Report(UINT32*        bufferPtr = NULL, 
                       unsigned int   bufferBytes = 0, 
                       bool           freeOnDestruct = false);
                ~Report();
                
                enum ReportType
                {
                    REPORT_INVALID  = 0,
                    REPORT_FLOW_IPv4,
                    REPORT_FLOW_IPv6
                };
                
                enum Flag
                {
                    FLAG_FLOW_ID        = 0x01, // set when Flow ID field is present
                    FLAG_LATENCY_SIGN   = 0x02  // set when latencyAve is negative value
                };
                    
                // Useful for report buffer array sizing 
                // IPv6 with FlowId report is worst case. 
                enum {MAX_LENGTH = (4 + 2*16 + 4*4)};
              
                // Use these to parse    
                bool InitFromBuffer(UINT32*         bufferPtr = NULL, 
                                    unsigned int    numBytes = 0, 
                                    bool            freeOnDestruct = false);
                
                void Log(FILE*               filePtr, 
                         const ProtoTime&    sentTime, 
                         const ProtoTime&    theTime, 
                         bool                localTime,
                         const ProtoAddress& reporterAddr) const;
                
                ReportType GetReportType() const
                {
                    UINT8 field = GetUINT8(OFFSET_TYPE);
                    return (ReportType)((field >> 4) & 0x0f);
                }   
                Protocol GetProtocol() const
                {
                    UINT8 field = GetUINT8(OFFSET_PROTOCOL);
                    return (Protocol)(field & 0x0f);
                }   
                UINT8 GetReportLength() const
                    {return GetUINT8(OFFSET_LEN);}
                bool FlagIsSet(Flag flag) const
                    {return (0 != (flag & (GetUINT8(OFFSET_FLAGS) >> 5)));}     
                bool GetDstAddr(ProtoAddress& dstAddr) const;  // gets addr and port
                bool GetSrcAddr(ProtoAddress& srcAddr) const;  // gets addr and port
                UINT32 GetFlowId() const
                    {return (FlagIsSet(FLAG_FLOW_ID) ? GetUINT32(OffsetFlowId()) : 0);}
                double GetWindowOffset() const
                {
                    UINT16 q = GetUINT16(OFFSET_WINDOW) & 0x1fff;
                    return UnquantizeTimeValue(q);
                }
                double GetWindowSize() const
                {
                    UINT8 q = GetUINT8(OffsetWindowSize());
                    return UnquantizeTimeValue(q);
                }
                double GetLatencyAve() const
                {
                    UINT8 q = GetUINT8(OffsetLatencyAve());
                    double ave = UnquantizeTimeValue(q);
                    return (FlagIsSet(FLAG_LATENCY_SIGN) ? -ave : ave);
                }
                double GetLatencyMin() const
                {
                    UINT8 q = GetUINT8(OffsetLatencyMin());
                    return (GetLatencyAve() - UnquantizeTimeValue(q));
                }
                double GetLatencyMax() const
                {
                    UINT8 q = GetUINT8(OffsetLatencyMax());
                    return (GetLatencyAve() + UnquantizeTimeValue(q));
                }
                double GetRateAve() const
                {
                    UINT16 q = GetUINT16(OffsetRateAve());
                    return UnquantizeRate(q);
                }
                double GetLossFraction() const
                {
                    UINT16 q = GetUINT16(OffsetLossFraction());
                    return UnquantizeLoss(q);
                }
                
                // Use these to build a report (MUST call set dst/src/flowId in  
                // order first. All other fields may be set any time afterward)
                bool InitIntoBuffer(ReportType      reportType,
                                    UINT32*         bufferPtr = NULL, 
                                    unsigned int    bufferBytes = 0, 
                                    bool            freeOnDestruct = false);
             
                
                void SetProtocol(Protocol protocol)
                {
                    UINT8 field = GetUINT8(OFFSET_PROTOCOL);
                    field = (0xf0 & field) | (UINT8)protocol;
                    SetUINT8(OFFSET_PROTOCOL, field);
                }
                bool SetDstAddr(const ProtoAddress& dstAddr);
                bool SetSrcAddr(const ProtoAddress& srcAddr);
                bool SetFlowId(UINT32 flowId);
                void SetWindowOffset(double seconds)
                {
                    UINT16 q = QuantizeTimeValue(seconds);
                    UINT16 field = GetUINT16(OFFSET_WINDOW);
                    field = (field & 0xe000) | q;
                    SetUINT16(OFFSET_WINDOW, field);
                }
                void SetWindowSize(double seconds)
                {
                    UINT8 q = QuantizeTimeValue(seconds);
                    SetUINT8(OffsetWindowSize(), q);
                }
                void SetLatencyAve(double seconds)
                {
                    if (seconds < 0.0) SetFlag(FLAG_LATENCY_SIGN);
                    UINT8 q = QuantizeTimeValue(fabs(seconds));
                    SetUINT8(OffsetLatencyAve(), q);
                }
                void SetLatencyDeltaMin(double deltaSeconds)
                {
                    UINT8 q = QuantizeTimeValue(fabs(deltaSeconds));
                    SetUINT8(OffsetLatencyMin(), q);
                }
                void SetLatencyDeltaMax(double deltaSeconds)
                {
                    UINT8 q = QuantizeTimeValue(fabs(deltaSeconds));
                    SetUINT8(OffsetLatencyMax(), q);
                }
                void SetRateAve(double rate)
                {
                    UINT16 q = QuantizeRate(rate);
                    SetUINT16(OffsetRateAve(), q);
                }
                void SetLossFraction(double loss)
                {
                    UINT16 q = QuantizeLoss(loss);
                    SetUINT16(OffsetLossFraction(), q);
                }
                
                static UINT8 QuantizeTimeValue(double value);
                static double UnquantizeTimeValue(UINT8 timeQuantized);
                
                    
            private:
                // Routines for our compressed rate, loss, and time value fields
                static UINT16 QuantizeOffset(double offset);
                static double UnquantizeOffset(UINT16 q);
                static UINT16 QuantizeRate(double rate);
                static double UnquantizeRate(UINT16 rate);
                static UINT16 QuantizeLoss(double lossFraction);
                static double UnquantizeLoss(UINT16 lossQuantized);
                static const double TIME_STRETCH;
                static const double TIME_SCALE;
                static const double TIME_MIN;
                static const double TIME_MAX;
                    
                // ProtoPkt offsets for set/get are byte offsets!
                enum
                {
                    OFFSET_PROTOCOL = OFFSET_TYPE,     // lower 4 bits            
                    OFFSET_FLAGS = OFFSET_LEN + 1,    
                    OFFSET_WINDOW = OFFSET_LEN + 1, 
                    OFFSET_DST = (OFFSET_WINDOW + 2)/4 // UINT32 offset 
                };
                    
                unsigned int GetAddrLen() const;  // based on report type
                    
                unsigned int OffsetSrc() const         // UINT32 offset
                    {return (OFFSET_DST + GetAddrLen()/4);} 
                unsigned int OffsetDstPort() const     // byte offset
                    {return (4*OffsetSrc() + GetAddrLen());}
                unsigned int OffsetSrcPort() const     // byte offset
                    {return (OffsetDstPort() + 2);}
                unsigned int OffsetFlowId() const      // byte offset
                    {return (OffsetSrcPort() + 2);}
                unsigned int OffsetWindowSize() const  // byte offset
                    {return (OffsetFlowId() + (FlagIsSet(FLAG_FLOW_ID) ? 4 : 0));}
                unsigned int OffsetLatencyAve() const  // byte offset
                    {return (OffsetWindowSize() + 1);}
                unsigned int OffsetLatencyMin() const  // byte offset
                    {return (OffsetLatencyAve() + 1);}
                unsigned int OffsetLatencyMax() const  // byte offset
                    {return (OffsetLatencyMin() + 1);}
                unsigned int OffsetRateAve() const     // byte offset (2 bytes) 
                    {return (OffsetLatencyMax() + 1);}
                unsigned int OffsetLossFraction() const// byte offset (2 bytes) 
                    {return (OffsetRateAve() + 2);}
                    
                void SetReportType(ReportType type)
                {
                    UINT8 field = GetUINT8(OFFSET_TYPE);
                    field = (0x0f & field) | ((UINT8)type << 4);
                    SetUINT8(OFFSET_TYPE, field);
                }
                void SetReportLength(UINT8 numBytes)
                    {SetUINT8(OFFSET_LEN, numBytes);}
                void SetFlag(Flag flag)
                {
                    UINT8 field = GetUINT8(OFFSET_FLAGS);
                    field |= (flag << 5);
                    SetUINT8(OFFSET_FLAGS, field);
                }
                
        };  // end class MgenAnalytic::Report
        
        // Used for ProtoIndexedQueue::Item lookup
        const char* GetKey() const
            {return flow_key;} 
        unsigned int GetKeysize() const
            {return flow_keysize;}  
        
    private:
        void FinalizeTcpStream(bool sampleTcpStream, const ProtoTime& sampleTime);
        // Reads the current TCP queue depth for tcp_stream_socket in the
        // configured direction, via tcp_queue_query_func if a test override
        // is set, otherwise via the real SIOCOUTQNSD/SIOCINQ ioctl().
        // Returns false on failure (ioctl error, or the override reports
        // failure); "queueValue" is only valid when this returns true.
        bool QueryTcpQueueBytes(int& queueValue) const;

        char*               flow_key;
        unsigned int        flow_keysize;  // in bits
        
        // State variables for current (in progress) analytics
        double              window_size;  
        bool                window_valid;
        ProtoTime           window_start;
        ProtoTime           window_end;
        unsigned long       msg_count;
        unsigned long       byte_count;
        unsigned long       dup_msg_count;
        UINT32              seq_start;
        ProtoSlidingMask    dup_mask;
        double              latency_sum;
        double              latency_min;
        double              latency_max;

        // TCP stream accounting.  TX and RX analytics are separate objects, so
        // each instance tracks one direction for one flow/socket.
        ProtoSocket*        tcp_stream_socket;
        bool                tcp_stream_enabled;
        bool                tcp_stream_is_tx;
        bool                tcp_stream_attributable;
        TcpStreamReason     tcp_stream_disabled_reason;  // why attribution was disabled
        bool                tcp_queue_initialized;
        bool                tcp_window_sample_valid;
        unsigned long long  tcp_io_total;
        unsigned long long  tcp_io_prev;
        unsigned long long  tcp_queue_prev;

        // Lossless cumulative sample state (Phase 2).  This tracks every
        // coherent queue-sample delta for the current socket generation,
        // independent of whether a given delta could be attributed to a
        // single nominal report window.
        bool                tcp_stream_socket_ever_set;      // false until first SetTcpStream() w/ a real socket
        bool                tcp_stream_pending_generation;    // set by ClearTcpStreamSocket(); consumed by next attach
        UINT32              tcp_stream_generation;            // increments when the socket is replaced/reconnected
        UINT32              tcp_stream_next_sample_id;         // next id to assign on a successful observation
        unsigned long long  tcp_stream_total_bytes;           // monotonic resolved-byte sum for this generation
        bool                tcp_stream_total_initialized;

        // Fields describing the most recent successful queue observation
        // (the "current attribution reason"/cumulative metadata that gets
        // copied into the report_* fields at FinalizeTcpStream() time).
        TcpStreamReason     tcp_stream_reason;
        UINT32              tcp_stream_sample_id;
        ProtoTime           tcp_stream_sample_time;

        // Test-only queue-query override (see SetTcpQueueQueryFuncForTest()).
        TcpQueueQueryFunc   tcp_queue_query_func;
        void*               tcp_queue_query_user_data;

        // Results of previous analytic
        bool                report_valid;
        ProtoTime           report_start;
        double              report_duration;
        unsigned long       report_msg_count;
        double              report_rate_ave;  // bytes/sec
        double              report_loss_ave;
        double              report_latency_ave;
        double              report_latency_min;
        double              report_latency_max;
        bool                report_tcp_stream_valid;
        double              report_tcp_stream_rate_ave;
        unsigned long long  report_tcp_stream_bytes;
        TcpStreamReason     report_tcp_stream_reason;
        unsigned long long  report_tcp_stream_total_bytes;
        ProtoTime           report_tcp_stream_sample_time;
        UINT32              report_tcp_stream_sample_id;
        UINT32              report_tcp_stream_generation;
        ProtoTime           report_time;
        UINT32              report_buffer[Report::MAX_LENGTH/sizeof(UINT32)];
        Report              report_msg;
        
};  // end class MgenAnalytic

class MgenAnalyticTable : public ProtoIndexedQueueTemplate<MgenAnalytic>
{
    public:
        MgenAnalytic* FindFlow(const ProtoAddress& srcAddr, const ProtoAddress& dstAddr,  UINT32 flowId);
    
    private:
        // Required overrides for ProtoIndexedQueue subclasses
        // (Override these to determine how items are sorted)
        virtual const char* GetKey(const Item& item) const
            {return (static_cast<const MgenAnalytic&>(item).GetKey());}
        virtual unsigned int GetKeysize(const Item& item) const
            {return (static_cast<const MgenAnalytic&>(item).GetKeysize());}
};  // end class MgenAnalyticTable

// This has a linked list and a built-in iterator to prioritize reporting of flows
// (unreported updates have precedence over reports already transmitted.  Otherwise,
// round-robin reporting is implemented.
class MgenAnalyticReporter
{
    public:
        MgenAnalyticReporter();
        ~MgenAnalyticReporter();
        
        bool Add(MgenAnalytic& item);
        void Remove(MgenAnalytic& item);
        
        // The Reset() call here resets loop detection
        // I.e., this reset does _not_ reset the underlying
        // report_iterator so the reports with the most
        // precedence are still returned first after a reset.
        void Reset()
            {iteration_start = NULL;}
        
        const MgenAnalytic::Report* PeekNextReport(const ProtoTime& theTime);
        void Advance()
            {report_iterator.GetNextItem();}
        
        const MgenAnalytic::Report* GetNextReport(const ProtoTime& theTime);
        
        
    private:
        class Queue : public ProtoSimpleQueueTemplate<MgenAnalytic> {};
        MgenAnalytic* PeekNextItem();
    
        Queue            report_queue;
        Queue::Iterator  report_iterator;
        MgenAnalytic*    last_unreported_item;
        MgenAnalytic*    iteration_start;
        
};  // end class MgenReportQueue()

#endif // _MGEN_ANALYTIC
