// event_log_monitor.h — Real-time Windows Event Log ingestion (Astartis v3.1)
//
// Tails Security, System, and Application event logs using the Windows
// EvtSubscribe API.  Each matching event is scored and forwarded to a
// caller-supplied callback (wired to observe_signal in the bridge).
//
// Monitored event IDs:
//   Security 4625  — Failed logon              score 40
//   Security 4648  — Explicit credential use   score 55
//   Security 4688  — New process created        score 30
//   Security 4697  — Service installed          score 60
//   Security 4720  — User account created       score 50
//   Security 4728/4732/4756 — Group membership  score 45
//   System   7045  — New service registered     score 65
//   System   7036  — Service state change       score 10
//   Application 1000 — App crash               score 25

#ifndef ASTARTIS_EVENT_LOG_MONITOR_H
#define ASTARTIS_EVENT_LOG_MONITOR_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winevt.h>
#pragma comment(lib, "wevtapi.lib")

#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <vector>
#include <cstdint>

namespace astartis {
namespace monitor {

struct EventSignal {
    std::string channel;        ///< "Security" | "System" | "Application"
    uint16_t    event_id;
    int         score;          ///< 0–100 threat score for observe_signal
    std::string source;         ///< "event_log/<channel>/<event_id>"
    std::string description;    ///< human-readable summary
    int64_t     timestamp_ms;
};

class EventLogMonitor {
public:
    using SignalCallback = std::function<void(const EventSignal&)>;

    explicit EventLogMonitor(SignalCallback on_signal);
    ~EventLogMonitor();

    EventLogMonitor(const EventLogMonitor&)            = delete;
    EventLogMonitor& operator=(const EventLogMonitor&) = delete;

    // Start tailing all configured channels.
    // Returns false if EvtSubscribe fails on every channel (e.g. not elevated).
    bool start();

    // Stop all subscriptions and wait for the dispatch thread to exit.
    void stop();

    bool is_running() const { return running_.load(); }

    // Total events forwarded since start().
    uint64_t events_forwarded() const { return events_forwarded_.load(); }

private:
    struct Subscription {
        std::wstring channel;
        EVT_HANDLE   handle = nullptr;
    };

    // EvtSubscribe callback — static trampoline → on_event()
    static DWORD WINAPI evt_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                     PVOID context,
                                     EVT_HANDLE event);

    void on_event(EVT_HANDLE event_handle);
    int  score_for_event_id(uint16_t id) const;
    std::string describe_event_id(uint16_t id) const;

    SignalCallback              on_signal_;
    std::vector<Subscription>   subscriptions_;
    HANDLE                      stop_event_ = nullptr;
    std::thread                 dispatch_thread_;
    std::atomic<bool>           running_{false};
    std::atomic<uint64_t>       events_forwarded_{0};
};

} // namespace monitor
} // namespace astartis

#endif // ASTARTIS_EVENT_LOG_MONITOR_H

// Made with Bob
