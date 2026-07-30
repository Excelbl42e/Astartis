// event_log_monitor.cpp — Windows Event Log ingestion implementation

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <winevt.h>
#pragma comment(lib, "wevtapi.lib")

#include "event_log_monitor.h"

#include <iostream>
#include <sstream>
#include <chrono>
#include <stdexcept>

namespace astartis {
namespace monitor {

// ---------------------------------------------------------------------------
// Event ID → threat score table
// ---------------------------------------------------------------------------

struct EventDef {
    uint16_t    id;
    int         score;
    const char* description;
};

static const EventDef k_event_defs[] = {
    // Security channel
    { 4625, 40, "Failed logon attempt" },
    { 4648, 55, "Logon with explicit credentials" },
    { 4688, 30, "New process created" },
    { 4697, 60, "Service installed on system" },
    { 4698, 55, "Scheduled task created" },
    { 4702, 45, "Scheduled task updated" },
    { 4720, 50, "User account created" },
    { 4726, 60, "User account deleted" },
    { 4728, 45, "Member added to security-enabled global group" },
    { 4732, 45, "Member added to security-enabled local group" },
    { 4756, 45, "Member added to security-enabled universal group" },
    { 4768, 35, "Kerberos authentication ticket requested" },
    { 4776, 40, "NTLM credential validation attempted" },
    { 4946, 50, "Firewall rule added" },
    { 4947, 50, "Firewall rule modified" },
    // System channel
    { 7045, 65, "New service registered on system" },
    { 7036, 10, "Service state changed" },
    // Application channel
    { 1000, 25, "Application crash" },
    { 1002, 30, "Application hang" },
};

static constexpr size_t k_event_def_count =
    sizeof(k_event_defs) / sizeof(k_event_defs[0]);

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

EventLogMonitor::EventLogMonitor(SignalCallback on_signal)
    : on_signal_(std::move(on_signal))
{
    stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

EventLogMonitor::~EventLogMonitor()
{
    stop();
    if (stop_event_) {
        CloseHandle(stop_event_);
        stop_event_ = nullptr;
    }
}

// ---------------------------------------------------------------------------
// start() / stop()
// ---------------------------------------------------------------------------

bool EventLogMonitor::start()
{
    if (running_.load()) return true;

    static const std::wstring channels[] = {
        L"Security", L"System", L"Application"
    };

    ResetEvent(stop_event_);
    int ok_count = 0;

    for (const auto& ch : channels) {
        Subscription sub;
        sub.channel = ch;
        // Subscribe from the current bookmark (future events only)
        sub.handle = EvtSubscribe(
            nullptr,                          // local machine
            stop_event_,                      // signal on stop
            ch.c_str(),
            nullptr,                          // no XPath filter — we filter by event ID in callback
            nullptr,                          // no bookmark
            this,                             // context = this
            evt_callback,
            EvtSubscribeToFutureEvents
        );

        if (!sub.handle) {
            std::cerr << "[EventLogMonitor] EvtSubscribe failed on channel "
                      << std::string(ch.begin(), ch.end())
                      << " error=" << GetLastError() << "\n";
        } else {
            ++ok_count;
        }
        subscriptions_.push_back(std::move(sub));
    }

    if (ok_count == 0) return false;

    running_.store(true);
    // Dispatch thread just keeps the process alive and handles stop signalling
    dispatch_thread_ = std::thread([this]() {
        WaitForSingleObject(stop_event_, INFINITE);
    });

    std::cerr << "[EventLogMonitor] Started on " << ok_count << "/3 channels\n";
    return true;
}

void EventLogMonitor::stop()
{
    if (!running_.exchange(false)) return;
    if (stop_event_) SetEvent(stop_event_);
    for (auto& sub : subscriptions_) {
        if (sub.handle) {
            EvtClose(sub.handle);
            sub.handle = nullptr;
        }
    }
    subscriptions_.clear();
    if (dispatch_thread_.joinable()) dispatch_thread_.join();
    std::cerr << "[EventLogMonitor] Stopped, forwarded=" << events_forwarded_.load() << " events\n";
}

// ---------------------------------------------------------------------------
// Static EvtSubscribe callback → on_event()
// ---------------------------------------------------------------------------

DWORD WINAPI EventLogMonitor::evt_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                            PVOID context,
                                            EVT_HANDLE event_handle)
{
    if (action != EvtSubscribeActionDeliver) return ERROR_SUCCESS;
    auto* self = static_cast<EventLogMonitor*>(context);
    if (self && self->running_.load()) {
        self->on_event(event_handle);
    }
    return ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
// on_event() — extract event ID, score, and fire callback
// ---------------------------------------------------------------------------

void EventLogMonitor::on_event(EVT_HANDLE event_handle)
{
    // Render the event as an XML string to extract EventID
    DWORD buf_used = 0, prop_count = 0;
    EvtRender(nullptr, event_handle, EvtRenderEventXml, 0, nullptr,
              &buf_used, &prop_count);

    if (buf_used == 0) return;
    std::vector<WCHAR> buf(buf_used / sizeof(WCHAR) + 1, L'\0');
    if (!EvtRender(nullptr, event_handle, EvtRenderEventXml,
                   buf_used, buf.data(), &buf_used, &prop_count)) return;

    std::wstring xml(buf.data());

    // Extract <EventID> value — simple substring search, no XML parser needed
    auto id_start = xml.find(L"<EventID>");
    auto id_end   = xml.find(L"</EventID>");
    if (id_start == std::wstring::npos || id_end == std::wstring::npos) return;

    std::wstring id_str = xml.substr(id_start + 9, id_end - id_start - 9);
    // Strip any Qualifiers attribute
    auto bracket = id_str.find(L'>');
    if (bracket != std::wstring::npos) id_str = id_str.substr(bracket + 1);

    uint16_t event_id = 0;
    try { event_id = static_cast<uint16_t>(std::stoul(id_str)); }
    catch (...) { return; }

    int score = score_for_event_id(event_id);
    if (score <= 0) return;   // not a monitored event ID

    // Extract channel
    std::string channel = "unknown";
    auto ch_start = xml.find(L"<Channel>");
    auto ch_end   = xml.find(L"</Channel>");
    if (ch_start != std::wstring::npos && ch_end != std::wstring::npos) {
        std::wstring wch = xml.substr(ch_start + 9, ch_end - ch_start - 9);
        channel = std::string(wch.begin(), wch.end());
    }

    int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    EventSignal sig;
    sig.channel      = channel;
    sig.event_id     = event_id;
    sig.score        = score;
    sig.source       = "event_log/" + channel + "/" + std::to_string(event_id);
    sig.description  = describe_event_id(event_id);
    sig.timestamp_ms = now_ms;

    ++events_forwarded_;
    try {
        on_signal_(sig);
    } catch (...) {
        std::cerr << "[EventLogMonitor] callback threw on event_id=" << event_id << "\n";
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

int EventLogMonitor::score_for_event_id(uint16_t id) const
{
    for (size_t i = 0; i < k_event_def_count; ++i)
        if (k_event_defs[i].id == id) return k_event_defs[i].score;
    return 0;
}

std::string EventLogMonitor::describe_event_id(uint16_t id) const
{
    for (size_t i = 0; i < k_event_def_count; ++i)
        if (k_event_defs[i].id == id) return k_event_defs[i].description;
    return "Unknown event " + std::to_string(id);
}

} // namespace monitor
} // namespace astartis

// Made with Bob
