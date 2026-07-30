// event_bus.h -- Typed publish/subscribe event bus (Astartis v2.0 / v2.1)
//
// Decouples modules: instead of direct callbacks, producers publish events
// and consumers subscribe with typed handlers.
//
// Thread-safe: publish() and subscribe() can be called from any thread.
//
// Two dispatch modes:
//   publish()       — synchronous: handlers called on the caller's thread.
//   publish_async() — asynchronous: event queued for the background worker
//                     thread; non-blocking. Worker dispatches in FIFO order.
//                     Worker is started lazily on first publish_async() call.
//
// Usage:
//   EventBus<ThreatEvent> bus;
//   auto sub = bus.subscribe([](const ThreatEvent& e){ /* ... */ });
//   bus.publish(ThreatEvent{...});       // sync
//   bus.publish_async(ThreatEvent{...}); // async, non-blocking
//   // sub goes out of scope → auto-unsubscribed

#ifndef ASTARTIS_EVENT_BUS_H
#define ASTARTIS_EVENT_BUS_H

#include <functional>
#include <map>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>
#include <cstdint>
#include <memory>

namespace astartis {
namespace events {

// ---------------------------------------------------------------------------
// Subscription handle — unsubscribes on destruction (RAII)
// ---------------------------------------------------------------------------

class SubscriptionHandle {
public:
    SubscriptionHandle() = default;
    SubscriptionHandle(std::function<void()> unsubscribe_fn)
        : unsubscribe_fn_(std::move(unsubscribe_fn)) {}

    ~SubscriptionHandle() {
        if (unsubscribe_fn_) unsubscribe_fn_();
    }

    // Non-copyable; moveable
    SubscriptionHandle(const SubscriptionHandle&) = delete;
    SubscriptionHandle& operator=(const SubscriptionHandle&) = delete;
    SubscriptionHandle(SubscriptionHandle&&) = default;
    SubscriptionHandle& operator=(SubscriptionHandle&&) = default;

    // Explicitly cancel early without waiting for scope exit
    void cancel() {
        if (unsubscribe_fn_) { unsubscribe_fn_(); unsubscribe_fn_ = nullptr; }
    }

private:
    std::function<void()> unsubscribe_fn_;
};

// ---------------------------------------------------------------------------
// EventBus<EventType>
// ---------------------------------------------------------------------------

template<typename EventType>
class EventBus {
public:
    using Handler = std::function<void(const EventType&)>;
    using SubId   = uint64_t;

    EventBus() = default;

    // Not copyable (owns subscriptions)
    EventBus(const EventBus&)            = delete;
    EventBus& operator=(const EventBus&) = delete;

    /**
     * @brief Subscribe to events.
     * @return A SubscriptionHandle; unsubscribes when the handle is destroyed.
     */
    [[nodiscard]] SubscriptionHandle subscribe(Handler handler) {
        std::lock_guard<std::mutex> lk(mutex_);
        SubId id = next_id_++;
        handlers_[id] = std::move(handler);
        return SubscriptionHandle([this, id]() { unsubscribe(id); });
    }

    /**
     * @brief Publish an event synchronously.
     * Handlers are called on the calling thread before publish() returns.
     */
    void publish(const EventType& event) {
        dispatch(event);
    }

    /**
     * @brief Publish an event asynchronously (non-blocking).
     * The event is queued; the background worker thread delivers it in FIFO
     * order. Starts the worker thread on first call (lazy init).
     */
    void publish_async(const EventType& event) {
        ensure_worker_running();
        {
            std::lock_guard<std::mutex> lk(queue_mutex_);
            event_queue_.push(event);
        }
        queue_cv_.notify_one();
    }

    /// Number of active subscribers.
    std::size_t subscriber_count() const {
        std::lock_guard<std::mutex> lk(mutex_);
        return handlers_.size();
    }

    ~EventBus() {
        // Signal the worker to drain and exit
        if (worker_.joinable()) {
            {
                std::lock_guard<std::mutex> lk(queue_mutex_);
                stop_worker_ = true;
            }
            queue_cv_.notify_all();
            worker_.join();
        }
    }

private:
    // Synchronous dispatch: snapshots handlers, then calls each
    void dispatch(const EventType& event) {
        std::map<SubId, Handler> snapshot;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            snapshot = handlers_;
        }
        for (auto& [id, handler] : snapshot) {
            handler(event);
        }
    }

    void unsubscribe(SubId id) {
        std::lock_guard<std::mutex> lk(mutex_);
        handlers_.erase(id);
    }

    void ensure_worker_running() {
        std::lock_guard<std::mutex> lk(queue_mutex_);
        if (!worker_started_) {
            worker_started_ = true;
            worker_ = std::thread([this]() { worker_loop(); });
        }
    }

    void worker_loop() {
        while (true) {
            EventType event;
            {
                std::unique_lock<std::mutex> lk(queue_mutex_);
                queue_cv_.wait(lk, [this]{
                    return !event_queue_.empty() || stop_worker_;
                });
                if (stop_worker_ && event_queue_.empty()) break;
                event = event_queue_.front();
                event_queue_.pop();
            }
            dispatch(event);
        }
    }

    // --- Subscription state ---
    mutable std::mutex       mutex_;
    std::map<SubId, Handler> handlers_;
    SubId                    next_id_ = 1;

    // --- Async worker state ---
    std::mutex              queue_mutex_;
    std::condition_variable queue_cv_;
    std::queue<EventType>   event_queue_;
    std::thread             worker_;
    bool                    worker_started_ = false;
    bool                    stop_worker_    = false;
};

// ---------------------------------------------------------------------------
// Standard Astartis event types
// ---------------------------------------------------------------------------

struct ThreatEvent {
    int         tier;        ///< 0=LOW … 3=CRITICAL
    std::string tier_name;
    int         score;
    std::string source;
    bool        worm_triggered;
};

struct ChaosEvent {
    double   K;
    bool     anomalous;
    uint64_t window_index;
};

struct WormEvent {
    bool        locked;
    std::string reason;
};

struct AgentTaskEvent {
    std::string agent_name;
    std::string task_id;
    std::string status;    ///< "queued" | "running" | "completed" | "failed"
    std::string result;
};

struct PipelineEvent {
    std::string stage;
    std::string status;    ///< "started" | "passed" | "failed" | "auto_fixed"
    std::string detail;
};

} // namespace events
} // namespace astartis

#endif // ASTARTIS_EVENT_BUS_H

// Made with Bob
