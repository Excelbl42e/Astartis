// fs_monitor.h — Real-time file system watcher (Astartis v3.1)
//
// Uses ReadDirectoryChangesW to watch one or more directories for
// file creation and modification events.  On each event the caller-supplied
// callback receives the full path so the bridge can call scan_and_quarantine.
//
// Default watch roots:
//   %USERPROFILE%\Downloads
//   %USERPROFILE%\Desktop
//   %TEMP%
//   C:\Users\Public
//   %USERPROFILE%\AppData\Roaming   (startup folder, common malware drop)

#ifndef ASTARTIS_FS_MONITOR_H
#define ASTARTIS_FS_MONITOR_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <cstdint>

namespace astartis {
namespace monitor {

enum class FsEventType { CREATED, MODIFIED };

struct FsEvent {
    FsEventType type;
    std::string path;       ///< full absolute path
    std::string filename;   ///< basename only
    std::string extension;  ///< lower-case, including dot (e.g. ".exe")
    int64_t     timestamp_ms;
};

class FsMonitor {
public:
    using EventCallback = std::function<void(const FsEvent&)>;

    // watch_roots: directories to watch recursively.
    // If empty, the default high-risk roots are used.
    explicit FsMonitor(EventCallback on_event,
                       std::vector<std::string> watch_roots = {});
    ~FsMonitor();

    FsMonitor(const FsMonitor&)            = delete;
    FsMonitor& operator=(const FsMonitor&) = delete;

    // Start one watcher thread per root.
    bool start();

    // Stop all watcher threads.
    void stop();

    bool     is_running()       const { return running_.load(); }
    uint64_t events_forwarded() const { return events_forwarded_.load(); }

    // Add an extension filter — only fire callback for these extensions.
    // Empty list = fire for everything. Call before start().
    void set_extension_filter(std::vector<std::string> exts);

private:
    struct WatchRoot {
        std::string  path;
        HANDLE       dir_handle  = INVALID_HANDLE_VALUE;
        HANDLE       stop_event  = nullptr;
        std::thread  thread;
    };

    void watch_loop(WatchRoot* root);
    bool should_fire(const std::string& ext) const;

    static std::vector<std::string> default_roots();
    static std::string to_lower(std::string s);

    EventCallback              on_event_;
    std::vector<WatchRoot>     roots_;
    std::vector<std::string>   ext_filter_;   // lower-case with dot
    std::atomic<bool>          running_{false};
    std::atomic<uint64_t>      events_forwarded_{0};
    mutable std::mutex         filter_mutex_;
};

} // namespace monitor
} // namespace astartis

#endif // ASTARTIS_FS_MONITOR_H

// Made with Bob
