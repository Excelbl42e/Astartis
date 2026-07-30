// fs_monitor.cpp — File system watcher implementation

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "fs_monitor.h"

#include <algorithm>
#include <iostream>
#include <chrono>
#include <filesystem>
#include <shlobj.h>   // SHGetKnownFolderPath
#pragma comment(lib, "shell32.lib")

namespace fs = std::filesystem;

namespace astartis {
namespace monitor {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string FsMonitor::to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return s;
}

static std::string known_folder(REFKNOWNFOLDERID fid) {
    PWSTR path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(fid, 0, nullptr, &path))) {
        std::wstring ws(path);
        CoTaskMemFree(path);
        return std::string(ws.begin(), ws.end());
    }
    return "";
}

std::vector<std::string> FsMonitor::default_roots() {
    std::vector<std::string> roots;
    // Downloads
    auto dl = known_folder(FOLDERID_Downloads);
    if (!dl.empty()) roots.push_back(dl);
    // Desktop
    auto desk = known_folder(FOLDERID_Desktop);
    if (!desk.empty()) roots.push_back(desk);
    // Temp
    char tmp[MAX_PATH];
    if (GetTempPathA(MAX_PATH, tmp)) roots.push_back(std::string(tmp));
    // Public
    roots.push_back("C:\\Users\\Public");
    // AppData\Roaming (startup folder lives here)
    auto roam = known_folder(FOLDERID_RoamingAppData);
    if (!roam.empty()) roots.push_back(roam);
    return roots;
}

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

FsMonitor::FsMonitor(EventCallback on_event,
                     std::vector<std::string> watch_roots)
    : on_event_(std::move(on_event))
{
    if (watch_roots.empty())
        watch_roots = default_roots();

    roots_.resize(watch_roots.size());
    for (size_t i = 0; i < watch_roots.size(); ++i)
        roots_[i].path = watch_roots[i];
}

FsMonitor::~FsMonitor() { stop(); }

void FsMonitor::set_extension_filter(std::vector<std::string> exts) {
    std::lock_guard<std::mutex> lk(filter_mutex_);
    ext_filter_.clear();
    for (auto& e : exts) ext_filter_.push_back(to_lower(e));
}

// ---------------------------------------------------------------------------
// start() / stop()
// ---------------------------------------------------------------------------

bool FsMonitor::start() {
    if (running_.load()) return true;
    running_.store(true);

    int started = 0;
    for (auto& root : roots_) {
        // Ensure directory exists
        std::error_code ec;
        if (!fs::exists(root.path, ec)) {
            std::cerr << "[FsMonitor] Skipping non-existent root: " << root.path << "\n";
            continue;
        }

        root.dir_handle = CreateFileA(
            root.path.c_str(),
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
            nullptr
        );

        if (root.dir_handle == INVALID_HANDLE_VALUE) {
            std::cerr << "[FsMonitor] CreateFile failed on " << root.path
                      << " err=" << GetLastError() << "\n";
            continue;
        }

        root.stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        root.thread = std::thread([this, &root]() { watch_loop(&root); });
        ++started;
        std::cerr << "[FsMonitor] Watching: " << root.path << "\n";
    }

    if (started == 0) { running_.store(false); return false; }
    return true;
}

void FsMonitor::stop() {
    if (!running_.exchange(false)) return;
    for (auto& root : roots_) {
        if (root.stop_event) SetEvent(root.stop_event);
    }
    for (auto& root : roots_) {
        if (root.thread.joinable()) root.thread.join();
        if (root.dir_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(root.dir_handle);
            root.dir_handle = INVALID_HANDLE_VALUE;
        }
        if (root.stop_event) {
            CloseHandle(root.stop_event);
            root.stop_event = nullptr;
        }
    }
    std::cerr << "[FsMonitor] Stopped, forwarded=" << events_forwarded_.load() << " events\n";
}

// ---------------------------------------------------------------------------
// Per-root watch loop (ReadDirectoryChangesW with OVERLAPPED)
// ---------------------------------------------------------------------------

void FsMonitor::watch_loop(WatchRoot* root) {
    constexpr DWORD kBufSize = 65536;
    std::vector<BYTE> buf(kBufSize, 0);

    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) return;

    HANDLE handles[2] = { ov.hEvent, root->stop_event };

    while (running_.load()) {
        ResetEvent(ov.hEvent);

        DWORD bytes_returned = 0;
        BOOL ok = ReadDirectoryChangesW(
            root->dir_handle,
            buf.data(), kBufSize,
            TRUE,   // watch subtree
            FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE |
            FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_CREATION,
            &bytes_returned,
            &ov,
            nullptr
        );

        if (!ok && GetLastError() != ERROR_IO_PENDING) break;

        DWORD wait = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        if (wait == WAIT_OBJECT_0 + 1) break;   // stop_event signalled
        if (wait != WAIT_OBJECT_0) continue;

        if (!GetOverlappedResult(root->dir_handle, &ov, &bytes_returned, FALSE))
            continue;
        if (bytes_returned == 0) continue;

        int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        DWORD offset = 0;
        do {
            auto* info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buf.data() + offset);

            FsEventType type;
            if (info->Action == FILE_ACTION_ADDED ||
                info->Action == FILE_ACTION_RENAMED_NEW_NAME)
                type = FsEventType::CREATED;
            else if (info->Action == FILE_ACTION_MODIFIED)
                type = FsEventType::MODIFIED;
            else {
                offset = info->NextEntryOffset ? offset + info->NextEntryOffset : 0;
                if (!info->NextEntryOffset) break;
                continue;
            }

            // Build full path
            std::wstring wrel(info->FileName,
                              info->FileNameLength / sizeof(WCHAR));
            std::string rel(wrel.begin(), wrel.end());
            std::string full = root->path + "\\" + rel;

            // Extension
            std::string ext;
            auto dot = rel.rfind('.');
            if (dot != std::string::npos)
                ext = to_lower(rel.substr(dot));

            // Extension filter
            if (should_fire(ext)) {
                FsEvent ev;
                ev.type         = type;
                ev.path         = full;
                ev.filename     = rel;
                ev.extension    = ext;
                ev.timestamp_ms = now_ms;
                ++events_forwarded_;
                try { on_event_(ev); } catch (...) {}
            }

            if (!info->NextEntryOffset) break;
            offset += info->NextEntryOffset;
        } while (offset < bytes_returned);
    }

    CancelIo(root->dir_handle);
    CloseHandle(ov.hEvent);
}

bool FsMonitor::should_fire(const std::string& ext) const {
    std::lock_guard<std::mutex> lk(filter_mutex_);
    if (ext_filter_.empty()) return true;
    return std::find(ext_filter_.begin(), ext_filter_.end(), ext) != ext_filter_.end();
}

} // namespace monitor
} // namespace astartis

// Made with Bob
