#ifdef NDEBUG
#undef NDEBUG   // force assert() active in Release builds for test executables
#endif
#include <iostream>
#include <cassert>
#include <string>
#include <filesystem>
#include <algorithm>

#include "../core/audit_chain/audit_chain.h"
#include "../core/worm_lock/worm_lock.h"
#include "../core/sandbox/sandbox.h"

namespace fs = std::filesystem;

using namespace astartis::audit;
using namespace astartis::worm;
using namespace astartis::sandbox;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Use the system temp directory so we never touch the project tree.
static std::string make_sandbox_root(const std::string& suffix) {
    fs::path tmp = fs::temp_directory_path() / ("astartis_sandbox_test_" + suffix);
    return tmp.string();
}

// Clean up on exit (best-effort).
static void cleanup(const std::string& root) {
    std::error_code ec;
    fs::remove_all(root, ec);
}

// ---------------------------------------------------------------------------
// Test 1: populate() creates realistic synthetic hierarchy
// ---------------------------------------------------------------------------
void test_populate_creates_hierarchy() {
    std::cout << "\n=== Test 1: populate() Creates Realistic Hierarchy ===" << std::endl;

    std::string root = make_sandbox_root("t1");
    cleanup(root);

    AuditChain chain;
    Sandbox sb(root,
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        });

    size_t created = sb.populate();

    std::cout << "  Sandbox root:    " << root << std::endl;
    std::cout << "  Entries created: " << created << std::endl;

    assert(created > 0);
    assert(sb.entry_count() == created);

    // Spot-check expected entries exist
    auto tree = sb.get_tree();
    bool found_nginx   = false;
    bool found_authlog = false;
    bool found_backup  = false;
    bool found_config  = false;
    for (const auto& e : tree) {
        if (e.rel_path == "etc/nginx.conf")             found_nginx   = true;
        if (e.rel_path == "var/log/auth.log")           found_authlog = true;
        if (e.rel_path == "backup/db-2024-06-26.tar.gz") found_backup = true;
        if (e.rel_path == "opt/app/config.json")        found_config  = true;
    }
    assert(found_nginx   && "etc/nginx.conf missing");
    assert(found_authlog && "var/log/auth.log missing");
    assert(found_backup  && "backup entry missing");
    assert(found_config  && "opt/app/config.json missing");

    std::cout << "  Found: etc/nginx.conf, var/log/auth.log, backup/, opt/app/config.json" << std::endl;

    // Audit chain should have a sandbox_populated entry
    bool has_populated_entry = false;
    for (const auto& e : chain.get_all_entries()) {
        if (e.event_type == "sandbox_populated") { has_populated_entry = true; break; }
    }
    assert(has_populated_entry);
    std::cout << "  Audit entry 'sandbox_populated': present" << std::endl;

    // On-disk: verify at least one file exists
    fs::path nginx_disk = fs::path(root) / "etc" / "nginx.conf";
    assert(fs::exists(nginx_disk));
    std::cout << "  On-disk: etc/nginx.conf exists" << std::endl;

    cleanup(root);
}

// ---------------------------------------------------------------------------
// Test 2: Path guard rejects operations outside the sandbox root
// ---------------------------------------------------------------------------
void test_path_guard_rejects_outside_paths() {
    std::cout << "\n=== Test 2: Path Guard Rejects Paths Outside Sandbox ===" << std::endl;

    std::string root = make_sandbox_root("t2");
    cleanup(root);

    AuditChain chain;
    Sandbox sb(root,
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        });

    sb.populate();

    // Attempt to write outside the sandbox root
    std::string outside_path = "C:/Windows/System32/evil.txt";
    auto r1 = sb.write(outside_path, "evil content", "attacker");
    assert(!r1.ok);
    std::cout << "  Write to " << outside_path << ": REJECTED — " << r1.error << std::endl;

    // Attempt with a path that looks like it starts with the root but is really a sibling
    // (e.g. root = /tmp/sandbox, path = /tmp/sandbox_evil/file)
    std::string sibling = root + "_evil/etc/passwd";
    auto r2 = sb.write(sibling, "root:x:0:0...", "attacker");
    assert(!r2.ok);
    std::cout << "  Write to sibling dir: REJECTED — " << r2.error << std::endl;

    // Attempt lock_entry on outside path
    auto r3 = sb.lock_entry(outside_path, "test");
    assert(!r3.ok);
    std::cout << "  lock_entry outside sandbox: REJECTED — " << r3.error << std::endl;

    // Read outside path
    SandboxEntry dummy;
    auto r4 = sb.read(outside_path, dummy);
    assert(!r4.ok);
    std::cout << "  read outside sandbox: REJECTED — " << r4.error << std::endl;

    // Confirm legitimate inside write still works
    std::string inside = root + "/etc/nginx.conf";
    auto r5 = sb.write(inside, "# updated config", "admin");
    assert(r5.ok);
    std::cout << "  Write inside sandbox: OK" << std::endl;

    // --- Traversal attack: path starts inside sandbox but uses ".." to escape ---
    // e.g. <root>/../../Windows/System32/evil.dll
    // The old prefix-only check would pass this because it starts with root.
    // The fixed is_inside() rejects any path containing a ".." component.
    std::string traversal = root + "/../../Windows/System32/evil.dll";
    auto r_trav1 = sb.write(traversal, "evil", "attacker");
    if (r_trav1.ok) {
        std::cerr << "FAIL: traversal write should be rejected\n"; std::exit(1);
    }
    std::cout << "  Traversal (../../): REJECTED -- " << r_trav1.error << std::endl;

    // is_inside() must also reject the traversal statically
    if (Sandbox::is_inside(traversal, root)) {
        std::cerr << "FAIL: is_inside() should return false for traversal path\n"; std::exit(1);
    }
    std::cout << "  is_inside() on traversal: false (correct)" << std::endl;

    // Variant: traversal in the middle of the path
    std::string mid_traversal = root + "/etc/../../../Windows/evil.txt";
    auto r_trav2 = sb.write(mid_traversal, "evil", "attacker");
    if (r_trav2.ok) {
        std::cerr << "FAIL: mid-path traversal write should be rejected\n"; std::exit(1);
    }
    std::cout << "  Traversal (mid /../): REJECTED -- " << r_trav2.error << std::endl;

    // Variant: traversal via lock_entry
    auto r_trav3 = sb.lock_entry(traversal, "test");
    if (r_trav3.ok) {
        std::cerr << "FAIL: traversal lock_entry should be rejected\n"; std::exit(1);
    }
    std::cout << "  Traversal lock_entry: REJECTED -- " << r_trav3.error << std::endl;

    cleanup(root);
}

// ---------------------------------------------------------------------------
// Test 3: write() creates and versions entries; old content recoverable
// ---------------------------------------------------------------------------
void test_write_and_versioning() {
    std::cout << "\n=== Test 3: Write Versions Entries ===" << std::endl;

    std::string root = make_sandbox_root("t3");
    cleanup(root);

    AuditChain chain;
    Sandbox sb(root,
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        });

    std::string path = root + "/opt/app/config.json";

    auto r1 = sb.write(path, "v1-content", "admin");
    assert(r1.ok);

    auto r2 = sb.write(path, "v2-content", "admin");
    assert(r2.ok);

    SandboxEntry entry;
    sb.read(path, entry);
    assert(entry.version == 2);
    assert(entry.content == "v2-content");
    std::cout << "  After 2 writes: version=" << entry.version
              << "  content=" << entry.content << std::endl;

    cleanup(root);
}

// ---------------------------------------------------------------------------
// Test 4: lock_entry blocks subsequent writes to that entry
// ---------------------------------------------------------------------------
void test_lock_entry_blocks_write() {
    std::cout << "\n=== Test 4: lock_entry Blocks Write ===" << std::endl;

    std::string root = make_sandbox_root("t4");
    cleanup(root);

    AuditChain chain;
    Sandbox sb(root,
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        });

    sb.populate();
    std::string path = root + "/etc/sshd_config";

    // Write before lock — succeeds
    auto r1 = sb.write(path, "PermitRootLogin yes  # attacker trying to unlock", "admin");
    assert(r1.ok);
    std::cout << "  Write before lock: OK" << std::endl;

    // Lock the entry
    sb.lock_entry(path, "WORM: entry frozen");

    // Write after lock — must fail
    auto r2 = sb.write(path, "attacker override", "attacker");
    assert(!r2.ok);
    std::cout << "  Write after lock:  REJECTED — " << r2.error << std::endl;

    // Unlock and retry
    sb.unlock_entry(path, "admin unlocked");
    auto r3 = sb.write(path, "PermitRootLogin no  # restored", "admin");
    assert(r3.ok);
    std::cout << "  Write after unlock: OK" << std::endl;

    cleanup(root);
}

// ---------------------------------------------------------------------------
// Test 5: lock_all() locks every entry; global WORM write block
// ---------------------------------------------------------------------------
void test_lock_all_and_global_worm() {
    std::cout << "\n=== Test 5: lock_all() + Global WORM Hook ===" << std::endl;

    std::string root = make_sandbox_root("t5");
    cleanup(root);

    AuditChain chain;
    WormLock    worm([&chain](const std::string& et, const std::string& p) {
                   return chain.add_entry(et, p);
               });

    Sandbox sb(root,
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        },
        [&worm]() { return worm.is_locked(); });

    sb.populate();
    size_t total = sb.entry_count();

    // lock_all: every entry frozen
    size_t newly = sb.lock_all("ransomware WORM trigger");
    assert(newly == total);
    std::cout << "  lock_all() locked " << newly << " entries" << std::endl;

    // Write to any entry must fail
    std::string path = root + "/opt/app/config.json";
    auto r1 = sb.write(path, "encrypted!", "ransomware");
    assert(!r1.ok);
    std::cout << "  Write after lock_all: REJECTED — " << r1.error << std::endl;

    // Now also test global WORM hook (separate fixture, no lock_all)
    std::string root2 = make_sandbox_root("t5b");
    cleanup(root2);
    AuditChain chain2;
    WormLock    worm2([&chain2](const std::string& et, const std::string& p) {
                    return chain2.add_entry(et, p);
                });
    Sandbox sb2(root2,
        [&chain2](const std::string& et, const std::string& p) {
            return chain2.add_entry(et, p);
        },
        [&worm2]() { return worm2.is_locked(); });

    sb2.populate();
    worm2.trigger_lockdown("breach detected");

    std::string p2 = root2 + "/etc/nginx.conf";
    auto r2 = sb2.write(p2, "attacker content", "attacker");
    assert(!r2.ok);
    std::cout << "  Global WORM active — write: REJECTED — " << r2.error << std::endl;

    cleanup(root);
    cleanup(root2);
}

// ---------------------------------------------------------------------------
// Test 6: get_tree() returns all entries with version and lock status
// ---------------------------------------------------------------------------
void test_get_tree_for_dashboard() {
    std::cout << "\n=== Test 6: get_tree() Returns Full Dashboard View ===" << std::endl;

    std::string root = make_sandbox_root("t6");
    cleanup(root);

    AuditChain chain;
    Sandbox sb(root,
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        });

    sb.populate();

    // Lock one entry
    sb.lock_entry(root + "/backup/db-2024-06-26.tar.gz", "demo lock");

    auto tree = sb.get_tree();
    size_t locked_count = 0;
    for (const auto& e : tree) {
        if (e.locked) ++locked_count;
    }
    assert(locked_count == 1);

    std::cout << "  Total entries: " << tree.size() << std::endl;
    std::cout << "  Locked entries: " << locked_count << std::endl;
    std::cout << "  Sample entries (first 5):" << std::endl;
    size_t shown = 0;
    for (const auto& e : tree) {
        std::cout << "    [" << (e.locked ? "LOCKED" : "open  ") << "] "
                  << "v" << e.version << "  " << e.rel_path
                  << "  (" << e.size_bytes << " bytes)" << std::endl;
        if (++shown >= 5) break;
    }

    cleanup(root);
}

// ---------------------------------------------------------------------------
// Test 7: is_inside() path guard — static method exhaustive checks
// ---------------------------------------------------------------------------
void test_is_inside_static() {
    std::cout << "\n=== Test 7: is_inside() Static Path Guard ===" << std::endl;

    std::string root = "/tmp/astartis_sandbox";

    assert( Sandbox::is_inside("/tmp/astartis_sandbox",             root));
    assert( Sandbox::is_inside("/tmp/astartis_sandbox/etc",         root));
    assert( Sandbox::is_inside("/tmp/astartis_sandbox/etc/nginx.conf", root));

    assert(!Sandbox::is_inside("/tmp/astartis_sandbox_evil",        root));
    assert(!Sandbox::is_inside("/tmp/other",                        root));
    assert(!Sandbox::is_inside("/etc/passwd",                       root));
    assert(!Sandbox::is_inside("C:/Windows/System32/cmd.exe",       root));

    // Windows-style root
    std::string win_root = "C:/Users/kgosi/AppData/Local/Temp/astartis_sb";
    assert( Sandbox::is_inside("C:/Users/kgosi/AppData/Local/Temp/astartis_sb/etc/hosts", win_root));
    assert(!Sandbox::is_inside("C:/Users/kgosi/AppData/Local/Temp/astartis_sb_bad/file",  win_root));

    std::cout << "  All is_inside() cases correct" << std::endl;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "ASTARTIS SANDBOXED MIRROR ENVIRONMENT   " << std::endl;
    std::cout << "Step 9: Sandbox + Path Guard Tests      " << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_populate_creates_hierarchy();
        test_path_guard_rejects_outside_paths();
        test_write_and_versioning();
        test_lock_entry_blocks_write();
        test_lock_all_and_global_worm();
        test_get_tree_for_dashboard();
        test_is_inside_static();

        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL TESTS PASSED"                         << std::endl;
        std::cout << "Sandboxed environment working!"           << std::endl;
        std::cout << "========================================\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << std::endl;
        return 1;
    }
}

// Made with Bob
