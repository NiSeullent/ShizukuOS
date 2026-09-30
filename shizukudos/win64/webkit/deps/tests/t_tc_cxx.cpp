// SPDX-License-Identifier: GPL-2.0-only
// Guest check of the W3 toolchain's C++ runtime (libc++.dll, libunwind.dll, UCRT through the api-ms-win-crt contracts)
// on Kernel64: Itanium-ABI exceptions with SEH unwinding through the Shizuku ntdll, destructors in the frames between
// throw and catch, a throw from inside libc++.dll, rethrow, nested handlers, exceptions on threads, and the library
// parts WebKit relies on (containers, strings, iostreams, chrono, filesystem, atomics, condition variables).
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

static int failures;
#define CHECK(cond) do { if (cond) std::printf("PASS %s\n", #cond); else { std::printf("FAIL %s (line %d)\n", #cond, __LINE__); ++failures; } } while (0)

static int destroyed;
struct Guard {
    int id;
    explicit Guard(int i) : id(i) {}
    ~Guard() { destroyed += id; }
};

struct Base : std::runtime_error { using std::runtime_error::runtime_error; };
struct Derived : Base { int code; Derived(const char *w, int c) : Base(w), code(c) {} };

[[gnu::noinline]] static void level3(int v) { Guard g(100); if (v) throw Derived("deep", v); }
[[gnu::noinline]] static void level2(int v) { Guard g(10); std::string s(64, 'x'); level3(v); }
[[gnu::noinline]] static void level1(int v) { Guard g(1); std::vector<int> big(1000, v); level2(v); }

int main()
{
    // 1. throw through three frames with destructors, catch by base class reference
    destroyed = 0;
    int code = 0;
    try { level1(7); } catch (const Base &b) { code = dynamic_cast<const Derived &>(b).code; }
    CHECK(code == 7 && destroyed == 111);

    // 2. an exception thrown inside libc++.dll (vector::at) caught here
    bool range = false;
    try { std::vector<int> v(3); (void)v.at(10); } catch (const std::out_of_range &) { range = true; }
    CHECK(range);

    // 3. rethrow and nested handlers
    int stage = 0;
    try {
        try { throw std::logic_error("inner"); }
        catch (const std::logic_error &) { stage = 1; throw; }
    } catch (const std::exception &e) { stage = (std::string(e.what()) == "inner") ? 2 : -1; }
    CHECK(stage == 2);

    // 4. exception_ptr across threads, and a throw/catch on each of four threads
    std::exception_ptr ep;
    std::thread t([&] { try { throw std::runtime_error("from thread"); } catch (...) { ep = std::current_exception(); } });
    t.join();
    bool got = false;
    try { if (ep) std::rethrow_exception(ep); } catch (const std::runtime_error &e) { got = std::string(e.what()) == "from thread"; }
    CHECK(got);
    std::atomic<int> caught{0};
    std::vector<std::thread> ts;
    for (int i = 0; i < 4; ++i)
        ts.emplace_back([&, i] { for (int k = 0; k < 50; ++k) { try { level1(i + 1); } catch (const Derived &d) { if (d.code == i + 1) ++caught; } } });
    for (auto &th : ts) th.join();
    CHECK(caught == 200);

    // 5. mutex + condition variable handshake
    std::mutex m;
    std::condition_variable cv;
    int turn = 0;
    std::thread ping([&] { for (int i = 0; i < 100; ++i) { std::unique_lock<std::mutex> l(m); cv.wait(l, [&] { return turn % 2 == 0; }); ++turn; cv.notify_all(); } });
    for (int i = 0; i < 100; ++i) { std::unique_lock<std::mutex> l(m); cv.wait(l, [&] { return turn % 2 == 1; }); ++turn; cv.notify_all(); }
    ping.join();
    CHECK(turn == 200);

    // 6. containers, strings, streams, chrono, function
    std::map<std::string, int> mp;
    std::unordered_map<int, std::string> um;
    for (int i = 0; i < 1000; ++i) { mp[std::to_string(i)] = i; um[i] = std::to_string(i * i); }
    std::ostringstream os;
    os << mp.size() << ' ' << um[31] << ' ' << 3.5 << ' ' << std::hex << 255;
    CHECK(os.str() == "1000 961 3.5 ff");
    std::istringstream is("12 34.5 word");
    int a; double b; std::string w;
    is >> a >> b >> w;
    CHECK(a == 12 && b == 34.5 && w == "word");
    auto t0 = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    CHECK(ms >= 15 && ms < 5000);
    std::function<int(int)> f = [](int x) { return x * 3; };
    auto up = std::make_unique<Guard>(0);
    auto sp = std::make_shared<std::string>("shared");
    CHECK(f(14) == 42 && sp.use_count() == 1 && up->id == 0);

    // 7. filesystem and fstream in the current directory (D:\WK)
    namespace fs = std::filesystem;
    fs::path dir = fs::current_path() / "tcxx_dir";
    std::error_code ec;
    fs::remove_all(dir, ec);
    CHECK(fs::create_directory(dir));
    { std::ofstream out(dir / "a.txt", std::ios::binary); out << "hello filesystem"; }
    CHECK(fs::exists(dir / "a.txt") && fs::file_size(dir / "a.txt") == 16);
    std::string back;
    { std::ifstream in(dir / "a.txt", std::ios::binary); std::getline(in, back); }
    CHECK(back == "hello filesystem");
    int entries = 0;
    for (auto &e : fs::directory_iterator(dir)) { (void)e; ++entries; }
    CHECK(entries == 1);
    fs::rename(dir / "a.txt", dir / "b.txt");
    CHECK(!fs::exists(dir / "a.txt") && fs::exists(dir / "b.txt"));
    CHECK(fs::remove_all(dir) == 2);

    std::printf("t_tc_cxx: %d failure(s)\n", failures);
    return failures ? 1 : 0;
}
