// SPDX-License-Identifier: GPL-2.0-only
// Toolchain probe (docs/shizukudos10/WEBKIT.md "Toolchain"): libstdc++ containers, std::thread + std::mutex, thread_local,
// C++ exceptions and printf of a double, the parts of the C++ runtime WTF/JavaScriptCore rely on. Exit 0 = all consistent.
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <cmath>
#include <functional>
#include <stdexcept>
static thread_local int tl = 5;
int main(int argc, char** argv) {
    std::vector<std::string> v;
    for (int i = 0; i < 100; i++) v.push_back(std::to_string(i * i));
    std::map<std::string, int> m;
    for (auto& s : v) m[s] = (int)s.size();
    std::atomic<int> sum{0};
    std::mutex mu;
    std::vector<std::thread> th;
    for (int t = 0; t < 4; t++) th.emplace_back([&, t] { tl += t; std::lock_guard<std::mutex> g(mu); sum += tl; });
    for (auto& t : th) t.join();
    int caught = 0;
    try { throw std::runtime_error("x"); } catch (const std::exception& e) { caught = e.what()[0] == 'x'; }
    char buf[64]; snprintf(buf, sizeof buf, "%.3f", std::sqrt(2.0));
    std::printf("PROBE v=%zu m=%zu sum=%d caught=%d sqrt=%s tl=%d\n", v.size(), m.size(), sum.load(), caught, buf, tl);
    return (v.size() == 100 && sum == 26 && caught && tl == 5) ? 0 : 1;
}
