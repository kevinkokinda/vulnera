#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace spectre {

class CanaryMonitor {
public:
    static CanaryMonitor& get_instance();
    void start(const std::string& webhook_url);
    void stop();

    std::string get_canary_url();

    bool has_canary_chirped(const std::string& canary_id);

private:
    CanaryMonitor() = default;
    struct pimpl;
    std::unique_ptr<pimpl> pimpl_;
};

void start_canary_monitor();
void stop_canary_monitor();

} // namespace spectre 