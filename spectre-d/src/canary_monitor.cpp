#include "spectre/canary_monitor.h"
#include <iostream>
#include <thread>
#include <mutex>
#include <vector>
#include <random>
#include <chrono>
#include <nlohmann/json.hpp>
#include <cpr/cpr.h>

namespace spectre {

struct CanaryMonitor::pimpl {
    std::string webhook_url;
    std::vector<std::string> active_canaries;
    std::vector<std::string> chirped_canaries;
    std::mutex mtx;
    bool running = false;
    std::thread worker;

    void poll_webhook() {
        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            if (webhook_url.empty()) {
                continue;
            }

            cpr::Response r = cpr::Get(cpr::Url{webhook_url});

            if (r.status_code != 200) {
                continue;
            }

            try {
                auto json_body = nlohmann::json::parse(r.text);
                if (!json_body.contains("data")) {
                    continue;
                }

                std::lock_guard<std::mutex> lock(mtx);
                for (const auto& item : json_body["data"]) {
                    if (!item.contains("url")) {
                        continue;
                    }
                    std::string url = item["url"];
                    for (const auto& canary : active_canaries) {
                        if (url.find(canary) != std::string::npos) {
                            bool already_chirped = false;
                            for (const auto& chirped : chirped_canaries) {
                                if (chirped == canary) {
                                    already_chirped = true;
                                    break;
                                }
                            }

                            if (!already_chirped) {
                                std::cout << "[canary_monitor] HIT DETECTED on: " << url << std::endl;
                                chirped_canaries.push_back(canary);
                            }
                        }
                    }
                }
            } catch (const nlohmann::json::parse_error& e) {
                
            }
        }
    }
};

CanaryMonitor& CanaryMonitor::get_instance() {
    static CanaryMonitor instance;
    return instance;
}

void CanaryMonitor::start(const std::string& webhook_url) {
    if (!pimpl_) {
        pimpl_ = std::make_unique<pimpl>();
    }
    pimpl_->webhook_url = webhook_url;
    pimpl_->running = true;
    pimpl_->worker = std::thread(&pimpl::poll_webhook, pimpl_.get());
    std::cout << "[canary_monitor] started. Webhook: " << webhook_url << std::endl;
}

void CanaryMonitor::stop() {
    if (pimpl_ && pimpl_->running) {
        pimpl_->running = false;
        if (pimpl_->worker.joinable()) {
            pimpl_->worker.join();
        }
    }
}

std::string CanaryMonitor::get_canary_url() {
    static const char* chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    thread_local std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> dist(0, 35);
    std::string token(16, '\0');
    for (char& c : token) {
        c = chars[dist(gen)];
    }
    
    if (pimpl_) {
        std::lock_guard<std::mutex> lock(pimpl_->mtx);
        pimpl_->active_canaries.push_back(token);
        return pimpl_->webhook_url + "/" + token;
    }
    return "error-canary-monitor-not-started";
}

bool CanaryMonitor::has_canary_chirped(const std::string& canary_id) {
    if (pimpl_) {
        std::lock_guard<std::mutex> lock(pimpl_->mtx);
        for(const auto& c : pimpl_->chirped_canaries) {
            if (c == canary_id) return true;
        }
    }
    return false;
}

void start_canary_monitor() {
    char* url = std::getenv("CANARY_WEBHOOK_API_URL");
    if (!url) {
        std::cerr << "CANARY_WEBHOOK_API_URL environment variable not set. Canary monitor will not start." << std::endl;
        return;
    }
    CanaryMonitor::get_instance().start(url);
}

void stop_canary_monitor() {
    CanaryMonitor::get_instance().stop();
}

} // namespace spectre 

