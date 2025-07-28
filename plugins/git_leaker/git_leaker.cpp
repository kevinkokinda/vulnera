#include "spectre/plugin.h"
#include "spectre/proof_queue.h"
#include "spectre/tor_proxy.h"
#include <iostream>
#include <string>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

namespace {
class GitLeakerPlugin : public spectre::Plugin {
public:
    std::string name() const override {
        return "git_leak";
    }

    void handle_task(const spectre::Task& task) override {
        if (task.data.value("type", "") != name()) {
            return;
        }

        std::string target_url = task.data.value("target", "");
        if (target_url.empty()) {
            return;
        }

        std::cout << "[" << name() << "] scanning " << target_url << std::endl;

        if (target_url.back() == '/') {
            target_url.pop_back();
        }
        std::string git_config_url = target_url + "/.git/config";

        cpr::Session session;
        session.SetUrl(cpr::Url{git_config_url});
        session.SetTimeout(cpr::Timeout{10000});

        if (spectre::TorProxy::get_instance().is_available()) {
            session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                {"https", "socks5://127.0.0.1:9050"}});
        }

        cpr::Response r = session.Get();

        if (r.status_code == 200 && r.text.find("[remote \"origin\"]") != std::string::npos) {
            std::cout << "[" << name() << "] VULNERABILITY CONFIRMED: Exposed and valid .git/config at " << git_config_url << std::endl;
            
            nlohmann::json evidence;
            evidence["description"] = "The web server is exposing a valid .git/config file. This confirms the entire source code repository is publicly accessible, posing a critical security risk.";
            evidence["exposed_file_url"] = git_config_url;
            evidence["http_status"] = r.status_code;
            evidence["validation"] = "Response body contains '[remote \"origin\"]', confirming it is a valid git config file.";

            spectre::VulnProof proof = {
                target_url,
                "EXPOSED_GIT_REPOSITORY",
                evidence,
                std::to_string(std::time(nullptr)),
                ""
            };
            spectre::enqueue_proof(proof);
        } else {
            std::cout << "[" << name() << "] no git exposure detected on " << target_url << " (status: " << r.status_code << ")" << std::endl;
        }
    }
};
} // namespace

extern "C" spectre::Plugin* spectre_create_plugin() {
    return new GitLeakerPlugin();
} 