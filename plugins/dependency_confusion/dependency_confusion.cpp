#include "spectre/plugin.h"
#include "spectre/proof_queue.h"
#include "spectre/tor_proxy.h"
#include <cpr/cpr.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <regex>

namespace {

class DependencyConfusionPlugin : public spectre::Plugin {
public:
    std::string name() const override {
        return "dependency_confusion";
    }

    void handle_task(const spectre::Task& task) override {
        if (task.data.value("type", "") != name()) {
            return;
        }

        std::string url = task.data.value("target", "");
        if (url.empty()) {
            return;
        }

        std::cout << "[" << name() << "] scanning " << url << std::endl;

        check_package_json(url);
        check_requirements_txt(url);
    }

private:
    void check_package_json(const std::string& base_url) {
        std::string pkg_url = base_url + "/package.json";
        cpr::Response r = get_request(pkg_url);

        if (r.status_code == 200) {
            try {
                nlohmann::json pkg = nlohmann::json::parse(r.text);
                const std::vector<std::string> keys = {"dependencies", "devDependencies", "peerDependencies"};
                for (const auto& key : keys) {
                    if (pkg.contains(key)) {
                        for (auto& [dep_name, version] : pkg[key].items()) {
                            check_npm_registry(base_url, dep_name);
                        }
                    }
                }
            } catch (const nlohmann::json::parse_error&) {
            }
        }
    }

    void check_requirements_txt(const std::string& base_url) {
        std::string req_url = base_url + "/requirements.txt";
        cpr::Response r = get_request(req_url);

        if (r.status_code == 200) {
            std::istringstream stream(r.text);
            std::string line;
            while (std::getline(stream, line)) {
                std::regex dep_regex("^[a-zA-Z0-9_-]+");
                std::smatch match;
                if (std::regex_search(line, match, dep_regex)) {
                    check_pypi_registry(base_url, match.str(0));
                }
            }
        }
    }

    void check_npm_registry(const std::string& target, const std::string& dep_name) {
        std::string registry_url = "https://registry.npmjs.org/" + dep_name;
        cpr::Response r = get_request(registry_url);

        if (r.status_code == 200 || r.status_code == 404) {
            submit_proof(target, dep_name, "npm", registry_url);
        }
    }
    
    void check_pypi_registry(const std::string& target, const std::string& dep_name) {
        std::string registry_url = "https://pypi.org/pypi/" + dep_name + "/json";
        cpr::Response r = get_request(registry_url);

        if (r.status_code == 200) {
            submit_proof(target, dep_name, "pypi", registry_url);
        }
    }

    cpr::Response get_request(const std::string& url) {
        cpr::Session session;
        session.SetUrl(cpr::Url{url});
        session.SetTimeout(cpr::Timeout{10000});
        if (spectre::TorProxy::get_instance().is_available()) {
            session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                {"https", "socks5://127.0.0.1:9050"}});
        }
        return session.Get();
    }

    void submit_proof(const std::string& target, const std::string& dep_name, const std::string& ecosystem, const std::string& registry_url) {
        std::cout << "[" << name() << "] VULNERABILITY FOUND: " << dep_name << " exists in the public " << ecosystem << " registry." << std::endl;
        
        nlohmann::json evidence;
        evidence["description"] = "A package with a name matching a project dependency was found in a public repository. This could allow an attacker to execute a dependency confusion attack by creating a malicious package with a higher version number.";
        evidence["dependency_name"] = dep_name;
        evidence["ecosystem"] = ecosystem;
        evidence["public_registry_url"] = registry_url;

        spectre::VulnProof proof = {
            target,
            "DEPENDENCY_CONFUSION",
            evidence,
            std::to_string(std::time(nullptr)),
            ""
        };
        spectre::enqueue_proof(proof);
        std::cout << "[" << name() << "] proof queued" << std::endl;
    }
};
} // namespace


extern "C" spectre::Plugin* spectre_create_plugin() {
    return new DependencyConfusionPlugin();
} 