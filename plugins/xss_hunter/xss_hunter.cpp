#include "spectre/plugin.h"
#include "spectre/proof_queue.h"
#include "spectre/tor_proxy.h"
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <vector>
#include <uriparser/Uri.h>
#include <regex>
#include <fstream>

namespace {

class XSSHunter : public spectre::Plugin {
private:
    std::vector<std::string> xss_payloads;

    void load_payloads() {
        std::ifstream payload_file("payload/payload.txt");
        if (!payload_file.is_open()) {
            std::cerr << "Failed to open payload file: payload/payload.txt" << std::endl;
            return;
        }
        std::string payload;
        while (std::getline(payload_file, payload)) {
            if (!payload.empty()) {
                xss_payloads.push_back(payload);
            }
        }
    }

public:
    XSSHunter() {
        load_payloads();
    }
    std::string name() const override { return "xss_hunter"; }

    void handle_task(const spectre::Task& task) override {
        if (task.data.value("type", "") != name()) {
            return;
        }

        std::string url = task.data.value("target", "");
        if (url.empty()) {
            return;
        }

        std::cout << "[xss_hunter] scanning " << url << std::endl;

        UriUriA uri;
        if (uriParseSingleUriA(&uri, url.c_str(), nullptr) != URI_SUCCESS) {
            uriFreeUriMembersA(&uri);
            return;
        }

        if (uri.query.first) {
            UriQueryListA* query_list;
            int item_count;
            if (uriDissectQueryMallocA(&query_list, &item_count, uri.query.first, uri.query.afterLast) == URI_SUCCESS) {
                for (int i = 0; i < item_count; ++i) {
                    std::string param_name = query_list->key;
                    for (const auto& payload : xss_payloads) {
                        test_payload(url, param_name, payload);
                    }
                    query_list = query_list->next;
                }
                uriFreeQueryListA(query_list);
            }
        }
        uriFreeUriMembersA(&uri);
    }

private:
    void test_payload(const std::string& base_url, const std::string& param, const std::string& payload) {
        std::string malicious_url = base_url;
        std::regex param_regex(param + "=[^&]*");
        malicious_url = std::regex_replace(malicious_url, param_regex, param + "=" + cpr::util::urlEncode(payload));

        cpr::Session session;
        session.SetUrl(cpr::Url{malicious_url});
        session.SetTimeout(cpr::Timeout{10000});
        if (spectre::TorProxy::get_instance().is_available()) {
            session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                {"https", "socks5://127.0.0.1:9050"}});
        }
        cpr::Response r = session.Get();

        if (r.status_code == 200 && r.text.find(payload) != std::string::npos) {
            std::cout << "[xss_hunter] VULNERABILITY DISCOVERED" << std::endl;
            std::cout << "  -> Target: " << base_url << std::endl;
            std::cout << "  -> Parameter: " << param << std::endl;
            submit_proof(base_url, param, malicious_url, payload);
        }
    }

    void submit_proof(const std::string& target, const std::string& param, const std::string& vulnerable_url, const std::string& payload) {
        nlohmann::json evidence;
        evidence["description"] = "A reflected Cross-Site Scripting (XSS) vulnerability was discovered.";
        evidence["parameter"] = param;
        evidence["payload"] = payload;
        evidence["vulnerable_url"] = vulnerable_url;

        spectre::VulnProof proof = {
            target,
            "XSS",
            evidence,
            std::to_string(std::time(nullptr)),
            ""
        };
        spectre::enqueue_proof(proof);
        std::cout << "[xss_hunter] proof queued" << std::endl;
    }
};

} // namespace

extern "C" spectre::Plugin* spectre_create_plugin() {
    return new XSSHunter();
}
