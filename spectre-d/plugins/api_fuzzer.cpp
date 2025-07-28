#include "spectre/plugin.h"
#include "spectre/proof_queue.h"
#include "spectre/tor_proxy.h"
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <string>
#include <vector>

namespace {

class APIFuzzer : public spectre::Plugin {
private:
    struct FuzzPayload {
        std::string name;
        std::string body;
    };

    std::vector<FuzzPayload> fuzz_payloads = {
        {"Empty JSON", "{}"},
        {"Malformed JSON", "{\"key\": \"value\""},
        {"Large String", "{\"data\": \"" + std::string(10000, 'A') + "\"}"},
        {"Special Chars", "{\"data\": \"!@#$%^&*()_+-=[]{};':\\\",./<>?`~\"}"},
        {"SQLi Attempt", "{\"id\": \"' OR 1=1 --\"}"},
        {"XSS Attempt", "{\"html\": \"<script>alert('fuzzer')</script>\"}"}
    };

public:
    std::string name() const override { return "api_fuzzer"; }
    
    void handle_task(const spectre::Task& task) override {
        if (task.data.value("type", "") != name()) {
            return;
        }
        
        std::string url = task.data.value("target", "");
        if (url.empty()) {
            return;
        }
        
        std::cout << "[api_fuzzer] fuzzing " << url << std::endl;

        for (const auto& payload : fuzz_payloads) {
            test_payload(url, payload);
        }
    }

private:
    void test_payload(const std::string& url, const FuzzPayload& payload) {
        cpr::Session session;
        session.SetUrl(cpr::Url{url});
        session.SetHeader({{"Content-Type", "application/json"}});
        session.SetBody(cpr::Body{payload.body});
        session.SetTimeout(cpr::Timeout{10000});

        if (spectre::TorProxy::get_instance().is_available()) {
            session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                {"https", "socks5://127.0.0.1:9050"}});
        }

        cpr::Response r = session.Post();

        if (r.status_code >= 500) {
            std::cout << "[api_fuzzer] VULNERABILITY DISCOVERED (Server Error)" << std::endl;
            std::cout << "  -> Target: " << url << std::endl;
            std::cout << "  -> Payload Name: " << payload.name << std::endl;
            std::cout << "  -> Status Code: " << r.status_code << std::endl;
            submit_proof(url, payload, r.status_code);
        }
    }

    void submit_proof(const std::string& target, const FuzzPayload& payload, int status_code) {
        nlohmann::json evidence;
        evidence["description"] = "The API endpoint returned a server error when fuzzed with a malformed request, indicating a potential unhandled exception or other vulnerability.";
        evidence["payload_name"] = payload.name;
        evidence["payload_body"] = payload.body;
        evidence["response_status_code"] = status_code;

        spectre::VulnProof proof = {
            target,
            "API_FUZZ_ERROR",
            evidence,
            std::to_string(std::time(nullptr)),
            ""
        };
        spectre::enqueue_proof(proof);
        std::cout << "[api_fuzzer] proof queued" << std::endl;
    }
};

} // namespace

extern "C" spectre::Plugin* spectre_create_plugin() {
    return new APIFuzzer();
}
