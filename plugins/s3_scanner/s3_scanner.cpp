#include "spectre/plugin.h"
#include "spectre/proof_queue.h"
#include "spectre/tor_proxy.h"
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>

namespace {
class S3ScannerPlugin : public spectre::Plugin {
public:
    std::string name() const override {
        return "s3_scan";
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

        std::string domain = extract_domain(target_url);
        if (domain.empty()) {
            std::cerr << "[" << name() << "] could not extract a valid domain from " << target_url << std::endl;
            return;
        }

        std::vector<std::string> permutations = generate_permutations(domain);
        for (const auto& bucket_name : permutations) {
            check_bucket(bucket_name, target_url);
        }

        std::cout << "[" << name() << "] finished scanning for " << target_url << std::endl;
    }

private:
    std::string extract_domain(const std::string& url) {
        std::string domain;
        size_t start = url.find("://");
        if (start != std::string::npos) {
            start += 3;
        } else {
            start = 0;
        }

        size_t end = url.find('/', start);
        if (end != std::string::npos) {
            domain = url.substr(start, end - start);
        } else {
            domain = url.substr(start);
        }

        if (domain.rfind("www.", 0) == 0) {
            domain = domain.substr(4);
        }
        return domain;
    }

    std::vector<std::string> generate_permutations(const std::string& domain) {
        std::vector<std::string> perms;
        std::string base_name = domain;
        std::replace(base_name.begin(), base_name.end(), '.', '-');

        perms.push_back(base_name);

        std::vector<std::string> prefixes = {"assets-", "media-", "files-", "data-"};
        std::vector<std::string> suffixes = {"-prod", "-production", "-dev", "-development", "-staging", "-assets", "-media", "-uploads", "-backups", "-files", "-data"};

        for (const auto& suffix : suffixes) {
            perms.push_back(base_name + suffix);
        }
        for (const auto& prefix : prefixes) {
            perms.push_back(prefix + base_name);
        }
        return perms;
    }

    void check_bucket(const std::string& bucket_name, const std::string& original_target) {
        std::cout << "  -> Testing bucket: " << bucket_name << std::endl;
        std::string bucket_url = "http://" + bucket_name + ".s3.amazonaws.com";
        
        cpr::Session session;
        session.SetUrl(cpr::Url{bucket_url});
        session.SetTimeout(cpr::Timeout{7000});
        session.SetRedirect(cpr::Redirect{false});

        if (spectre::TorProxy::get_instance().is_available()) {
            session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                {"https", "socks5://127.0.0.1:9050"}});
        }

        cpr::Response r = session.Head();

        if (r.status_code == 200) {
            report_vulnerability(bucket_name, bucket_url, original_target, "Bucket is public and listable.");
        } else if (r.status_code >= 300 && r.status_code < 400) {
            std::string location = r.header["location"];
            std::cout << "[" << name() << "] INFO: Bucket '" << bucket_name << "' exists in another region. Endpoint: " << location << std::endl;
            report_vulnerability(bucket_name, location, original_target, "Bucket exists (confirmed by redirect).");
        } else if (r.status_code == 403) {
            std::cout << "[" << name() << "] INFO: Bucket '" << bucket_name << "' exists but is not public (403 Forbidden)." << std::endl;
        }
    }

    void report_vulnerability(const std::string& bucket_name, const std::string& bucket_url, const std::string& original_target, const std::string& details) {
        std::cout << "[" << name() << "] VULNERABILITY FOUND: " << details << " Bucket: " << bucket_name << std::endl;

        nlohmann::json evidence;
        evidence["description"] = "An Amazon S3 bucket related to the target domain was found to be exposed. This could lead to sensitive data exposure.";
        evidence["bucket_name"] = bucket_name;
        evidence["bucket_url"] = bucket_url;
        evidence["details"] = details;

        spectre::VulnProof proof = {
            original_target,
            "EXPOSED_S3_BUCKET",
            evidence,
            std::to_string(std::time(nullptr)),
            ""
        };
        spectre::enqueue_proof(proof);
    }
};
} // namespace

extern "C" spectre::Plugin* spectre_create_plugin() {
    return new S3ScannerPlugin();
} 