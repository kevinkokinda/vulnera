#include "spectre/plugin.h"
#include "spectre/proof_queue.h"
#include "spectre/tor_proxy.h"
#include <iostream>
#include <string>
#include <vector>
#include <queue>
#include <set>
#include <regex>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <uriparser/Uri.h>

namespace {
std::string resolve_url(const std::string& base_url, const std::string& relative_url) {
    UriUriA base_uri, resolved_uri;
    const char* error_pos;
    if (uriParseSingleUriA(&base_uri, base_url.c_str(), &error_pos) != URI_SUCCESS) {
        return "";
    }
    if (uriParseSingleUriA(&resolved_uri, relative_url.c_str(), &error_pos) != URI_SUCCESS) {
        uriFreeUriMembersA(&base_uri);
        return "";
    }

    UriUriA absolute_uri;
    if (uriAddBaseUriA(&absolute_uri, &resolved_uri, &base_uri) != URI_SUCCESS) {
        uriFreeUriMembersA(&base_uri);
        uriFreeUriMembersA(&resolved_uri);
        return "";
    }

    int chars_required;
    uriToStringCharsRequiredA(&absolute_uri, &chars_required);
    std::string result(chars_required, '\0');
    uriToStringA(&result[0], &absolute_uri, chars_required + 1, &chars_required);
    result.pop_back();

    uriFreeUriMembersA(&base_uri);
    uriFreeUriMembersA(&resolved_uri);
    uriFreeUriMembersA(&absolute_uri);
    
    size_t fragment_pos = result.find('#');
    if (fragment_pos != std::string::npos) {
        result = result.substr(0, fragment_pos);
    }

    return result;
}

class CrawlerPlugin : public spectre::Plugin {
public:
    std::string name() const override {
        return "crawler";
    }

    void handle_task(const spectre::Task& task) override {
        if (task.data.value("type", "") != name()) {
            return;
        }

        std::string start_url = task.data.value("target", "");
        if (start_url.empty()) {
            return;
        }
        
        std::string scan_id = task.data.value("id", "");

        std::cout << "[" << name() << "] starting crawl on " << start_url << std::endl;

        std::queue<std::string> to_visit;
        std::set<std::string> visited;
        to_visit.push(start_url);

        std::string base_host = get_host(start_url);

        while (!to_visit.empty()) {
            std::string current_url = to_visit.front();
            to_visit.pop();

            if (visited.count(current_url)) {
                continue;
            }

            visited.insert(current_url);
            std::cout << "  -> Crawling: " << current_url << std::endl;

            cpr::Session session;
            session.SetUrl(cpr::Url{current_url});
            session.SetTimeout(cpr::Timeout{10000});
            if (spectre::TorProxy::get_instance().is_available()) {
                session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                    {"https", "socks5://127.0.0.1:9050"}});
            }
            cpr::Response r = session.Get();
            
            if (r.status_code != 200) {
                continue;
            }

            std::regex link_regex(R"(<a\s+(?:[^>]*?\s+)?href=\"([^\"]+)\")");
            auto links_begin = std::sregex_iterator(r.text.begin(), r.text.end(), link_regex);
            auto links_end = std::sregex_iterator();

            for (std::sregex_iterator i = links_begin; i != links_end; ++i) {
                std::string link = (*i)[1].str();
                std::string absolute_link = resolve_url(current_url, link);
                
                if (!absolute_link.empty() && get_host(absolute_link) == base_host) {
                    if(visited.find(absolute_link) == visited.end()){
                       to_visit.push(absolute_link);
                    }
                }
            }
        }

        report_sitemap(start_url, visited, scan_id);
    }

private:
    std::string get_host(const std::string& url) {
        UriUriA uri;
        const char* error_pos;
        if (uriParseSingleUriA(&uri, url.c_str(), &error_pos) != URI_SUCCESS) {
            return "";
        }
        std::string host(uri.hostText.first, uri.hostText.afterLast);
        uriFreeUriMembersA(&uri);
        return host;
    }

    void report_sitemap(const std::string& target, const std::set<std::string>& urls, const std::string& scan_id) {
        std::cout << "[" << name() << "] Crawl complete. Discovered " << urls.size() << " unique URLs." << std::endl;

        nlohmann::json evidence;
        evidence["description"] = "A map of all discoverable URLs on the target site.";
        evidence["url_count"] = urls.size();
        evidence["sitemap"] = nlohmann::json::array();
        for(const auto& url : urls) {
            evidence["sitemap"].push_back(url);
        }
        
        spectre::VulnProof proof = {
            target,
            "CRAWL_COMPLETE",
            evidence,
            std::to_string(std::time(nullptr)),
            scan_id
        };
        spectre::enqueue_proof(proof);
    }
};
} // namespace

extern "C" spectre::Plugin* spectre_create_plugin() {
    return new CrawlerPlugin();
} 