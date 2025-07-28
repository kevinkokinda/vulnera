#pragma once
#include <string>
#include <nlohmann/json.hpp>

namespace spectre {
using json = nlohmann::json;

struct VulnProof {
    std::string target;
    std::string vuln_type;
    json evidence;
    std::string timestamp;
    std::string id;
};

class ArweaveClient {
public:
    ArweaveClient();
    ~ArweaveClient();
    
    bool submit_proof(const VulnProof& proof);
    std::string query_proofs(const std::string& target);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace spectre 