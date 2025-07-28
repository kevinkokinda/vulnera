#pragma once

#include <vector>
#include <string>
#include <nlohmann/json.hpp>
#include <mutex>
#include <condition_variable>
#include "arweave_client.h" 
#include "websocket_server.h"

namespace spectre {

using json = nlohmann::json;


class ProofQueue {
public:
    ProofQueue(WebSocketServer& ws);
    void start_processing();
    void stop_processing();
    void enqueue(const VulnProof& proof);

private:
    void process_proofs();
    std::vector<VulnProof> proofs_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_ = false;
    ArweaveClient arweave_client_;
    WebSocketServer& ws_;
};


void enqueue_proof(const VulnProof& proof);
void init_proof_queue(WebSocketServer& ws);
void shutdown_proof_queue();

} // namespace spectre 