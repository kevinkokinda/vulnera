#include "spectre/proof_queue.h"
#include <iostream>
#include <thread>

namespace spectre {

ProofQueue* proof_queue_instance = nullptr;
std::thread proof_processing_thread;

ProofQueue::ProofQueue(WebSocketServer& ws) : ws_(ws) {}

void ProofQueue::start_processing() {
    proof_processing_thread = std::thread(&ProofQueue::process_proofs, this);
}

void ProofQueue::stop_processing() {
    {
        std::unique_lock<std::mutex> lock(mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    if (proof_processing_thread.joinable()) {
        proof_processing_thread.join();
    }
}

void ProofQueue::process_proofs() {
    while (!stop_) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !proofs_.empty() || stop_; });

        if (stop_ && proofs_.empty()) {
            return;
        }

        VulnProof proof = proofs_.front();
        proofs_.erase(proofs_.begin());
        lock.unlock();

        json proof_json;
        proof_json["target"] = proof.target;
        proof_json["vuln_type"] = proof.vuln_type;
        proof_json["evidence"] = proof.evidence;
        proof_json["timestamp"] = proof.timestamp;
        proof_json["id"] = proof.id;
        ws_.broadcast(proof_json.dump());

        arweave_client_.submit_proof(proof);
    }
}

void ProofQueue::enqueue(const VulnProof& proof) {
    std::unique_lock<std::mutex> lock(mutex_);
    proofs_.push_back(proof);
    cv_.notify_one();
}

void enqueue_proof(const VulnProof& proof) {
    if (proof_queue_instance) {
        proof_queue_instance->enqueue(proof);
    }
}

void init_proof_queue(WebSocketServer& ws) {
    if (!proof_queue_instance) {
        proof_queue_instance = new ProofQueue(ws);
        proof_queue_instance->start_processing();
    }
}

void shutdown_proof_queue() {
    if (proof_queue_instance) {
        proof_queue_instance->stop_processing();
        delete proof_queue_instance;
        proof_queue_instance = nullptr;
    }
}

} // namespace spectre 