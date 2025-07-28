#include "spectre/network_manager.h"
#include <boost/asio.hpp>
#include <iostream>
#include <thread>

using boost::asio::ip::udp;

namespace spectre {
class NetworkManager::Impl {
    boost::asio::io_context io_;
    udp::socket socket_;
    udp::endpoint broadcast_endpoint_;
    std::thread worker_;
    TaskHandler handler_;
    bool running_ = false;
    
public:
    Impl() : socket_(io_), broadcast_endpoint_(boost::asio::ip::address_v4::broadcast(), 8888) {}
    
    void start(TaskHandler handler) {
        handler_ = handler;
        socket_.open(udp::v4());
        socket_.set_option(udp::socket::reuse_address(true));
        socket_.set_option(boost::asio::socket_base::broadcast(true));
        socket_.bind(udp::endpoint(udp::v4(), 8888));
        
        running_ = true;
        worker_ = std::thread([this] { 
            start_receive();
            io_.run(); 
        });
        
        std::cout << "network: UDP broadcast P2P started on port 8888" << std::endl;
    }
    
    void stop() {
        running_ = false;
        io_.stop();
        if (worker_.joinable()) worker_.join();
        std::cout << "network: P2P stopped" << std::endl;
    }
    
    void publish_task(const Task& task) {
        auto data = task.data.dump();
        socket_.async_send_to(
            boost::asio::buffer(data),
            broadcast_endpoint_,
            [](boost::system::error_code, std::size_t) {}
        );
        std::cout << "network: broadcasted task: " << data << std::endl;
    }
    
private:
    void start_receive() {
        auto buffer = std::make_shared<std::array<char, 1024>>();
        auto sender = std::make_shared<udp::endpoint>();
        
        socket_.async_receive_from(
            boost::asio::buffer(*buffer),
            *sender,
            [this, buffer, sender](boost::system::error_code ec, std::size_t bytes) {
                if (!ec && running_) {
                    try {
                        std::string data(buffer->data(), bytes);
                        auto json = nlohmann::json::parse(data);
                        Task task{json};
                        handler_(task);
                        std::cout << "network: received task from " << sender->address() << std::endl;
                    } catch (...) {}
                    start_receive();
                }
            }
        );
    }
};

NetworkManager::NetworkManager() : impl_(std::make_unique<Impl>()) {}
NetworkManager::~NetworkManager() = default;

void NetworkManager::start(TaskHandler handler) {
    impl_->start(handler);
}

void NetworkManager::stop() {
    impl_->stop();
}

void NetworkManager::publish_task(const Task& task) {
    impl_->publish_task(task);
}
} // namespace spectre 