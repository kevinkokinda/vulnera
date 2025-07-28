#include "spectre/websocket_server.h"
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>

using boost::asio::ip::tcp;
namespace websocket = boost::beast::websocket;

namespace spectre {
class WebSocketServer::Impl {
    boost::asio::io_context io_;
    tcp::acceptor acceptor_;
    std::thread worker_;
    MessageHandler handler_;
    std::vector<std::shared_ptr<websocket::stream<tcp::socket>>> clients_;
    std::mutex clients_mutex_;
    bool running_ = false;

public:
    Impl(int port) : acceptor_(io_, tcp::endpoint(tcp::v4(), port)) {}

    void start() {
        running_ = true;
        start_accept();
        worker_ = std::thread([this] { io_.run(); });
        std::cout << "[websocket] server started on port 8889" << std::endl;
    }

    void stop() {
        running_ = false;
        io_.stop();
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            clients_.clear();
        }
        if (worker_.joinable()) worker_.join();
        std::cout << "[websocket] server stopped" << std::endl;
    }

    void broadcast(const std::string &message) {
        io_.post([this, message] {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto it = clients_.begin(); it != clients_.end();) {
                auto ws = *it;
                if (!ws->is_open()) {
                    it = clients_.erase(it);
                    continue;
                }
                try {
                    ws->text(true);
                    ws->async_write(boost::asio::buffer(message), [ws](boost::system::error_code, std::size_t) {});
                } catch (...) {
                    ws->next_layer().close();
                }
                ++it;
            }
        });
        std::cout << "[websocket] broadcast: " << message << std::endl;
    }

    void set_message_handler(MessageHandler h) { handler_ = h; }

private:
    void start_accept() {
        auto socket = std::make_shared<tcp::socket>(io_);
        acceptor_.async_accept(*socket, [this, socket](boost::system::error_code ec) {
            if (!ec && running_) {
                handle_connection(socket);
            }
            if (running_) start_accept();
        });
    }

    void handle_connection(std::shared_ptr<tcp::socket> socket) {
        auto ws = std::make_shared<websocket::stream<tcp::socket>>(std::move(*socket));
        ws->set_option(websocket::stream_base::timeout::suggested(boost::beast::role_type::server));
        ws->set_option(websocket::stream_base::decorator([](websocket::response_type &res) {
            res.set(boost::beast::http::field::server, std::string("spectre-d"));
        }));

        ws->async_accept([this, ws](boost::system::error_code ec) {
            if (ec) {
                return;
            }
            {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                clients_.push_back(ws);
            }
            std::cout << "[websocket] client connected" << std::endl;
            read_loop(ws);
        });
    }

    void read_loop(std::shared_ptr<websocket::stream<tcp::socket>> ws) {
        auto buffer = std::make_shared<boost::beast::flat_buffer>();
        ws->async_read(*buffer, [this, ws, buffer](boost::system::error_code ec, std::size_t) {
            if (ec) {
                std::lock_guard<std::mutex> lock(clients_mutex_);
                clients_.erase(std::remove(clients_.begin(), clients_.end(), ws), clients_.end());
                return;
            }
            if (handler_) {
                auto data = boost::beast::buffers_to_string(buffer->data());
                handler_(data);
            }
            read_loop(ws);
        });
    }
};

WebSocketServer::WebSocketServer(int port) : impl_(std::make_unique<Impl>(port)) {}
WebSocketServer::~WebSocketServer() = default;

void WebSocketServer::start() { impl_->start(); }
void WebSocketServer::stop() { impl_->stop(); }
void WebSocketServer::broadcast(const std::string &message) { impl_->broadcast(message); }
void WebSocketServer::set_message_handler(MessageHandler handler) { impl_->set_message_handler(handler); }
} // namespace spectre 