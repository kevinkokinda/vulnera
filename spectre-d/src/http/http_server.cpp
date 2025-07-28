#include "spectre/http/http_server.h"
#include <boost/beast/http.hpp>
#include <boost/beast/core.hpp>
#include <nlohmann/json.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = net::ip::tcp;

class session : public std::enable_shared_from_this<session> {
    tcp::socket socket_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;
    spectre::NetworkManager& network_manager_;

public:
    session(tcp::socket socket, spectre::NetworkManager& network_manager)
        : socket_(std::move(socket)), network_manager_(network_manager) {}

    void run() {
        do_read();
    }

private:
    void do_read() {
        req_ = {};
        http::async_read(socket_, buffer_, req_,
            beast::bind_front_handler(
                &session::on_read,
                shared_from_this()));
    }

    void on_read(beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);

        if (ec == http::error::end_of_stream)
            return do_close();

        if (ec)
            return; 

        handle_request();
    }

    void handle_request() {
        if (req_.method() == http::verb::post && req_.target() == "/scan") {
            try {
                auto body = nlohmann::json::parse(req_.body());
                if (body.contains("target")) {
                    nlohmann::json task_data;
                    task_data["type"] = "scan";
                    task_data["target"] = body["target"];
                    spectre::Task task{task_data};
                    network_manager_.publish_task(task);

                    http::response<http::string_body> res{http::status::ok, req_.version()};
                    res.set(http::field::server, "Spectre-HTTP");
                    res.set(http::field::content_type, "application/json");
                    res.keep_alive(req_.keep_alive());
                    res.body() = "{\"status\":\"scan initiated\"}";
                    res.prepare_payload();
                    send_response(std::move(res));
                }
            } catch (const std::exception& e) {
                http::response<http::string_body> res{http::status::bad_request, req_.version()};
                res.set(http::field::server, "Spectre-HTTP");
                res.set(http::field::content_type, "application/json");
                res.keep_alive(req_.keep_alive());
                res.body() = "{\"error\":\"invalid json\"}";
                res.prepare_payload();
                send_response(std::move(res));
            }
        } else {
            http::response<http::string_body> res{http::status::not_found, req_.version()};
            res.set(http::field::server, "Spectre-HTTP");
            res.set(http::field::content_type, "text/html");
            res.keep_alive(req_.keep_alive());
            res.body() = "<h1>404 Not Found</h1>";
            res.prepare_payload();
            send_response(std::move(res));
        }
    }

    void send_response(http::response<http::string_body>&& res) {
        auto self = shared_from_this();
        http::async_write(socket_, std::move(res),
            [self](beast::error_code ec, std::size_t bytes_transferred) {
                boost::ignore_unused(ec, bytes_transferred);
                self->do_close();
            });
    }

    void do_close() {
        beast::error_code ec;
        socket_.shutdown(tcp::socket::shutdown_send, ec);
    }
};

namespace spectre {

http_server::http_server(boost::asio::io_context& io_context, unsigned short port, NetworkManager& network_manager)
    : acceptor_(io_context, {tcp::v4(), port}), network_manager_(network_manager) {
    do_accept();
}

void http_server::do_accept() {
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket) {
            if (!ec) {
                std::make_shared<session>(std::move(socket), network_manager_)->run();
            }
            do_accept();
        });
}

} // namespace spectre 