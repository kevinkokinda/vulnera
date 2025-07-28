#include "spectre/tor_proxy.h"
#include <boost/asio.hpp>

namespace spectre { 

TorProxy& TorProxy::get_instance() {
    static TorProxy instance;
    return instance;
}

TorProxy::TorProxy() {
    try {
        boost::asio::io_context io_context;
        boost::asio::ip::tcp::socket socket(io_context);
        boost::asio::ip::tcp::resolver resolver(io_context);
        boost::asio::connect(socket, resolver.resolve("127.0.0.1", "9050"));
        available_ = true;
    } catch (const std::exception&) {
        available_ = false;
    }
}

bool TorProxy::is_available() {
    return available_;
}

} 