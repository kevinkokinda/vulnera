#ifndef SPECTRE_HTTP_SERVER_H
#define SPECTRE_HTTP_SERVER_H

#include <boost/asio.hpp>
#include <string>
#include <functional>
#include <iostream>
#include "spectre/network_manager.h"

namespace spectre {

class http_server {
public:
    http_server(boost::asio::io_context& io_context, unsigned short port, NetworkManager& network_manager);

private:
    void do_accept();

    boost::asio::ip::tcp::acceptor acceptor_;
    NetworkManager& network_manager_;
};

} // namespace spectre

#endif // SPECTRE_HTTP_SERVER_H 