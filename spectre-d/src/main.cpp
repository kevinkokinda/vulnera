#include <boost/asio.hpp>
#include <boost/asio/signal_set.hpp>
#include <iostream>
#include <cstdlib>
#include "spectre/plugin_loader.h"
#include "spectre/network_manager.h"
#include "spectre/tor_proxy.h"
#include <nlohmann/json.hpp>
#include "spectre/websocket_server.h"
#include "spectre/proof_queue.h"
#include "spectre/canary_monitor.h"
#include "spectre/http/http_server.h"

int main(int argc, char* argv[]) {
    try {
        boost::asio::io_context io;

        std::string plugin_dir = (argc > 1) ? argv[1] : "plugins";
        spectre::PluginLoader loader(plugin_dir);
        auto plugins = loader.load_all();
        std::cout << "spectre-d: loaded " << plugins.size() << " plugins" << std::endl;
            
        if (spectre::TorProxy::get_instance().is_available()) {
            std::cout << "spectre-d: Tor proxy available at 127.0.0.1:9050. Anonymity is ON." << std::endl;
        } else {
            std::cout << "spectre-d: Tor proxy NOT available. Anonymity is OFF." << std::endl;
        }

        spectre::WebSocketServer ws;
        ws.start();

        spectre::init_proof_queue(ws);
        
        spectre::start_canary_monitor();
        
        spectre::NetworkManager network;
        network.start([&plugins, &ws](const spectre::Task& task) {
            ws.broadcast(task.data.dump());
            for (auto& p : plugins) {
                try {
                    p->handle_task(task);
                } catch (const std::exception& ex) {
                    std::cerr << "[plugin] exception from " << p->name() << ": " << ex.what() << std::endl;
                } catch (...) {
                    std::cerr << "[plugin] unknown exception from " << p->name() << std::endl;
                }
            }
        });

        spectre::http_server http_server(io, 8081, network);

        std::cout << "spectre-d: daemon started" << std::endl;

        boost::asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int) {
            io.stop();
        });

        io.run();

    } catch (const std::exception& e) {
        std::cerr << "spectre-d: exception: " << e.what() << std::endl;
    }

    spectre::shutdown_proof_queue();
    spectre::stop_canary_monitor();
    std::cout << "spectre-d: shutdown" << std::endl;

    return 0;
} 