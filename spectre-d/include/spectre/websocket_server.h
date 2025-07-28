#pragma once
#include <string>
#include <memory>
#include <functional>

namespace spectre {
class WebSocketServer {
public:
    using MessageHandler = std::function<void(const std::string&)>;
    
    WebSocketServer(int port = 8889);
    ~WebSocketServer();
    
    void start();
    void stop();
    void broadcast(const std::string& message);
    void set_message_handler(MessageHandler handler);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace spectre 