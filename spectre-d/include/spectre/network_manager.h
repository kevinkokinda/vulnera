#pragma once
#include <functional>
#include <memory>
#include "plugin.h"

namespace spectre {
class NetworkManager {
public:
    using TaskHandler = std::function<void(const Task&)>;
    
    NetworkManager();
    ~NetworkManager();
    
    void start(TaskHandler handler);
    void stop();
    void publish_task(const Task& task);
    
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace spectre 