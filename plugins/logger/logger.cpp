#include "spectre/plugin.h"
#include <iostream>

namespace {
class LoggerPlugin : public spectre::Plugin {
public:
    void handle_task(const spectre::Task& task) override {
        std::cout << "[logger] " << task.data.dump() << std::endl;
    }
    std::string name() const override { return "logger"; }
};
}

extern "C" spectre::Plugin* spectre_create_plugin() {
    return new LoggerPlugin();
} 