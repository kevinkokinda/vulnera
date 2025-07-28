#pragma once
#include <string>
#include <nlohmann/json.hpp>

namespace spectre {
using json = nlohmann::json;
struct Task {
    json data;
};
class Plugin {
public:
    virtual ~Plugin() = default;
    virtual void handle_task(const Task&) = 0;
    virtual std::string name() const = 0;
};
} // namespace spectre

extern "C" spectre::Plugin* spectre_create_plugin(); 