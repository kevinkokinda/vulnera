#pragma once
#include <memory>
#include <string>
#include <vector>
#include "plugin.h"

namespace spectre {
class PluginLoader {
public:
    explicit PluginLoader(const std::string& directory);
    std::vector<std::shared_ptr<Plugin>> load_all();
private:
    std::string dir;
};
} // namespace spectre 