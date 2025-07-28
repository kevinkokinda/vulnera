#include "spectre/plugin_loader.h"

#include <filesystem>
#include <dlfcn.h>
#include <iostream>
#include <cstdlib>
#include <set>

namespace fs = std::filesystem;

namespace spectre {
namespace {
using create_fn = Plugin* (*)();
}
PluginLoader::PluginLoader(const std::string& directory) : dir(directory) {}
std::vector<std::shared_ptr<Plugin>> PluginLoader::load_all() {
    std::vector<std::shared_ptr<Plugin>> out;
    std::set<std::string> names;
    bool debug = std::getenv("SPECTRE_DEBUG") != nullptr;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (!entry.is_regular_file()) continue;
        auto ext = entry.path().extension();
        if (ext != ".so" && ext != ".dll" && ext != ".dylib") continue;
        if(debug) std::cout << "[plugin_loader] loading " << entry.path() << std::endl;
        void* handle = dlopen(entry.path().c_str(), RTLD_NOW);
        if (!handle) {
            std::cerr << "[plugin_loader] dlopen failed for " << entry.path() << ": " << dlerror() << std::endl;
            continue;
        }
        auto sym = reinterpret_cast<create_fn>(dlsym(handle, "spectre_create_plugin"));
        if (!sym) {
            std::cerr << "[plugin_loader] dlsym failed for " << entry.path() << ": " << dlerror() << std::endl;
            dlclose(handle);
            continue;
        }
        Plugin* raw = nullptr;
        try {
            raw = sym();
        } catch (const std::exception& ex) {
            std::cerr << "[plugin_loader] plugin ctor threw for " << entry.path() << ": " << ex.what() << std::endl;
        } catch (...) {
            std::cerr << "[plugin_loader] plugin ctor threw (unknown) for " << entry.path() << std::endl;
        }
        if (!raw) {
            dlclose(handle);
            continue;
        }
        std::string pname;
        try { pname = raw->name(); } catch (...) { pname = "<unknown>"; }
        if (!names.insert(pname).second) {
            std::cerr << "[plugin_loader] duplicate plugin name: " << pname << " (skipping)" << std::endl;
            delete raw;
            dlclose(handle);
            continue;
        }
        auto deleter = [handle](Plugin* p) {
            delete p;
            dlclose(handle);
        };
        out.emplace_back(raw, deleter);
    }
    return out;
}
} // namespace spectre 