#pragma once

namespace spectre {

class TorProxy {
public:
    static TorProxy& get_instance();

    bool is_available();

private:
    TorProxy();
    bool available_ = false;
};

} // namespace spectre 