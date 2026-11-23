#pragma once

namespace cypherarx {

struct Settings {
    int log_retention_days = 7;
    int session_duration_minutes = 30;
    bool session_use_os_keyring = true;
    bool session_lock_on_screensaver = true;
    int session_lock_idle_minutes = 10;
    bool session_require_password_for_export = true;

    bool operator==(const Settings&) const = default;
};

}
