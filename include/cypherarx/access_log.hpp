#pragma once

#include <cstdint>
#include <string>

namespace cypherarx {

enum class AccessAction { view, copy };

struct AccessRecord {
    std::string entry_uuid;
    AccessAction action = AccessAction::view;
    std::int64_t accessed_at = 0;

    bool operator==(const AccessRecord&) const = default;
};

}
