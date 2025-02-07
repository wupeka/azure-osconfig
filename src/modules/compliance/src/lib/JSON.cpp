#include "JSON.hpp"

#include "parson.h"

namespace compliance
{
    void JSONDeleter::operator()(json_value_t* value) const
    {
        json_value_free(value);
    }

    JSON parseJSON(const char* input)
    {
        return JSON(json_parse_string(input), JSONDeleter());
    }
} // namespace compliance
