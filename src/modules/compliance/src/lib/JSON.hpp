#ifndef JSON_HPP
#define JSON_HPP

#include <memory>

struct json_value_t;

namespace compliance
{
    struct JSONDeleter
    {
        void operator()(json_value_t* value) const;
    };
    using JSON = std::unique_ptr<json_value_t, JSONDeleter>;

    JSON parseJSON(const char* input);
} // namespace compliance

#endif // JSON_HPP
