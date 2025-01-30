#ifndef PROCEDURE_HPP
#define PROCEDURE_HPP

#include <Result.hpp>
#include <Optional.hpp>

#include <map>
#include <string>

struct json_value_t;
struct json_object_t;

namespace compliance
{
    class Procedure
    {
        std::map<std::string, std::string> mParameters;
        json_value_t* mAuditRule = nullptr;
        json_value_t* mRemediationRule = nullptr;

    public:
        Procedure(std::map<std::string, std::string> parameters);
        ~Procedure();

        Procedure(const Procedure&) = delete;
        Procedure& operator=(const Procedure&) = delete;
        Procedure(Procedure&&);
        Procedure& operator=(Procedure&&);

        const std::map<std::string, std::string>& parameters() const noexcept { return mParameters; }
        const json_object_t* audit() const noexcept;
        const json_object_t* remediation() const noexcept;

        Optional<Error> setParameter(const std::string& key, std::string value) noexcept;
        Optional<Error> setAudit(const json_value_t* rule) noexcept;
        Optional<Error> setRemediation(const json_value_t* rule) noexcept;
    };
} // namespace compliance

#endif // PROCEDURE_HPP
