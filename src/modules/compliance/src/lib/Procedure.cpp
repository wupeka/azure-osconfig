#include "Procedure.hpp"
#include <Logging.h>

#include <parson.h>

namespace compliance
{
    Procedure::Procedure(std::map<std::string, std::string> parameters)
        : mParameters(std::move(parameters))
    {
    }

    Procedure::~Procedure()
    {
        json_value_free(mAuditRule);
        json_value_free(mRemediationRule);
    }

    Procedure::Procedure(Procedure&& other)
    {
        mAuditRule = other.mAuditRule;
        other.mAuditRule = nullptr;
        mRemediationRule = other.mRemediationRule;
        other.mRemediationRule = nullptr;
        mParameters = std::move(other.mParameters);
    }

    Procedure& Procedure::operator=(Procedure&& other)
    {
        if(this == &other)
        {
            return *this;
        }

        mAuditRule = other.mAuditRule;
        other.mAuditRule = nullptr;
        mRemediationRule = other.mRemediationRule;
        other.mRemediationRule = nullptr;
        return *this;
    }

    Optional<Error> Procedure::setParameter(const std::string& key, std::string value) noexcept
    {
        auto it = mParameters.find(key);
        if(it == mParameters.end())
        {
            return Error("Unknown parameter " + key);
        }

        mParameters[key] = std::move(value);
        return {};
    }

    Optional<Error> Procedure::setAudit(const json_value_t* rule) noexcept
    {
        if(mAuditRule != nullptr)
        {
            return Error("Audit rule already set");
        }

        mAuditRule = json_value_deep_copy(rule);
        return {};
    }

    const JSON_Object* Procedure::audit() const noexcept {
        if( mAuditRule == nullptr )
        {
            return nullptr;
        }
        return json_value_get_object(mAuditRule);
    }

    Optional<Error> Procedure::setRemediation(const json_value_t* rule) noexcept
    {
        if (mRemediationRule != nullptr)
        {
            return Error("Remediation rule already set");
        }

        mRemediationRule = json_value_deep_copy(rule);
        return {};
    }

    const JSON_Object* Procedure::remediation() const noexcept {
        if (mRemediationRule == nullptr)
        {
            return nullptr;
        }
        return json_value_get_object(mRemediationRule);
    }
} // namespace compliance
