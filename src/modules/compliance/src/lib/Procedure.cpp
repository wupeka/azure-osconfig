#include "Procedure.hpp"
#include <Logging.h>

#include <parson.h>
#include <sstream>

namespace compliance
{
    Procedure::Procedure(const std::string &name)
        : mName(name)
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
        mParameters[key] = std::move(value);
        return {};
    }

    Optional<Error> Procedure::updateUserParameters(const std::string &input) noexcept
    {
        std::istringstream stream(input);
        std::string token;

        while (std::getline(stream, token, ' '))
        {
            // In the non-NRP scenario the token is delimited by double quotes
            if (token.size() >= 2 && token.front() == '"' && token.back() == '"')
            {
                token = token.substr(1, token.size() - 2);
            }

            size_t pos = token.find('=');
            if (pos == std::string::npos)
            {
                continue;
            }

            std::string key = token.substr(0, pos);
            std::string value = token.substr(pos + 1);

            if (!value.empty() && value[0] == '"')
            {
                value.erase(0, 1);
                while (!value.empty() && value.back() == '\\')
                {
                    std::string nextToken;
                    if (std::getline(stream, nextToken, ' '))
                    {
                        value.pop_back();
                        value += ' ' + nextToken;
                    }
                    else
                    {
                        break;
                    }
                }
                if (!value.empty() && value.back() == '"')
                {
                    value.pop_back();
                }
            }

            auto it = mParameters.find(key);
            if (it == mParameters.end())
            {
                return Error("User parameter not found");
            }

            it->second = value;
        }

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
