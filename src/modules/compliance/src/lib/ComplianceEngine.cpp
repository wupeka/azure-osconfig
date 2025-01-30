// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ComplianceEngine.hpp"

#include <CommonUtils.h>
#include "../../../../common/compliance/Compliance.h"
#include "base64.h"

#include "parson.h"
#include <string>
#include <vector>
#include <map>

namespace compliance
{
    // static constexpr const char* cModuleName = "OSConfig Compliance module";
    static constexpr const char* cLogFile = "/var/log/osconfig_compliance.log";
    static constexpr const char* cRolledLogFile = "/var/log/osconfig_compliance.bak";
    static constexpr const char* cModuleInfo = "{\"Name\": \"Compliance\","
        "\"Description\": \"Provides functionality to audit and remediate Security Baseline policies on device\","
        "\"Manufacturer\": \"Microsoft\","
        "\"VersionMajor\": 2,"
        "\"VersionMinor\": 0,"
        "\"VersionInfo\": \"Dilithium\","
        "\"Components\": [\"Compliance\"],"
        "\"Lifetime\": 2,"
        "\"UserAccount\": 0}";


    Optional<Error> Engine::parseDatabase(const char* jsonStr)
    {
        auto json = parseJSON(jsonStr);
        const auto* rootObject = json_value_get_object(json.get());
        if (!rootObject)
        {
            return Error("Failed to parse root object");
        }

        auto count = json_object_get_count(rootObject);
        for (decltype(count) i = 0; i < count; ++i)
        {
            const char* key = json_object_get_name(rootObject, i);
            if(!key)
            {
                return Error("Failed to get object key");
            }

            OsConfigLogInfo(log(), "Loading rule %s", key);
            auto* itemObj = json_object_get_object(rootObject, key);
            if(!itemObj)
            {
                return Error(std::string("Expected JSON object at key ") + std::string(key));
            }

            // Audit is mandatory
            const auto* auditRule = json_object_get_object(itemObj, "audit");
            if (auditRule == nullptr)
            {
                return Error("Failed to parse audit object");
            }

            // Remediation is optional
            const auto* remediationRule = json_object_get_object(itemObj, "remediate");

            // Parameters are mandatory
            const auto* parametersObject = json_object_get_object(itemObj, "parameters");

            std::map<std::string, std::string> parameters;
            auto paramsCount = json_object_get_count(parametersObject);
            for (decltype(paramsCount) j = 0; j < paramsCount; ++j)
            {
                const char* paramKey = json_object_get_name(parametersObject, j);
                const char* paramVal = json_object_get_string(parametersObject, paramKey);
                if(paramKey == nullptr || paramVal == nullptr)
                {
                    return Error("Failed to parse parameters");
                }

                OsConfigLogInfo(log(), "Adding parameter %s=%s", paramKey, paramVal);
                parameters[paramKey] = paramVal;
            }

            auto procedure = Procedure(std::move(parameters));
            auto error = procedure.setAudit(json_value_deep_copy(json_object_get_wrapping_value(auditRule)));
            if (error)
            {
                return error;
            }

            if (remediationRule != nullptr)
            {
                error = procedure.setRemediation(json_value_deep_copy(json_object_get_wrapping_value(remediationRule)));
                if (error)
                {
                    return error;
                }
            }

            mDatabase.insert({key, std::move(procedure)});
        }

        return {};
    }

    Optional<Error> Engine::loadDatabase(const char* fileName)
    {
        auto* database = LoadStringFromFile(fileName, false, log());
        if (!database)
        {
            return Error("Failed to load configuration file");
        }

        auto error = parseDatabase(database);
        FREE_MEMORY(database);
        if (error)
        {
            OsConfigLogError(log(), "%s", error->message.c_str());
        }
        else
        {
            OsConfigLogInfo(log(), "Loaded compliance database from %s", fileName);
        }

        return error;
    }

    Engine::Engine(void* log) noexcept : mLog{ log }, mLocalLog{ false }
    {
        if (nullptr == mLog)
        {
            return;
        }
    }

    Engine::Engine() noexcept : mLocalLog{ true }
    {
        mLog = OpenLog(cLogFile, cRolledLogFile);
    }

    Engine::~Engine()
    {
        if(mLocalLog)
        {
            CloseLog(&mLog);
        }
    }

    void Engine::setMaxPayloadSize(unsigned int value) noexcept {
        mMaxPayloadSize = value;
    }

    void Engine::setContext(Context context) noexcept
    {
        OsConfigLogInfo(log(), "Engine::setContext(%d)", static_cast<int>(context));
        mContext = context;
    }

    unsigned int Engine::getMaxPayloadSize() const noexcept {
        return mMaxPayloadSize;
    }

    OSCONFIG_LOG_HANDLE Engine::log() const noexcept {
        return mLog;
    }

    const char* Engine::getMoguleInfo() const noexcept
    {
        return cModuleInfo;
    }

    Result<Engine::Payload> Engine::mmiGet(const char* objectName) {
        OsConfigLogInfo(log(), "Engine::mmiGet(%s)", objectName);

        auto result = Payload{};
        const JSON_Object* rule = nullptr;
        constexpr const char* auditPrefix = "audit";

        if (mContext == Context::MMI) // RC/DC and other scenarios
        {
            auto key = std::string(objectName);
            if (key.find(auditPrefix) == 0)
            {
                key = key.substr(strlen(auditPrefix));
            }

            OsConfigLogInfo(log(), "Looking for rule %s", key.c_str());
            auto it = mDatabase.find(key);
            if (it == mDatabase.end())
            {
                return Error("Rule not found");
            }

            rule = it->second.audit();

            auto rc = ComplianceExecuteAudit(rule, it->second.parameters(), &result.data, &result.size, log());
            if (rc != 0)
            {
                return Error("ComplianceExecuteRule failed", rc);
            }
        }
        else // NRP transaction
        {
            auto it = mDatabase.find("NRP-placeholder");
            if (it == mDatabase.end())
            {
                OsConfigLogError(log(), "Rule not found");
                return Error("Rule not found");
            }
            const auto& parameters = it->second.parameters();

            // try to decode base64 rule
            OsConfigLogInfo(log(), "Attempting to decode base64 rule %s", objectName);
            auto json = decodeB64JSON(objectName);
            if (!json.has_value())
            {
                OsConfigLogError(log(), "Failed to decode base64 JSON: %s", json.error().message.c_str());
                return json.error();
            }

            auto object = json_value_get_object(json.value().get());
            if (object == nullptr)
            {
                OsConfigLogError(log(), "Failed to parse JSON object");
                return Error("Failed to parse JSON object");
            }

            auto value = json_object_get_value(object, auditPrefix);
            if (value == nullptr)
            {
                OsConfigLogError(log(), "Failed to get audit value");
                return Error("Failed to get audit value");
            }

            rule = json_value_get_object(value);
            if (rule == nullptr)
            {
                OsConfigLogError(log(), "Failed to get audit object");
                return Error("Failed to get audit object");
            }

            auto rc = ComplianceExecuteAudit(rule, parameters, &result.data, &result.size, log());
            if (rc != 0)
            {
                OsConfigLogError(log(), "ComplianceExecuteRule failed with %d", rc);
                return Error("ComplianceExecuteRule failed", rc);
            }
        }

        return result;
    }

    Result<JSON> Engine::decodeB64JSON(const char* input) const
    {
        unsigned int baseLen = 0;

        Base64Decode(input, NULL, &baseLen);
        if (0 == baseLen)
        {
            return Error("Failed to decode base64 input length", EINVAL);
        }

        std::unique_ptr<char[]> inputJSONString(new char[baseLen]);
        if (Base64Decode(input, (unsigned char*)inputJSONString.get(), &baseLen) != 0)
        {
            return Error("Failed to decode base64 input", EINVAL);
        }

        auto result = json_parse_string(inputJSONString.get());
        if (NULL == result)
        {
            return Error("Failed to parse JSON", EINVAL);
        }

        return JSON(result);
    }

    Optional<Error> Engine::mmiSet(const char* objectName, const char* payload, const int payloadSizeBytes) {
        OsConfigLogInfo(log(), "Engine::mmiSet(%s, %.*s)", objectName, payloadSizeBytes, payload);
        const JSON_Object* rule = nullptr;
        constexpr const char* remediatePrefix = "remediate";
        constexpr const char* initPrefix = "init";

        if (mContext == Context::MMI)
        {
            auto key = std::string(objectName);
            if (key.find(remediatePrefix) == 0)
            {
                key = key.substr(strlen(remediatePrefix));
            }
            else if (key.find(initPrefix) == 0)
            {
                key = key.substr(strlen(initPrefix));
            }

            auto it = mDatabase.find(key);
            if (it == mDatabase.end())
            {
                OsConfigLogError(log(), "Rule not found");
                return Error("Rule not found");
            }

            auto result = ComplianceExecuteRemediation(it->second.remediation(), it->second.parameters(), payload, payloadSizeBytes, log());
            if (result != 0)
            {
                OsConfigLogError(log(), "ComplianceExecuteRule failed with %d", result);
                return Error("ComplianceExecuteRule failed", result);
            }
        }
        else
        {
            // try to decode base64 rule
            auto result = decodeB64JSON(objectName);
            if (!result.has_value())
            {
                OsConfigLogError(log(), "Failed to decode base64 JSON: %s", result.error().message.c_str());
                return result.error();
            }

            auto object = json_value_get_object(result.value().get());
            if (object == nullptr)
            {
                OsConfigLogError(log(), "Failed to parse JSON object");
                return Error("Failed to parse JSON object");
            }

            auto value = json_object_get_value(object, "parameters");
            if (nullptr != value)
            {
                // TODO(robertwoj): This should be based on rule name
                auto it = mDatabase.find("NRP-placeholder");
                if (it != mDatabase.end())
                {
                    OsConfigLogInfo(log(), "Resetting parameters for NRP operation");
                    mDatabase.erase(it);
                }

                auto paramsObj = json_value_get_object(value);
                if (paramsObj)
                {
                    std::map<std::string, std::string> parameters;
                    auto count = json_object_get_count(paramsObj);
                    for (decltype(count) i = 0; i < count; ++i)
                    {
                        const char* key = json_object_get_name(paramsObj, i);
                        const char* val = json_object_get_string(paramsObj, key);
                        if (val)
                        {
                            parameters.insert({key, val});
                        }
                    }
                    mDatabase.insert({ "NRP-placeholder", std::move(parameters) });
                }
            }
            else
            {
                // TODO(robertwoj): This should be based on rule name
                auto it = mDatabase.find("NRP-placeholder");
                if (it == mDatabase.end())
                {
                    OsConfigLogError(log(), "Out-of-order NRP operation: parameters must be called first");
                    return Error("Out-of-order NRP operation: parameters must be called first", EINVAL);
                }

                value = json_object_get_value(object, "remediate");
                if (value != nullptr)
                {
                    rule = json_value_get_object(value);
                    if (rule == nullptr)
                    {
                        OsConfigLogError(log(), "Failed to get remediate object");
                        return Error("Failed to get remediate object");
                    }

                    OsConfigLogInfo(log(), "Executing rule %s", objectName);
                    mDatabase.erase("NRP-placeholder");
                    auto result = ComplianceExecuteRemediation(rule, it->second.parameters(), payload, payloadSizeBytes, log());
                    if (result != 0)
                    {
                        OsConfigLogError(log(), "ComplianceExecuteRule failed with %d", result);
                        return Error("ComplianceExecuteRule failed", result);
                    }
                }
            }
        }

        return {};
    }

    bool Engine::loadConfigurationFile() noexcept
    {
        auto* config = LoadStringFromFile("/etc/osconfig/osconfig.json", false, log());
        if (!config)
        {
            OsConfigLogError(log(), "Failed to load configuration file");
            return false;
        }

        auto* databaseFile = GetComplianceDatabaseFromJsonConfig(config, log());
        if (!databaseFile)
        {
            OsConfigLogError(log(), "Failed to load compliance database from configuration file");
            FREE_MEMORY(config);
            return false;
        }

        try
        {
            auto error = loadDatabase(databaseFile);
            FREE_MEMORY(databaseFile);
            FREE_MEMORY(config);
            if (error)
            {
                OsConfigLogError(log(), "%s", error->message.c_str());
                return false;
            }

            return true;
        }
        catch(const std::exception& e)
        {
            OsConfigLogError(log(), "Failed to load compliance database: %s", e.what());
            FREE_MEMORY(databaseFile);
            FREE_MEMORY(config);
            return false;
        }
    }
}
