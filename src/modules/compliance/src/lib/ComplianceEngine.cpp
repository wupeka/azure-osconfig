// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ComplianceEngine.hpp"

#include <CommonUtils.h>

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

    bool Engine::loadDatabase(const char* fileName) noexcept
    {
        auto* database = LoadStringFromFile(fileName, false, log());
        if (!database)
        {
            OsConfigLogError(log(), "Failed to load configuration file");
            return false;
        }

        OsConfigLogInfo(log(), "Loaded compliance database from %s", fileName);
        // TODO: Implement database loading
        return true;
    }

    Engine::Engine() noexcept
    {
        mLog = OpenLog(cLogFile, cRolledLogFile);
    }

    bool loadConfigurationFile() noexcept;
    
    void Engine::setMaxPayloadSize(unsigned int value) noexcept {
        mMaxPayloadSize = value;
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

    int Engine::mmiGet(const char* objectName) const {
        OsConfigLogInfo(log(), "Engine::mmiGet(%s)", objectName);
        return 0;
    }

    int Engine::mmiSet(const char* objectName, const char* payload, const int payloadSizeBytes) const {
        OsConfigLogInfo(log(), "Engine::mmiSet(%s, %.*s)", objectName, payloadSizeBytes, payload);
        return 0;
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

        auto result = loadDatabase(databaseFile);
        OsConfigLogInfo(log(), "Loaded compliance database from %s", databaseFile);
        FREE_MEMORY(databaseFile);
        FREE_MEMORY(config);
        return result;
    }
}