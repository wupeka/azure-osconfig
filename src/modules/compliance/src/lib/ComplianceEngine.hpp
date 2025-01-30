// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_HPP
#define COMPLIANCE_ENGINE_HPP

#include <Mmi.h>
#include <Logging.h>

#include <memory>
#include <string>

namespace compliance
{
    class Engine
    {
        OSCONFIG_LOG_HANDLE mLog = nullptr;
        unsigned int mMaxPayloadSize = 0;

        bool loadDatabase(const char* fileName) noexcept;
    public:
        Engine() noexcept;
        ~Engine() = default;

        void setMaxPayloadSize(unsigned int value) noexcept;
        unsigned int getMaxPayloadSize() const noexcept;
        OSCONFIG_LOG_HANDLE log() const noexcept;

        const char* getMoguleInfo() const noexcept;
        bool loadConfigurationFile() noexcept;

        int mmiGet(const char* objectName) const;
        int mmiSet(const char* objectName, const char* payload, const int payloadSizeBytes) const;
    };
}

#endif // COMPLIANCE_ENGINE_HPP