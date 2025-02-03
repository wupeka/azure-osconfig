// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCE_ENGINE_HPP
#define COMPLIANCE_ENGINE_HPP

#include <Mmi.h>
#include <Logging.h>

#include <Result.hpp>
#include <Optional.hpp>
#include <Procedure.hpp>
#include <JSON.hpp>

#include <memory>
#include <string>
#include <map>

struct json_object_t;

namespace compliance
{
    class Engine
    {
    public:
        enum class Context
        {
            MMI,
            NRP
        };

        struct Payload
        {
            char* data = nullptr;
            int size = 0;
        };
    private:
        OSCONFIG_LOG_HANDLE mLog = nullptr;
        bool mLocalLog = false;
        unsigned int mMaxPayloadSize = 0;
        std::map<std::string, Procedure> mDatabase;
        Context mContext = Context::MMI;

        Optional<Error> loadDatabase(const char* fileName);

        Result<JSON> decodeB64JSON(const char* input) const;
        Optional<Error> parseDatabase(const char* jsonStr);
    public:
        // Create engine with external log file
        Engine(void* log) noexcept;
        // Create engine with locally initialized log file
        Engine() noexcept;
        ~Engine();

        void setContext(Context context) noexcept;

        void setMaxPayloadSize(unsigned int value) noexcept;
        unsigned int getMaxPayloadSize() const noexcept;
        OSCONFIG_LOG_HANDLE log() const noexcept;

        const char* getMoguleInfo() const noexcept;
        bool loadConfigurationFile() noexcept;

        Result<Payload> mmiGet(const char* objectName);
        Optional<Error> mmiSet(const char* objectName, const char* payload, const int payloadSizeBytes);
    };
}

#endif // COMPLIANCE_ENGINE_HPP
