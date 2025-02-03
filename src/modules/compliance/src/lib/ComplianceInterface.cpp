// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <CommonUtils.h>
#include <Logging.h>
#include <Asb.h>

#include "ComplianceInterface.hpp"
#include "ComplianceEngine.hpp"

// ---------------------------------------------------------------
//                  MMI module C interface
// ---------------------------------------------------------------

static std::unique_ptr <compliance::Engine> g_compliance;

static bool IsValidSession(MMI_HANDLE clientSession)
{
    return clientSession == g_compliance.get();
}

void ComplianceInitialize(void* log)
{
    try
    {
        if (log)
        {
            g_compliance.reset(new compliance::Engine(log));
        }
        else
        {
            g_compliance.reset(new compliance::Engine());
        }
    }
    catch (const std::exception& e)
    {
        OsConfigLogError(nullptr, "ComplianceInitialize failed: %s", e.what());
    }
}

void ComplianceShutdown(void)
{
    OsConfigLogInfo(nullptr, "ComplianceShutdown");
    g_compliance.reset(nullptr);
}

MMI_HANDLE ComplianceMmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes)
{
    OsConfigLogInfo(g_compliance->log(), "MmiOpen(%s, %d) returning %p", clientName, maxPayloadSizeBytes, g_compliance.get());
    return g_compliance.get();
}

int ComplianceSetMaxPayloadSize(MMI_HANDLE clientSession, const unsigned int maxPayloadSizeBytes)
{
    if (!IsValidSession(clientSession))
    {
        OsConfigLogError(g_compliance->log(), "SetMaxPayloadSize() called outside of a valid session");
        return EINVAL;
    }

    g_compliance->setMaxPayloadSize(maxPayloadSizeBytes);
    OsConfigLogInfo(g_compliance->log(), "SetMaxPayloadSize(%p, %d)", clientSession, maxPayloadSizeBytes);
    return 0;
}

int ComplianceLoadLocalDatabase(MMI_HANDLE clientSession)
{
    if (!IsValidSession(clientSession))
    {
        OsConfigLogError(g_compliance->log(), "EnableLocalDatabase() called outside of a valid session");
        return EINVAL;
    }

    OsConfigLogInfo(g_compliance->log(), "ComplianceEnableLocalDatabase(%p)", clientSession);
    return g_compliance->loadConfigurationFile() ? 0 : EINVAL;
}

void ComplianceMmiClose(MMI_HANDLE clientSession)
{
    if (IsValidSession(clientSession))
    {
        OsConfigLogInfo(g_compliance->log(), "MmiClose(%p)", clientSession);
    }
    else
    {
        OsConfigLogError(g_compliance->log(), "MmiClose() called outside of a valid session");
    }
}

int ComplianceMmiGetInfo(const char* clientName, char** payload, int* payloadSizeBytes)
{
    if ((NULL == payload) || (NULL == payloadSizeBytes))
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiGetInfo(%s, %p, %p) called with invalid arguments", clientName, payload, payloadSizeBytes);
        return EINVAL;
    }

    *payload = (char*)strdup(g_compliance->getMoguleInfo());
    if (!*payload)
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiGetInfo: failed to duplicate module info");
        return ENOMEM;
    }

    *payloadSizeBytes = (int)strlen(g_compliance->getMoguleInfo());
    return 0;
}

int ComplianceMmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, char** payload, int* payloadSizeBytes)
{
    if ((NULL == componentName) || (NULL == objectName) || (NULL == payload) || (NULL == payloadSizeBytes))
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiGet(%s, %s, %p, %p) called with invalid arguments", componentName, objectName, payload, payloadSizeBytes);
        return EINVAL;
    }

    if (!IsValidSession(clientSession))
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiGet(%s, %s) called outside of a valid session", componentName, objectName);
        return EINVAL;
    }

    if (strcmp(componentName, "Compliance"))
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiGet called for an unsupported component name (%s)", componentName);
        return EINVAL;
    }

    *payload = NULL;
    *payloadSizeBytes = 0;

    try
    {
        auto result = g_compliance->mmiGet(objectName);
        if(result.has_value())
        {
            *payload = strdup(result.value().data);
            *payloadSizeBytes = result.value().size;
            OsConfigLogInfo(g_compliance->log(), "MmiGet(%p, %s, %s, %.*s)", clientSession, componentName, objectName, *payloadSizeBytes, *payload);
            return 0;
        }
        else
        {
            OsConfigLogError(g_compliance->log(), "ComplianceMmiGet failed: %s", result.error().message.c_str());
            return result.error().code;
        }
    }
    catch (const std::exception& e)
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiGet failed: %s", e.what());
    }

    return -1;
}

int ComplianceMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const char* payload, const int payloadSizeBytes)
{
    if (!IsValidSession(clientSession))
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiSet(%s, %s) called outside of a valid session", componentName, objectName);
        return EINVAL;
    }

    if (strcmp(componentName, "Compliance"))
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiGet called for an unsupported component name (%s)", componentName);
        return EINVAL;
    }

    try
    {
        auto error = g_compliance->mmiSet(objectName, payload, payloadSizeBytes);
        if (!error)
        {
            OsConfigLogInfo(g_compliance->log(), "MmiSet(%p, %s, %s, %.*s, %d)", clientSession, componentName, objectName, payloadSizeBytes, payload, payloadSizeBytes);
            return 0;
        }
        else
        {
            OsConfigLogError(g_compliance->log(), "ComplianceMmiSet failed: %s", error->message.c_str());
            return error->code;
        }
    }
    catch (const std::exception& e)
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiSet failed: %s", e.what());
    }

    return -1;
}

void ComplianceMmiFree(char* payload)
{
    FREE_MEMORY(payload);
}

void ComplianceSetNRPContext(void)
{
    g_compliance->setContext(compliance::Engine::Context::NRP);
}
