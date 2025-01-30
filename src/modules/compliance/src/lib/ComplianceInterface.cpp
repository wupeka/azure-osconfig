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

void ComplianceInitialize()
{
    try
    {
        g_compliance.reset(new compliance::Engine());
    }
    catch(const std::exception& e)
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
    try
    {
        g_compliance->setMaxPayloadSize(maxPayloadSizeBytes);
        if (g_compliance->loadConfigurationFile() == false)
        {
            OsConfigLogError(g_compliance->log(), "ComplianceMmiOpen failed to load configuration file");
            return NULL;
        }

        OsConfigLogInfo(g_compliance->log(), "MmiOpen(%s, %d) returning %p", clientName, maxPayloadSizeBytes, g_compliance.get());
        return g_compliance.get();
    }
    catch(const std::exception& e)
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiOpen failed: %s", e.what());
    }

    return nullptr;
}

static bool IsValidSession(MMI_HANDLE clientSession)
{
    return clientSession == g_compliance.get();
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

int ComplianceMmiGetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
{
    if ((NULL == payload) || (NULL == payloadSizeBytes))
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiGetInfo(%s, %p, %p) called with invalid arguments", clientName, payload, payloadSizeBytes);
        return EINVAL;
    }

    *payload = (MMI_JSON_STRING)strdup(g_compliance->getMoguleInfo());
    if (!*payload)
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiGetInfo: failed to duplicate module info");
        return ENOMEM;
    }

    *payloadSizeBytes = (int)strlen(g_compliance->getMoguleInfo());
    return 0;
}

int ComplianceMmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes)
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

    int result = -1;
    try
    {
        result = g_compliance->mmiGet(objectName);

        // To be replaced by results from the engine
        *payload = strdup("test");
        *payloadSizeBytes = 4;
    }
    catch (const std::exception& e)
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiGet failed: %s", e.what());
    }

    OsConfigLogInfo(g_compliance->log(), "MmiGet(%p, %s, %s, %.*s, %d) returning %d", clientSession, componentName, objectName, *payloadSizeBytes, *payload, *payloadSizeBytes, result);
    return result;
}

int ComplianceMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes)
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

    int result = -1;
    try
    {
        result = g_compliance->mmiSet(objectName, payload, payloadSizeBytes);
    }
    catch(const std::exception& e)
    {
        OsConfigLogError(g_compliance->log(), "ComplianceMmiSet failed: %s", e.what());
    }
    
    OsConfigLogInfo(g_compliance->log(), "MmiSet(%p, %s, %s, %.*s, %d), returning %d", clientSession, componentName, objectName, payloadSizeBytes, payload, payloadSizeBytes, result);
    return result;
}

void ComplianceMmiFree(MMI_JSON_STRING payload)
{
    FREE_MEMORY(payload);
}