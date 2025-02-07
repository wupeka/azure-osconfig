// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../Common.h"
#include <ComplianceInterface.hpp>

static MMI_HANDLE g_compliance = NULL;

static const char gComponentName[] = "Compliance";

int BaselineIsValidResourceIdRuleId(const char* resourceId, const char* ruleId, const char* payloadKey, void* log)
{
    (void)resourceId;
    (void)ruleId;
    (void)payloadKey;
    (void)log;
    return 0;
}

void BaselineInitialize(void* log)
{
    (void)log;
    ComplianceInitialize(log);
    g_compliance = ComplianceMmiOpen("Compliance", -1);
    ComplianceSetNRPContext();
}

void BaselineShutdown(void* log)
{
    (void)log;
    if(NULL == g_compliance)
    {
        return;
    }

    ComplianceMmiClose(g_compliance);
    ComplianceShutdown();
    g_compliance = NULL;
}

int BaselineMmiGet(const char* componentName, const char* objectName, char** payload, int* payloadSizeBytes, unsigned int maxPayloadSizeBytes, void* log)
{
    int status;
    (void)log;

    if (0 != strcmp(componentName, gComponentName))
    {
        return EINVAL;
    }

    if (NULL == g_compliance)
    {
        return EINVAL;
    }

    if ((status = ComplianceSetMaxPayloadSize(g_compliance, maxPayloadSizeBytes)) != 0)
    {
        return status;
    }

    return ComplianceMmiGet(g_compliance, componentName, objectName, payload, payloadSizeBytes);
}

int BaselineMmiSet(const char* componentName, const char* objectName, const char* payload, const int payloadSizeBytes, void* log)
{
    (void)log;

    if (0 != strcmp(componentName, gComponentName))
    {
        return EINVAL;
    }

    return ComplianceMmiSet(g_compliance, componentName, objectName, payload, payloadSizeBytes);
}
