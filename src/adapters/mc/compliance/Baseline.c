// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../Common.h"
#include <Compliance.h>

static const char gComponentName[] = "Compliance";

int BaselineIsValidResourceIdRuleId(const char* resourceId, const char* ruleId, const char* payloadKey, void* log)
{
    return ComplianceIsValidResourceIdRuleId(resourceId, ruleId, payloadKey, log);
}

void BaselineInitialize(void* log)
{
    ComplianceInitialize(log);
}

void BaselineShutdown(void* log)
{
    ComplianceShutdown(log);
}

int BaselineMmiGet(const char* componentName, const char* objectName, char** payload, int* payloadSizeBytes, unsigned int maxPayloadSizeBytes, void* log)
{
    if (0 != strcmp(componentName, gComponentName))
    {
        return EINVAL;
    }
    return ComplianceMmiGet(componentName, objectName, payload, payloadSizeBytes, maxPayloadSizeBytes, log);
}

int BaselineMmiSet(const char* componentName, const char* objectName, const char* payload, const int payloadSizeBytes, void* log)
{
    if (0 != strcmp(componentName, gComponentName))
    {
        return EINVAL;
    }
    return ComplianceMmiSet(componentName, objectName, payload, payloadSizeBytes, log);
}
