#include "../Common.h"
#include <ComplianceInterface.hpp>

static MMI_HANDLE g_compliance = NULL;

static int NRPIsValidResourceIdRuleId(const char* resourceId, const char* ruleId, const char* payloadKey, void* log)
{
    (void)resourceId;
    (void)ruleId;
    (void)payloadKey;
    (void)log;
    return 0;
}

static void NRPInitialize(void* log)
{
    (void)log;
    ComplianceInitialize(log);
    g_compliance = ComplianceMmiOpen("Compliance", -1);
    ComplianceSetNRPContext();
}

void NRPShutdown(void* log)
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

int NRPMmiGet(const char* componentName, const char* objectName, char** payload, int* payloadSizeBytes, unsigned int maxPayloadSizeBytes, void* log)
{
    int status;
    (void)log;

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

int NRPMmiSet(const char* componentName, const char* objectName, const char* payload, int payloadSizeBytes, void* log)
{
    (void)log;
    return ComplianceMmiSet(g_compliance, componentName, objectName, payload, payloadSizeBytes);
}

OSCONFIG_REGISTER_COMPONENT(Compliance, NRPInitialize, NRPShutdown, NRPMmiGet, NRPMmiSet, NRPIsValidResourceIdRuleId);
