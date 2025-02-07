#ifndef COMPLIANCE_H
#define COMPLIANCE_H

#ifdef __cplusplus
extern "C"
{
#endif

int ComplianceIsValidResourceIdRuleId(const char* resourceId, const char* ruleId, const char* payloadKey, void* log);

void ComplianceInitialize(void* log);
void ComplianceShutdown(void* log);

int ComplianceMmiGet(const char* componentName, const char* objectName, char** payload, int* payloadSizeBytes, unsigned int maxPayloadSizeBytes, void* log);
int ComplianceMmiSet(const char* componentName, const char* objectName, const char* payload, const int payloadSizeBytes, void* log);


#ifdef __cplusplus
}
#endif

#endif // ASB_H
