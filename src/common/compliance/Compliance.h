#ifndef COMPLIANCE_H
#define COMPLIANCE_H

#ifdef __cplusplus
extern "C"
{
#endif

// int ComplianceIsValidResourceIdRuleId(const char* resourceId, const char* ruleId, const char* payloadKey, void* log);

// void ComplianceInitialize(void* log);
// void ComplianceShutdown(void* log);

// int ComplianceMmiGet(const char* componentName, const char* objectName, char** payload, int* payloadSizeBytes, unsigned int maxPayloadSizeBytes, void* log);
// int ComplianceMmiSet(const char* componentName, const char* objectName, const char* payload, const int payloadSizeBytes, void* log);

#ifdef __cplusplus
}

#include <map>
#include <string>

enum class Action
{
    Audit,
    Remediate
};

struct json_object_t;

void ComplianceSetParameters(const std::map<std::string, std::string>& params);
int ComplianceExecuteAudit(const json_object_t* rule, const std::map<std::string, std::string>& parameters, char** payload, int* payloadSizeBytes, void* log);
int ComplianceExecuteRemediation(const json_object_t* rule, std::map<std::string, std::string> parameters, void* log);
#endif

#endif // COMPLIANCE_H
