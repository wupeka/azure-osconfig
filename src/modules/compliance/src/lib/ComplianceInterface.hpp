// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef COMPLIANCE_H
#define COMPLIANCE_H

#include "../inc/Mmi.h"

#ifdef __cplusplus
extern "C"
{
#endif

void ComplianceInitialize(void);
void ComplianceShutdown(void);

MMI_HANDLE ComplianceMmiOpen(const char* clientName, const unsigned int maxPayloadSizeBytes);
void ComplianceMmiClose(MMI_HANDLE clientSession);
int ComplianceMmiGetInfo(const char* clientName, MMI_JSON_STRING* payload, int* payloadSizeBytes);
int ComplianceMmiGet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, MMI_JSON_STRING* payload, int* payloadSizeBytes);
int ComplianceMmiSet(MMI_HANDLE clientSession, const char* componentName, const char* objectName, const MMI_JSON_STRING payload, const int payloadSizeBytes);
void ComplianceMmiFree(MMI_JSON_STRING payload);

#ifdef __cplusplus
}
#endif

#endif // COMPLIANCE_H
