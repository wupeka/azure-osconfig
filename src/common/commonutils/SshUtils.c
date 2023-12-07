// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "Internal.h"
#include "SshUtils.h"

static const char* g_sshServerService = "sshd";
static const char* g_sshServerConfiguration = "/etc/ssh/sshd_config";

static const char* g_sshProtocol = "Protocol";
static const char* g_sshIgnoreHosts = "IgnoreRhosts";
static const char* g_sshLogLevel = "LogLevel";
static const char* g_sshMaxAuthTries = "MaxAuthTries";
static const char* g_sshAllowUsers = "AllowUsers";
static const char* g_sshDenyUsers = "DenyUsers";
static const char* g_sshAllowGroups = "AllowGroups";
static const char* g_sshDenyGroups = "DenyGroups";
static const char* g_sshHostBasedAuthentication = "HostBasedAuthentication";
static const char* g_sshPermitRootLogin = "PermitRootLogin";
static const char* g_sshPermitEmptyPasswords = "PermitEmptyPasswords";
static const char* g_sshClientAliveCountMax = "ClientAliveCountMax";
static const char* g_sshLoginGraceTime = "LoginGraceTime";
static const char* g_sshClientAliveInterval = "ClientAliveInterval";
static const char* g_sshMacs = "MACs";
static const char* g_sshPermitUserEnvironment = "PermitUserEnvironment";
static const char* g_sshBanner = "Banner";
static const char* g_sshCiphers = "Ciphers";

static const char* g_sshDefaultSshSshdConfigAccess = "600";
static const char* g_sshDefaultSshProtocol = "2";
static const char* g_sshDefaultSshYes = "yes";
static const char* g_sshDefaultSshNo = "no";
static const char* g_sshDefaultSshLogLevel = "INFO";
static const char* g_sshDefaultSshMaxAuthTries = "6";
static const char* g_sshDefaultSshAllowUsers = "*@*";
static const char* g_sshDefaultSshDenyUsers = "root";
static const char* g_sshDefaultSshAllowGroups = "*";
static const char* g_sshDefaultSshDenyGroups = "root";
static const char* g_sshDefaultSshClientIntervalCountMax = "0";
static const char* g_sshDefaultSshClientAliveInterval = "3600";
static const char* g_sshDefaultSshLoginGraceTime = "60";
static const char* g_sshDefaultSshMacs = "hmac-sha2-256,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-512-etm@openssh.com";
static const char* g_sshDefaultSshCiphers = "aes128-ctr,aes192-ctr,aes256-ctr";
static const char* g_sshDefaultSshBannerText =
    "#######################################################################\n\n"
    "Authorized access only!\n\n"
    "If you are not authorized to access or use this system, disconnect now!\n\n"
    "#######################################################################\n";

static const char* g_sshBannerFile = "/etc/azsec/banner.txt";
static const char* g_sshEscapedBannerFilePath = "\\/etc\\/azsec\\/banner.txt";

static const char* g_auditEnsurePermissionsOnEtcSshSshdConfigObject = "auditEnsurePermissionsOnEtcSshSshdConfig";
static const char* g_auditEnsureSshBestPracticeProtocolObject = "auditEnsureSshBestPracticeProtocol";
static const char* g_auditEnsureSshBestPracticeIgnoreRhostsObject = "auditEnsureSshBestPracticeIgnoreRhosts";
static const char* g_auditEnsureSshLogLevelIsSetObject = "auditEnsureSshLogLevelIsSet";
static const char* g_auditEnsureSshMaxAuthTriesIsSetObject = "auditEnsureSshMaxAuthTriesIsSet";
static const char* g_auditEnsureAllowUsersIsConfiguredObject = "auditEnsureAllowUsersIsConfigured";
static const char* g_auditEnsureDenyUsersIsConfiguredObject = "auditEnsureDenyUsersIsConfigured";
static const char* g_auditEnsureAllowGroupsIsConfiguredObject = "auditEnsureAllowGroupsIsConfigured";
static const char* g_auditEnsureDenyGroupsConfiguredObject = "auditEnsureDenyGroupsConfigured";
static const char* g_auditEnsureSshHostbasedAuthenticationIsDisabledObject = "auditEnsureSshHostbasedAuthenticationIsDisabled";
static const char* g_auditEnsureSshPermitRootLoginIsDisabledObject = "auditEnsureSshPermitRootLoginIsDisabled";
static const char* g_auditEnsureSshPermitEmptyPasswordsIsDisabledObject = "auditEnsureSshPermitEmptyPasswordsIsDisabled";
static const char* g_auditEnsureSshClientIntervalCountMaxIsConfiguredObject = "auditEnsureSshClientIntervalCountMaxIsConfigured";
static const char* g_auditEnsureSshClientAliveIntervalIsConfiguredObject = "auditEnsureSshClientAliveIntervalIsConfigured";
static const char* g_auditEnsureSshLoginGraceTimeIsSetObject = "auditEnsureSshLoginGraceTimeIsSet";
static const char* g_auditEnsureOnlyApprovedMacAlgorithmsAreUsedObject = "auditEnsureOnlyApprovedMacAlgorithmsAreUsed";
static const char* g_auditEnsureSshWarningBannerIsEnabledObject = "auditEnsureSshWarningBannerIsEnabled";
static const char* g_auditEnsureUsersCannotSetSshEnvironmentOptionsObject = "auditEnsureUsersCannotSetSshEnvironmentOptions";
static const char* g_auditEnsureAppropriateCiphersForSshObject = "auditEnsureAppropriateCiphersForSsh";

static const char* g_remediateEnsurePermissionsOnEtcSshSshdConfigObject = "remediateEnsurePermissionsOnEtcSshSshdConfig";
static const char* g_remediateEnsureSshBestPracticeProtocolObject = "remediateEnsureSshBestPracticeProtocol";
static const char* g_remediateEnsureSshBestPracticeIgnoreRhostsObject = "remediateEnsureSshBestPracticeIgnoreRhosts";
static const char* g_remediateEnsureSshLogLevelIsSetObject = "remediateEnsureSshLogLevelIsSet";
static const char* g_remediateEnsureSshMaxAuthTriesIsSetObject = "remediateEnsureSshMaxAuthTriesIsSet";
static const char* g_remediateEnsureAllowUsersIsConfiguredObject = "remediateEnsureAllowUsersIsConfigured";
static const char* g_remediateEnsureDenyUsersIsConfiguredObject = "remediateEnsureDenyUsersIsConfigured";
static const char* g_remediateEnsureAllowGroupsIsConfiguredObject = "remediateEnsureAllowGroupsIsConfigured";
static const char* g_remediateEnsureDenyGroupsConfiguredObject = "remediateEnsureDenyGroupsConfigured";
static const char* g_remediateEnsureSshHostbasedAuthenticationIsDisabledObject = "remediateEnsureSshHostbasedAuthenticationIsDisabled";
static const char* g_remediateEnsureSshPermitRootLoginIsDisabledObject = "remediateEnsureSshPermitRootLoginIsDisabled";
static const char* g_remediateEnsureSshPermitEmptyPasswordsIsDisabledObject = "remediateEnsureSshPermitEmptyPasswordsIsDisabled";
static const char* g_remediateEnsureSshClientIntervalCountMaxIsConfiguredObject = "remediateEnsureSshClientIntervalCountMaxIsConfigured";
static const char* g_remediateEnsureSshClientAliveIntervalIsConfiguredObject = "remediateEnsureSshClientAliveIntervalIsConfigured";
static const char* g_remediateEnsureSshLoginGraceTimeIsSetObject = "remediateEnsureSshLoginGraceTimeIsSet";
static const char* g_remediateEnsureOnlyApprovedMacAlgorithmsAreUsedObject = "remediateEnsureOnlyApprovedMacAlgorithmsAreUsed";
static const char* g_remediateEnsureSshWarningBannerIsEnabledObject = "remediateEnsureSshWarningBannerIsEnabled";
static const char* g_remediateEnsureUsersCannotSetSshEnvironmentOptionsObject = "remediateEnsureUsersCannotSetSshEnvironmentOptions";
static const char* g_remediateEnsureAppropriateCiphersForSshObject = "remediateEnsureAppropriateCiphersForSsh";

static char* g_desiredPermissionsOnEtcSshSshdConfig = NULL;
static char* g_desiredSshBestPracticeProtocol = NULL;
static char* g_desiredSshBestPracticeIgnoreRhosts = NULL;
static char* g_desiredSshLogLevelIsSet = NULL;
static char* g_desiredSshMaxAuthTriesIsSet = NULL;
static char* g_desiredAllowUsersIsConfigured = NULL;
static char* g_desiredDenyUsersIsConfigured = NULL;
static char* g_desiredAllowGroupsIsConfigured = NULL;
static char* g_desiredDenyGroupsConfigured = NULL;
static char* g_desiredSshHostbasedAuthenticationIsDisabled = NULL;
static char* g_desiredSshPermitRootLoginIsDisabled = NULL;
static char* g_desiredSshPermitEmptyPasswordsIsDisabled = NULL;
static char* g_desiredSshClientIntervalCountMaxIsConfigured = NULL;
static char* g_desiredSshClientAliveIntervalIsConfigured = NULL;
static char* g_desiredSshLoginGraceTimeIsSet = NULL;
static char* g_desiredOnlyApprovedMacAlgorithmsAreUsed = NULL;
static char* g_desiredSshWarningBannerIsEnabled = NULL;
static char* g_desiredUsersCannotSetSshEnvironmentOptions = NULL;
static char* g_desiredAppropriateCiphersForSsh = NULL;

static char* GetSshServerState(const char* name, void* log)
{
    const char* sshdDashTCommand = "sshd -T";
    const char* commandTemplateForOne = "%s | grep %s";
    char* command = NULL;
    char* textResult = NULL;
    int status = 0;

    if (NULL == name)
    {
        if (0 != (status = ExecuteCommand(NULL, sshdDashTCommand, true, false, 0, 0, &textResult, NULL, NULL)))
        {
            OsConfigLogError(log, "GetSshServerState: '%s' failed with %d and '%s'", sshdDashTCommand, status, textResult);
            FREE_MEMORY(textResult);
        }
    }
    else
    {
        if (NULL != (command = FormatAllocateString(commandTemplateForOne, sshdDashTCommand, name)))
        {
            if (0 != (status = ExecuteCommand(NULL, command, true, false, 0, 0, &textResult, NULL, NULL)))
            {
                OsConfigLogError(log, "GetSshServerState: '%s' failed with %d and '%s'", command, status, textResult);
                FREE_MEMORY(textResult);
            }
            else if ((NULL != textResult) && (NULL != strstr(textResult, name)))
            {
                RemovePrefixUpToString(textResult, name);
                RemovePrefixUpTo(textResult, ' ');
                RemovePrefixBlanks(textResult);
                RemoveTrailingBlanks(textResult);
            }
        }
        else
        {
            OsConfigLogError(log, "GetSshServerState: FormatAllocateString failed");
        }

        FREE_MEMORY(command);
    }

    return textResult;
}

static int IsSshServerActive(void* log)
{
    int result = 0;
   
    if (false == FileExists(g_sshServerConfiguration))
    {
        OsConfigLogInfo(log, "IsSshServerActive: the OpenSSH Server configuration file '%s' is not present on this device", g_sshServerConfiguration);
        result = EEXIST;
    }
    else if (false == IsDaemonActive(g_sshServerService, log))
    {
        OsConfigLogInfo(log, "IsSshServerActive: the OpenSSH Server service '%s' is not active on this device", g_sshServerService);
        result = EEXIST;
    }

    return result;
}

static int CheckOnlyApprovedMacAlgorithmsAreUsed(const char* macs, char** reason, void* log)
{
    char* sshMacs = DuplicateStringToLowercase(g_sshMacs);
    char* macsValue = NULL;
    char* value = NULL;
    size_t macsValueLength = 0;
    size_t i = 0;
    int status = 0;

    if (NULL == macs)
    {
        OsConfigLogError(log, "CheckOnlyApprovedMacAlgorithmsAreUsed: invalid arguments");
        return EINVAL;
    }
    else if (0 != IsSshServerActive(log))
    {
        return status;
    }

    if (NULL == (macsValue = GetSshServerState(sshMacs, log)))
    {
        OsConfigLogError(log, "CheckOnlyApprovedMacAlgorithmsAreUsed: '%s' not found in SSH Server response from 'sshd -T'", sshMacs);
        OsConfigCaptureReason(reason, "'%s' not found in SSH Server response", "%s, also '%s' not found in SSH Server response", sshMacs);
        status = ENOENT;
    }
    else
    {
        macsValueLength = strlen(macsValue);

        for (i = 0; i < macsValueLength; i++)
        {
            if (NULL == (value = DuplicateString(&(macsValue[i]))))
            {
                OsConfigLogError(log, "CheckOnlyApprovedMacAlgorithmsAreUsed: failed to duplicate string");
                status = ENOMEM;
                break;
            }
            else
            {
                TruncateAtFirst(value, ',');

                if (NULL == strstr(macs, value))
                {
                    status = ENOENT;
                    OsConfigLogError(log, "CheckOnlyApprovedMacAlgorithmsAreUsed: unapproved MAC algorithm '%s' found in SSH Server response", value);
                    OsConfigCaptureReason(reason, "Unapproved MAC algorithm '%s' found in SSH Server response", "%s, also MAC algorithm '%s' is unapproved", value);
                }

                i += strlen(value);
                FREE_MEMORY(value);
                continue;
            }
        }
    }

    if ((0 == status) && reason)
    {
        FREE_MEMORY(*reason);
        *reason = FormatAllocateString("%sThe %s service reports that '%s' is set to '%s' (all approved MAC algorithms)", 
            SECURITY_AUDIT_PASS, g_sshServerService, sshMacs, macsValue);
    }

    FREE_MEMORY(macsValue);
    FREE_MEMORY(sshMacs);

    OsConfigLogInfo(log, "CheckOnlyApprovedMacAlgorithmsAreUsed: %s (%d)", PLAIN_STATUS_FROM_ERRNO(status), status);

    return status;
}

static int CheckAppropriateCiphersForSsh(const char* ciphers, char** reason, void* log)
{
    char* sshCiphers = DuplicateStringToLowercase(g_sshCiphers);
    char* ciphersValue = NULL;
    char* value = NULL;
    size_t ciphersValueLength = 0;
    size_t i = 0;
    int status = 0;

    if (NULL == ciphers)
    {
        OsConfigLogError(log, "CheckAppropriateCiphersForSsh: invalid argument");
        return EINVAL;
    }
    else if (0 != IsSshServerActive(log))
    {
        return status;
    }

    if (NULL == (ciphersValue = GetSshServerState(sshCiphers, log)))
    {
        OsConfigLogError(log, "CheckAppropriateCiphersForSsh: '%s' not found in SSH Server response", sshCiphers);
        OsConfigCaptureReason(reason, "'%s' not found in SSH Server response", "%s, also '%s' not found in SSH Server response", sshCiphers);
        status = ENOENT;
    }
    else
    {
        ciphersValueLength = strlen(ciphersValue);

        // Check that no unapproved ciphers are configured
        for (i = 0; i < ciphersValueLength; i++)
        {
            if (NULL == (value = DuplicateString(&(ciphersValue[i]))))
            {
                OsConfigLogError(log, "CheckAppropriateCiphersForSsh: failed to duplicate string");
                status = ENOMEM;
                break;
            }
            else
            {
                TruncateAtFirst(value, ',');

                if (NULL == strstr(ciphers, value))
                {
                    status = ENOENT;
                    OsConfigLogError(log, "CheckAppropriateCiphersForSsh: unapproved cipher '%s' found in SSH Server response", value);
                    OsConfigCaptureReason(reason, "Unapproved cipher '%s' found in SSH Server response", "%s, also cipher '%s' is unapproved", value);
                }

                i += strlen(value);
                FREE_MEMORY(value);
                continue;
            }
        }

        ciphersValueLength = strlen(ciphers);

        // Check that all required ciphers are configured
        for (i = 0; i < ciphersValueLength; i++)
        {
            if (NULL == (value = DuplicateString(&(ciphers[i]))))
            {
                OsConfigLogError(log, "CheckAppropriateCiphersForSsh: failed to duplicate ciphers string");
                status = ENOMEM;
                break;
            }
            else
            {
                TruncateAtFirst(value, ',');

                if (NULL == strstr(ciphersValue, value))
                {
                    status = ENOENT;
                    OsConfigLogError(log, "CheckAppropriateCiphersForSsh: required cipher '%s' not found in SSH Server response", &(ciphers[i]));
                    OsConfigCaptureReason(reason, "Required cipher '%s' not found in SSH Server response", "%s, also required cipher '%s' is not found", &(ciphers[i]));
                }

                i += strlen(value);
                FREE_MEMORY(value);
                continue;
            }
        }
    }

    if ((0 == status) && reason)
    {
        FREE_MEMORY(*reason);
        *reason = FormatAllocateString("%sThe %s service reports that '%s' is set to '%s' (only approved ciphers)",
            SECURITY_AUDIT_PASS, g_sshServerService, sshCiphers, ciphersValue);
    }

    FREE_MEMORY(ciphersValue);
    FREE_MEMORY(sshCiphers);

    OsConfigLogInfo(log, "CheckAppropriateCiphersForSsh: %s (%d)", PLAIN_STATUS_FROM_ERRNO(status), status);

    return status;
}

static int CheckSshOptionIsSet(const char* option, const char* expectedValue, char** actualValue, char** reason, void* log)
{
    char* value = NULL;
    int status = 0;

    if (NULL == option)
    {
        OsConfigLogError(log, "CheckSshOptionIsSet: invalid argument");
        return EINVAL;
    }

    if (0 != IsSshServerActive(log))
    {
        return status;
    }

    if (NULL != (value = GetSshServerState(option, log)))
    {
        OsConfigLogInfo(log, "CheckSshOptionIsSet: '%s' found in SSH Server response set to '%s'", option, value);

        if ((NULL != expectedValue) && (0 != strcmp(value, expectedValue)))
        {
            OsConfigLogError(log, "CheckSshOptionIsSet: '%s' is not set to '%s' in SSH Server response (but to '%s')", option, expectedValue, value);
            OsConfigCaptureReason(reason, "'%s' is not set to '%s' in SSH Server response (but to '%s')",
                "%s, also '%s' is not set to '%s' in SSH Server response (but to '%s')", option, expectedValue, value);
            status = ENOENT;
        }

        if (NULL != actualValue)
        {
            *actualValue = DuplicateString(value);
        }

        if ((0 == status) && reason)
        {
            FREE_MEMORY(*reason);
            *reason = FormatAllocateString("%sThe %s service reports that '%s' is set to '%s'", SECURITY_AUDIT_PASS, g_sshServerService, option, value);
        }

        FREE_MEMORY(value);
    }
    else
    {
        OsConfigLogError(log, "CheckSshOptionIsSet: '%s' not found in SSH Server response", option);
        OsConfigCaptureReason(reason, "'%s' not found in SSH Server response", "%s, also '%s' is not found in SSH server response", option);
        status = ENOENT;
    }

    OsConfigLogInfo(log, "CheckSshOptionIsSet: %s (%d)", PLAIN_STATUS_FROM_ERRNO(status), status);

    return status;
}

static int CheckSshOptionIsSetToInteger(const char* option, int* expectedValue, int* actualValue, char** reason, void* log)
{
    char* actualValueString = NULL;
    char* expectedValueString = expectedValue ? FormatAllocateString("%d", *expectedValue) : NULL;
    int status = CheckSshOptionIsSet(option, expectedValueString, &actualValueString, reason, log);

    if ((0 == status) && (NULL != actualValue))
    {
        *actualValue = (NULL != actualValueString) ? atoi(actualValueString) : -1;
    }

    FREE_MEMORY(actualValueString);
    FREE_MEMORY(expectedValueString);

    return status;
}

static int CheckSshClientAliveInterval(char** reason, void* log)
{
    char* clientAliveInterval = DuplicateStringToLowercase(g_sshClientAliveInterval);
    int actualValue = 0;
    int status = 0; 
    
    if ((0 == (status = CheckSshOptionIsSetToInteger(clientAliveInterval, NULL, &actualValue, reason, log))) && (actualValue <= 0))
    {
        OsConfigLogError(log, "CheckSshClientAliveInterval: 'clientaliveinterval' is not set to a greater than zero value in SSH Server response (but to %d)", actualValue);
        OsConfigCaptureReason(reason, "'clientaliveinterval' is not set to a greater than zero value in SSH Server response (but to %d)",
            "%s, also 'clientaliveinterval' is not set to a greater than zero value in SSH Server response (but to %d)", actualValue);
        status = ENOENT;
    }
    else if (reason)
    {
        FREE_MEMORY(*reason);
        *reason = FormatAllocateString("%sThe %s service reports that '%s' is set to '%d' (that is greater than zero)", 
            SECURITY_AUDIT_PASS, g_sshServerService, clientAliveInterval, actualValue);
    }

    FREE_MEMORY(clientAliveInterval);

    OsConfigLogInfo(log, "CheckSshClientAliveInterval: %s (%d)", PLAIN_STATUS_FROM_ERRNO(status), status);

    return status;
}

static int CheckSshLoginGraceTime(const char* value, char** reason, void* log)
{
    char* loginGraceTime = DuplicateStringToLowercase(g_sshLoginGraceTime);
    int targetValue = atoi(value ? value : g_sshDefaultSshLoginGraceTime);
    int actualValue = 0;
    int status = 0; 

    if ((0 == (status = CheckSshOptionIsSetToInteger(loginGraceTime, NULL, &actualValue, reason, log))) && (actualValue > 60))
    {
        OsConfigLogError(log, "CheckSshLoginGraceTime: 'logingracetime' is not set to %d or less in SSH Server response (but to %d)", targetValue, actualValue);
        OsConfigCaptureReason(reason, "'logingracetime' is not set to a value of %d or less in SSH Server response (but to %d)",
            "%s, also 'logingracetime' is not set to a value of 60 or less in SSH Server response (but to %d)", targetValue, actualValue);
        status = ENOENT;
    }
    else if (reason)
    {
        FREE_MEMORY(*reason);
        *reason = FormatAllocateString("%sThe %s service reports that '%s' is set to '%d' (that is %d or less)", 
            SECURITY_AUDIT_PASS, g_sshServerService, loginGraceTime, targetValue, actualValue);
    }

    FREE_MEMORY(loginGraceTime);

    OsConfigLogInfo(log, "CheckSshLoginGraceTime: %s (%d)", PLAIN_STATUS_FROM_ERRNO(status), status);

    return status;
}

static int CheckSshWarningBanner(const char* bannerFile, const char* bannerText, char** reason, void* log)
{
    char* banner = DuplicateStringToLowercase(g_sshBanner);
    char* actualValue = NULL;
    char* contents = NULL;
    int status = 0;

    if ((NULL == bannerFile) || (NULL == bannerText))
    {
        OsConfigLogError(log, "CheckSshWarningBanner: invalid arguments");
        status = EINVAL;
    } 
    else if (0 == (status = CheckSshOptionIsSet(banner, bannerFile, &actualValue, reason, log)))
    {
        if (NULL == (contents = LoadStringFromFile(bannerFile, false, log)))
        {
            OsConfigLogError(log, "CheckSshWarningBanner: cannot read from '%s'", bannerFile);
            OsConfigCaptureReason(reason, "'%s' is set to '%s' but the file cannot be read",
                "%s, also '%s' is set to '%s' but the file cannot be read", banner, actualValue);
            status = ENOENT;
        }
        else  if (0 != strcmp(contents, bannerText))
        {
            OsConfigLogError(log, "CheckSshWarningBanner: banner text is:\n%s instead of:\n%s", contents, bannerText);
            OsConfigCaptureReason(reason, "Banner text from file '%s'is different from not the expected text",
                "%s, also the banner text from '%s' is different from the expected text", bannerFile);
            status = ENOENT;
        }
        else if (NULL != reason)
        {
            FREE_MEMORY(*reason);
            *reason = FormatAllocateString("%sThe sshd service reports that '%s' is set to '%s' and this file contains the expected banner text",
                SECURITY_AUDIT_PASS, banner, actualValue);
        }
    }

    FREE_MEMORY(contents);
    FREE_MEMORY(actualValue);
    FREE_MEMORY(banner);

    return status;
}

int CheckSshProtocol(char** reason, void* log)
{
    const char* protocolTemplate = "%s %s";
    char* protocol = NULL;
    int status = 0;

    if (0 != IsSshServerActive(log))
    {
        return status;
    }

    if (NULL == (protocol = FormatAllocateString(protocolTemplate, g_sshProtocol, g_desiredSshBestPracticeProtocol ? g_desiredSshBestPracticeProtocol : g_sshDefaultSshProtocol)))
    {
        OsConfigLogError(log, "CheckSshProtocol: FormatAllocateString failed");
        status = ENOMEM;
    }
    else if (EEXIST == (status = CheckLineNotFoundOrCommentedOut(g_sshServerConfiguration, '#', protocol, log)))
    {
        OsConfigLogInfo(log, "CheckSshProtocol: '%s' is found uncommented in %s", protocol, g_sshServerConfiguration);
        status = 0;
    }
    else
    {
        OsConfigLogError(log, "CheckSshProtocol: '%s' is not found uncommented with '#' in %s", protocol, g_sshServerConfiguration);
        OsConfigCaptureReason(reason, "'%s' is not found uncommented with '#' in %s",  
            "%s, also '%s' is not found uncommented with '#' in %s", protocol, g_sshServerConfiguration);
        status = ENOENT;
    }

    if ((0 == status) && reason)
    {
        FREE_MEMORY(*reason);
        *reason = FormatAllocateString("%s'%s' is found uncommented in %s", SECURITY_AUDIT_PASS, protocol, g_sshServerConfiguration);
    }

    FREE_MEMORY(protocol);

    return status;
}

static int SetSshOption(const char* option, const char* value, void* log)
{
    // Replaces any instances of 'option foo' with 'option value' and adds 'option value' when 'option' is missing
    const char* commandTemplate = "sed '/^%s /{h;s/ .*/ %s/};${x;/^$/{s//%s %s/;H};x}' %s";

    char* command = NULL;
    char* commandResult = NULL;
    size_t commandLength = 0;
    int status = 0;

    if ((NULL == option) || (NULL == value))
    {
        OsConfigLogError(log, "SetSshOption: invalid arguments");
        return EINVAL;
    }
    else if (false == FileExists(g_sshServerConfiguration))
    {
        OsConfigLogError(log, "SetSshOption: the SSH Server configuration file '%s' is not present on this device, no place to set '%s' to '%s'", 
            g_sshServerConfiguration, option, value);
        return status;
    }

    commandLength = strlen(commandTemplate) + (2 * strlen(option)) + (2 * strlen(value)) + strlen(g_sshServerConfiguration) + 1;

    if (NULL != (command = malloc(commandLength)))
    {
        memset(command, 0, commandLength);
        snprintf(command, commandLength, commandTemplate, option, value, option, value, g_sshServerConfiguration);

        if ((0 == (status = ExecuteCommand(NULL, command, false, false, 0, 0, &commandResult, NULL, log))) && commandResult)
        {
            if (false == SavePayloadToFile(g_sshServerConfiguration, commandResult, strlen(commandResult), log))
            {
                OsConfigLogError(log, "SetSshOption: failed saving the updated configuration to '%s'", g_sshServerConfiguration);
                status = ENOENT;
            }
        }
        else
        {
            OsConfigLogInfo(log, "SetSshOption: failed setting '%s' to '%s' in '%s' (%d)", option, value, g_sshServerConfiguration, status);
        }
    }
    else
    {
        OsConfigLogError(log, "SetSshOption: out of memory");
        status = ENOMEM;
    }

    FREE_MEMORY(commandResult);
    FREE_MEMORY(command);

    OsConfigLogInfo(log, "SetSshOption('%s' to '%s'): %s (%d)", option, value, PLAIN_STATUS_FROM_ERRNO(status), status);

    return status;
}

static int SetSshWarningBanner(unsigned int desiredBannerFileAccess, const char* bannerText, void* log)
{
    const char* etcAzSec = "/etc/azsec/";
    int status = 0;
       
    if (NULL == bannerText)
    {
        OsConfigLogError(log, "SetSshWarningBanner: invalid argument");
        return EINVAL;
    }
    
    if (false == DirectoryExists(etcAzSec))
    {
        if (0 != mkdir(etcAzSec, desiredBannerFileAccess))
        {
            status = errno ? errno : ENOENT;
            OsConfigLogError(log, "SetSshWarningBanner: mkdir(%s, %d) failed with %d", etcAzSec, desiredBannerFileAccess, status);
        }
    }

    if (true == DirectoryExists(etcAzSec))
    {
        if (SavePayloadToFile(g_sshBannerFile, bannerText, strlen(bannerText), log))
        {
            status = SetSshOption(g_sshBanner, g_sshEscapedBannerFilePath, log);
        }
        else
        {
            status = errno ? errno : ENOENT;
            OsConfigLogError(log, "SetSshWarningBanner: failed to save banner text '%s' to file '%s' with %d", bannerText, etcAzSec, status);
        }
    }

    return status;
}

int InitializeSshAudit(void* log)
{
    int status = 0;

    if ((NULL == (g_desiredPermissionsOnEtcSshSshdConfig = DuplicateString(g_sshDefaultSshSshdConfigAccess))) ||
        (NULL == (g_desiredSshBestPracticeProtocol = DuplicateString(g_sshDefaultSshProtocol))) ||
        (NULL == (g_desiredSshBestPracticeIgnoreRhosts = DuplicateString(g_sshDefaultSshYes))) ||
        (NULL == (g_desiredSshLogLevelIsSet = DuplicateString(g_sshDefaultSshLogLevel))) ||
        (NULL == (g_desiredSshMaxAuthTriesIsSet = DuplicateString(g_sshDefaultSshMaxAuthTries))) ||
        (NULL == (g_desiredAllowUsersIsConfigured = DuplicateString(g_sshDefaultSshAllowUsers))) ||
        (NULL == (g_desiredDenyUsersIsConfigured = DuplicateString(g_sshDefaultSshDenyUsers))) ||
        (NULL == (g_desiredAllowGroupsIsConfigured = DuplicateString(g_sshDefaultSshAllowGroups))) ||
        (NULL == (g_desiredDenyGroupsConfigured = DuplicateString(g_sshDefaultSshDenyGroups))) ||
        (NULL == (g_desiredSshHostbasedAuthenticationIsDisabled = DuplicateString(g_sshDefaultSshNo))) ||
        (NULL == (g_desiredSshPermitRootLoginIsDisabled = DuplicateString(g_sshDefaultSshNo))) ||
        (NULL == (g_desiredSshPermitEmptyPasswordsIsDisabled = DuplicateString(g_sshDefaultSshNo))) ||
        (NULL == (g_desiredSshClientIntervalCountMaxIsConfigured = DuplicateString(g_sshDefaultSshClientIntervalCountMax))) ||
        (NULL == (g_desiredSshClientAliveIntervalIsConfigured = DuplicateString(g_sshDefaultSshClientAliveInterval))) ||
        (NULL == (g_desiredSshLoginGraceTimeIsSet = DuplicateString(g_sshDefaultSshLoginGraceTime))) ||
        (NULL == (g_desiredOnlyApprovedMacAlgorithmsAreUsed = DuplicateString(g_sshDefaultSshMacs))) ||
        (NULL == (g_desiredSshWarningBannerIsEnabled = DuplicateString(g_sshDefaultSshBannerText))) ||
        (NULL == (g_desiredUsersCannotSetSshEnvironmentOptions = DuplicateString(g_sshDefaultSshNo))) ||
        (NULL == (g_desiredAppropriateCiphersForSsh = DuplicateString(g_sshDefaultSshCiphers))))
    {
        OsConfigLogError(log, "InitializeSshAudit: failed to allocate memory");
        status = ENOMEM;
    }

    return status;
}

void SshAuditCleanup(void* log)
{
    // Signal to the SSH Server service to reload configuration
    RestartDaemon(g_sshServerService, log);
    
    FREE_MEMORY(g_desiredPermissionsOnEtcSshSshdConfig);
    FREE_MEMORY(g_desiredSshBestPracticeProtocol);
    FREE_MEMORY(g_desiredSshBestPracticeIgnoreRhosts);
    FREE_MEMORY(g_desiredSshLogLevelIsSet);
    FREE_MEMORY(g_desiredSshMaxAuthTriesIsSet);
    FREE_MEMORY(g_desiredAllowUsersIsConfigured);
    FREE_MEMORY(g_desiredDenyUsersIsConfigured);
    FREE_MEMORY(g_desiredAllowGroupsIsConfigured);
    FREE_MEMORY(g_desiredDenyGroupsConfigured);
    FREE_MEMORY(g_desiredSshHostbasedAuthenticationIsDisabled);
    FREE_MEMORY(g_desiredSshPermitRootLoginIsDisabled);
    FREE_MEMORY(g_desiredSshPermitEmptyPasswordsIsDisabled);
    FREE_MEMORY(g_desiredSshClientIntervalCountMaxIsConfigured);
    FREE_MEMORY(g_desiredSshClientAliveIntervalIsConfigured);
    FREE_MEMORY(g_desiredSshLoginGraceTimeIsSet);
    FREE_MEMORY(g_desiredOnlyApprovedMacAlgorithmsAreUsed);
    FREE_MEMORY(g_desiredSshWarningBannerIsEnabled);
    FREE_MEMORY(g_desiredUsersCannotSetSshEnvironmentOptions);
    FREE_MEMORY(g_desiredAppropriateCiphersForSsh);
}

int ProcessSshAuditCheck(const char* name, char* value, char** reason, void* log)
{
    char* lowercase = NULL;
    int status = 0;

    if (NULL == name)
    {
        OsConfigLogError(log, "ProcessSshAuditCheck: invalid check name argument");
        return EINVAL;
    }

    if (NULL != reason)
    {
        FREE_MEMORY(*reason);
    }

    if (0 == strcmp(name, g_auditEnsurePermissionsOnEtcSshSshdConfigObject))
    {
        status = CheckFileAccess(g_sshServerConfiguration, 0, 0, atoi(g_desiredPermissionsOnEtcSshSshdConfig ? 
            g_desiredPermissionsOnEtcSshSshdConfig : g_sshDefaultSshSshdConfigAccess), reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureSshBestPracticeProtocolObject))
    {
        status = CheckSshProtocol(reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureSshBestPracticeIgnoreRhostsObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshIgnoreHosts);
        status = CheckSshOptionIsSet(lowercase, g_desiredSshBestPracticeIgnoreRhosts ? g_desiredSshBestPracticeIgnoreRhosts : g_sshDefaultSshYes, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureSshLogLevelIsSetObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshLogLevel);
        status = CheckSshOptionIsSet(lowercase, g_desiredSshLogLevelIsSet ? g_desiredSshLogLevelIsSet : g_sshDefaultSshLogLevel, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureSshMaxAuthTriesIsSetObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshMaxAuthTries);
        status = CheckSshOptionIsSet(lowercase, g_desiredSshMaxAuthTriesIsSet ? g_desiredSshMaxAuthTriesIsSet : g_sshDefaultSshMaxAuthTries, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureAllowUsersIsConfiguredObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshAllowUsers);
        status = CheckSshOptionIsSet(lowercase, g_desiredAllowUsersIsConfigured ? g_desiredAllowUsersIsConfigured : g_sshDefaultSshAllowUsers, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureDenyUsersIsConfiguredObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshDenyUsers);
        status = CheckSshOptionIsSet(lowercase, g_desiredDenyUsersIsConfigured ? g_desiredDenyUsersIsConfigured : g_sshDefaultSshDenyUsers, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureAllowGroupsIsConfiguredObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshAllowGroups);
        status = CheckSshOptionIsSet(lowercase, g_desiredAllowGroupsIsConfigured ? g_desiredAllowGroupsIsConfigured : g_sshDefaultSshAllowGroups, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureDenyGroupsConfiguredObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshDenyGroups);
        status = CheckSshOptionIsSet(lowercase, g_desiredDenyGroupsConfigured ? g_desiredDenyGroupsConfigured : g_sshDefaultSshDenyGroups, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureSshHostbasedAuthenticationIsDisabledObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshHostBasedAuthentication);
        status = CheckSshOptionIsSet(lowercase, g_desiredSshHostbasedAuthenticationIsDisabled ? g_desiredSshHostbasedAuthenticationIsDisabled : g_sshDefaultSshNo, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureSshPermitRootLoginIsDisabledObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshPermitRootLogin);
        status = CheckSshOptionIsSet(lowercase, g_desiredSshPermitRootLoginIsDisabled ? g_desiredSshPermitRootLoginIsDisabled : g_sshDefaultSshNo, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureSshPermitEmptyPasswordsIsDisabledObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshPermitEmptyPasswords);
        status = CheckSshOptionIsSet(lowercase, g_desiredSshPermitEmptyPasswordsIsDisabled ? g_desiredSshPermitEmptyPasswordsIsDisabled : g_sshDefaultSshNo, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureSshClientIntervalCountMaxIsConfiguredObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshClientAliveCountMax);
        status = CheckSshOptionIsSet(lowercase, g_desiredSshClientIntervalCountMaxIsConfigured ? g_desiredSshClientIntervalCountMaxIsConfigured : g_sshDefaultSshClientIntervalCountMax, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureSshClientAliveIntervalIsConfiguredObject))
    {
        status = CheckSshClientAliveInterval(reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureSshLoginGraceTimeIsSetObject))
    {
        status = CheckSshLoginGraceTime(g_desiredSshLoginGraceTimeIsSet ? g_desiredSshLoginGraceTimeIsSet : g_sshDefaultSshLoginGraceTime, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureOnlyApprovedMacAlgorithmsAreUsedObject))
    {
        status = CheckOnlyApprovedMacAlgorithmsAreUsed(g_desiredOnlyApprovedMacAlgorithmsAreUsed ? g_desiredOnlyApprovedMacAlgorithmsAreUsed : g_sshDefaultSshMacs, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureSshWarningBannerIsEnabledObject))
    {
        status = CheckSshWarningBanner(g_sshBannerFile, g_desiredSshWarningBannerIsEnabled ? g_desiredSshWarningBannerIsEnabled : g_sshDefaultSshBannerText, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureUsersCannotSetSshEnvironmentOptionsObject))
    {
        lowercase = DuplicateStringToLowercase(g_sshPermitUserEnvironment);
        status = CheckSshOptionIsSet(lowercase, g_desiredUsersCannotSetSshEnvironmentOptions ? g_desiredUsersCannotSetSshEnvironmentOptions : g_sshDefaultSshNo, NULL, reason, log);
    }
    else if (0 == strcmp(name, g_auditEnsureAppropriateCiphersForSshObject))
    {
        status = CheckAppropriateCiphersForSsh(g_desiredAppropriateCiphersForSsh ? g_desiredAppropriateCiphersForSsh : g_sshDefaultSshCiphers, reason, log);
    }
    else if (0 == strcmp(name, g_remediateEnsurePermissionsOnEtcSshSshdConfigObject))
    {
        FREE_MEMORY(g_desiredPermissionsOnEtcSshSshdConfig);
        status = (NULL != (g_desiredPermissionsOnEtcSshSshdConfig = DuplicateString(value ? value : g_sshDefaultSshSshdConfigAccess))) ?
            SetFileAccess(g_sshServerConfiguration, 0, 0, atoi(g_desiredPermissionsOnEtcSshSshdConfig), log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureSshBestPracticeProtocolObject))
    {
        FREE_MEMORY(g_desiredSshBestPracticeProtocol);
        status = (NULL != (g_desiredSshBestPracticeProtocol = DuplicateString(value ? value : g_sshDefaultSshProtocol))) ?
            SetSshOption(g_sshProtocol, g_desiredSshBestPracticeProtocol, log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureSshBestPracticeIgnoreRhostsObject))
    {
        FREE_MEMORY(g_desiredSshBestPracticeIgnoreRhosts);
        status = (NULL != (g_desiredSshBestPracticeIgnoreRhosts = DuplicateString(value ? value : g_sshDefaultSshYes))) ?
            SetSshOption(g_sshIgnoreHosts, value ? value : g_sshDefaultSshYes, log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureSshLogLevelIsSetObject))
    {
        FREE_MEMORY(g_desiredSshLogLevelIsSet);
        status = (NULL != (g_desiredSshLogLevelIsSet = DuplicateString(value ? value : g_sshDefaultSshLogLevel))) ?
            SetSshOption(g_sshLogLevel, g_desiredSshLogLevelIsSet, log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureSshMaxAuthTriesIsSetObject))
    {
        FREE_MEMORY(g_desiredSshMaxAuthTriesIsSet);
        status = (NULL != (g_desiredSshMaxAuthTriesIsSet = DuplicateString(value ? value : g_sshDefaultSshMaxAuthTries))) ?
            SetSshOption(g_sshMaxAuthTries, g_desiredSshMaxAuthTriesIsSet, log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureAllowUsersIsConfiguredObject))
    {
        FREE_MEMORY(g_desiredAllowUsersIsConfigured);
        status = (NULL != (g_desiredAllowUsersIsConfigured = DuplicateString(value ? value : g_sshDefaultSshAllowUsers))) ?
            SetSshOption(g_sshAllowUsers, g_desiredAllowUsersIsConfigured, log) : ENOMEM;

    }
    else if (0 == strcmp(name, g_remediateEnsureDenyUsersIsConfiguredObject))
    {
        FREE_MEMORY(g_desiredDenyUsersIsConfigured);
        status = (NULL != (g_desiredDenyUsersIsConfigured = DuplicateString(value ? value : g_sshDefaultSshDenyUsers))) ?
            SetSshOption(g_sshDenyUsers, g_desiredDenyUsersIsConfigured, log) : ENOMEM;

    }
    else if (0 == strcmp(name, g_remediateEnsureAllowGroupsIsConfiguredObject))
    {
        FREE_MEMORY(g_desiredAllowGroupsIsConfigured);
        status = (NULL != (g_desiredAllowGroupsIsConfigured = DuplicateString(value ? value : g_sshDefaultSshAllowGroups))) ?
            SetSshOption(g_sshAllowGroups, g_desiredAllowGroupsIsConfigured, log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureDenyGroupsConfiguredObject))
    {
        FREE_MEMORY(g_desiredDenyGroupsConfigured);
        status = (NULL != (g_desiredDenyGroupsConfigured = DuplicateString(value ? value : g_sshDefaultSshDenyGroups))) ?
            SetSshOption(g_sshDenyGroups, g_desiredDenyGroupsConfigured, log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureSshHostbasedAuthenticationIsDisabledObject))
    {
        FREE_MEMORY(g_desiredSshHostbasedAuthenticationIsDisabled);
        status = (NULL != (g_desiredSshHostbasedAuthenticationIsDisabled = DuplicateString(value ? value : g_sshDefaultSshNo))) ?
            SetSshOption(g_sshHostBasedAuthentication, g_desiredSshHostbasedAuthenticationIsDisabled, log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureSshPermitRootLoginIsDisabledObject))
    {
        FREE_MEMORY(g_desiredSshPermitRootLoginIsDisabled);
        status = (NULL != (g_desiredSshPermitRootLoginIsDisabled = DuplicateString(value ? value : g_sshDefaultSshNo))) ?
            SetSshOption(g_sshPermitRootLogin, g_desiredSshPermitRootLoginIsDisabled, log) : ENOMEM;

    }
    else if (0 == strcmp(name, g_remediateEnsureSshPermitEmptyPasswordsIsDisabledObject))
    {
        FREE_MEMORY(g_desiredSshPermitEmptyPasswordsIsDisabled);
        status = (NULL != (g_desiredSshPermitEmptyPasswordsIsDisabled = DuplicateString(value ? value : g_sshDefaultSshNo))) ?
            SetSshOption(g_sshPermitEmptyPasswords, g_desiredSshPermitEmptyPasswordsIsDisabled, log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureSshClientIntervalCountMaxIsConfiguredObject))
    {
        FREE_MEMORY(g_desiredSshClientIntervalCountMaxIsConfigured);
        status = (NULL != (g_desiredSshClientIntervalCountMaxIsConfigured = DuplicateString(value ? value : g_sshDefaultSshClientIntervalCountMax))) ?
            SetSshOption(g_sshClientAliveCountMax, g_desiredSshClientIntervalCountMaxIsConfigured, log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureSshClientAliveIntervalIsConfiguredObject))
    {
        FREE_MEMORY(g_desiredSshLoginGraceTimeIsSet);
        status = (NULL != (g_desiredSshLoginGraceTimeIsSet = DuplicateString(value ? value : g_sshDefaultSshLoginGraceTime))) ?
            SetSshOption(g_sshLoginGraceTime, g_desiredSshLoginGraceTimeIsSet, log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureSshLoginGraceTimeIsSetObject))
    {
        FREE_MEMORY(g_desiredSshClientAliveIntervalIsConfigured);
        status = (NULL != (g_desiredSshClientAliveIntervalIsConfigured = DuplicateString(value ? value : g_sshDefaultSshClientAliveInterval))) ?
            SetSshOption(g_sshClientAliveInterval, g_desiredSshClientAliveIntervalIsConfigured, log) : ENOMEM;

    }
    else if (0 == strcmp(name, g_remediateEnsureOnlyApprovedMacAlgorithmsAreUsedObject))
    {
        FREE_MEMORY(g_desiredOnlyApprovedMacAlgorithmsAreUsed);
        status = (NULL != (g_desiredOnlyApprovedMacAlgorithmsAreUsed = DuplicateString(value ? value : g_sshDefaultSshMacs))) ?
            SetSshOption(g_sshMacs, g_desiredOnlyApprovedMacAlgorithmsAreUsed, log) : ENOMEM;

    }
    else if (0 == strcmp(name, g_remediateEnsureSshWarningBannerIsEnabledObject))
    {
        FREE_MEMORY(g_desiredSshWarningBannerIsEnabled);
        status = (NULL != (g_desiredSshWarningBannerIsEnabled = DuplicateString(value ? value : g_sshDefaultSshBannerText))) ?
            SetSshWarningBanner(atoi(g_desiredPermissionsOnEtcSshSshdConfig), g_desiredSshWarningBannerIsEnabled, log) : ENOMEM;

    }
    else if (0 == strcmp(name, g_remediateEnsureUsersCannotSetSshEnvironmentOptionsObject))
    {
        FREE_MEMORY(g_desiredUsersCannotSetSshEnvironmentOptions);
        status = (NULL != (g_desiredUsersCannotSetSshEnvironmentOptions = DuplicateString(value ? value : g_sshDefaultSshNo))) ?
            SetSshOption(g_sshPermitUserEnvironment, g_desiredUsersCannotSetSshEnvironmentOptions, log) : ENOMEM;
    }
    else if (0 == strcmp(name, g_remediateEnsureAppropriateCiphersForSshObject))
    {
        FREE_MEMORY(g_desiredAppropriateCiphersForSsh);
        status = (NULL != (g_desiredAppropriateCiphersForSsh = DuplicateString(value ? value : g_sshDefaultSshCiphers))) ?
            SetSshOption(g_sshCiphers, g_desiredAppropriateCiphersForSsh, log) : ENOMEM;
    }
    else
    {
        OsConfigLogError(log, "ProcessSshAuditCheck: unsupported check name '%s'", name);
        status = EINVAL;
    }

    FREE_MEMORY(lowercase);

    OsConfigLogInfo(log, "ProcessSshAuditCheck(%s, '%s'): '%s' and %d", name, value ? value : "", reason ? *reason : "", status);

    return status;
}