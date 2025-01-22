#include <string>
#include <memory>
#include <map>

#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdarg.h>
#include <version.h>
#include <ctype.h>
#include <parson.h>
#include <CommonUtils.h>
#include <UserUtils.h>
#include <SshUtils.h>
#include <Logging.h>

#include "Compliance.h"
#include "ComplianceInt.hpp"
#include "base64.h"

static std::map<std::string, std::pair<action_func_t, action_func_t> > func_map;

void RegisterAuditFn(const char *name, action_func_t fn) {
    func_map[name].first = fn;
}

void RegisterRemediationFn(const char *name, action_func_t fn) {
    func_map[name].second = fn;
}

int ComplianceIsValidResourceIdRuleId(const char *resourceId, const char *ruleId, const char *payloadKey, void *log)
{
    (void) resourceId;
    (void) ruleId;
    (void) payloadKey;
    (void) log;
    return 0;
};

static int DecodeB64JSON(const char *input, JSON_Value **output)
{
    unsigned int baseLen = 0;
    JSON_Value *inputJSON = NULL;

    Base64Decode(input, NULL, &baseLen);
    if (0 == baseLen) {
        return EINVAL;
    }

    std::shared_ptr<char> inputJSONString(new char[baseLen], std::default_delete<char[]>());

    if (Base64Decode(input, (unsigned char *)inputJSONString.get(), &baseLen) != 0)
    {
        return EINVAL;
    }

    inputJSON = json_parse_string(inputJSONString.get());
    if (NULL == inputJSON) {
        return EINVAL;
    }

    *output = inputJSON;
    return 0;
}

tristate_t EvaluateProcedure(JSON_Object *json, bool remediate, std::string &vlog, void *log)
{
    // checks!
    const char *name = json_object_get_name(json, 0);
    JSON_Value *value = json_object_get_value_at(json, 0);
    if (!strcmp(name, "anyOf")) {
        if (json_value_get_type(value) != JSONArray) {
            return FAILURE;
        }
        JSON_Array *array = json_value_get_array(value);
        size_t count = json_array_get_count(array);
        for (size_t i = 0; i < count; ++i) {
            JSON_Object *subObject = json_array_get_object(array, i);
            tristate_t result = EvaluateProcedure(subObject, remediate, vlog, log);
            if (result == TRUE || result == FAILURE) {
                return result;
            }
        }
        return FALSE;
    } else if (!strcmp(name, "allOf")) {
        if (json_value_get_type(value) != JSONArray) {
            return FAILURE;
        }
        JSON_Array *array = json_value_get_array(value);
        size_t count = json_array_get_count(array);
        for (size_t i = 0; i < count; ++i) {
            JSON_Object *subObject = json_array_get_object(array, i);
            tristate_t result = EvaluateProcedure(subObject, remediate, vlog, log);
            if (result != TRUE) {
                return result;
            }
        }
        return TRUE;
    } else if (!strcmp(name, "not")) {
        if (json_value_get_type(value) != JSONObject) {
            return FAILURE;
        }
        // NOT can be only used as an audit!
        tristate_t rv = EvaluateProcedure(json_value_get_object(value), false, vlog, log);
        if (rv == TRUE) {
            return FALSE;
        }
        else if (rv == FALSE)
        {
            return TRUE;
        }
        else
        {
            return FAILURE;
        }
    } else {
        if (json_value_get_type(value) != JSONObject) {
            return FAILURE;
        }
        std::map<std::string, std::string> arguments;
        JSON_Object *args_object = json_value_get_object(value);
        size_t count = json_object_get_count(args_object);
        for (size_t i = 0; i < count; ++i) {
            const char *key = json_object_get_name(args_object, i);
            JSON_Value *val = json_object_get_value_at(args_object, i);
            if (json_value_get_type(val) != JSONString) {
                return FAILURE;
            }
            arguments[key] = json_value_get_string(val);
        }

        auto f = func_map.find(name);
        if (f == func_map.end()) {
            vlog += "Unknown function " + std::string(name);
            return FAILURE;
        }
        action_func_t fn;
        if (remediate)
        {
            fn = f->second.second;
            if (fn == NULL) {
                fn = f->second.first;
            }
            if (fn == NULL) {
                return FAILURE;
            }
        }
        else
        {
            fn = f->second.first;
        }
        if (fn == NULL) {
            return FAILURE;
        }
        tristate_t result = fn(name, arguments, vlog, log);
        return result;
    }
}

void ComplianceInitialize(void *log) {
    (void)log;

};
void ComplianceShutdown(void *log) {
    (void)log;
};

int ComplianceMmiGet(const char *componentName, const char *objectName, char **payload, int *payloadSizeBytes, unsigned int maxPayloadSizeBytes, void *log) {
    int status = 0;
    
    OsConfigLogInfo(log, "ComplianceMmiGet(%s, %s, %s, %p) called with arguments", componentName, objectName, *payload, payloadSizeBytes);

    if ((NULL == componentName) || (NULL == objectName) || (NULL == payload) || (NULL == payloadSizeBytes))
    {
        OsConfigLogError(log, "ComplianceMmiGet(%s, %s, %p, %p) called with invalid arguments", componentName, objectName, payload, payloadSizeBytes);
        return EINVAL;
    }

    JSON_Value *inputJSON = NULL;
    status = DecodeB64JSON(objectName, &inputJSON);
    if (0 != status) {
        OsConfigLogError(log, "ComplianceMmiGet failed to decode input JSON %s", objectName);
        return status;
    }
    std::shared_ptr<JSON_Value> inputJSONPtr(inputJSON, json_value_free);
    if (json_value_get_type(inputJSON) != JSONObject) {
        OsConfigLogError(log, "ComplianceMmiGet input JSON is not an object");
        return EINVAL;
    }
    JSON_Object *root = json_value_get_object(inputJSON);

    std::string vlog;
    tristate_t result = EvaluateProcedure(root, false, vlog, log);
    if (result == FAILURE) {
        OsConfigLogError(log, "ComplianceMmiGet failed to evaluate procedure");
        return EINVAL;
    }
    vlog = vlog.substr(0, maxPayloadSizeBytes - (1 + 4 + 2)); // 4 for "PASS" or "FAIL", 2 for quotes
    if (result == TRUE) {
        vlog = "\"PASS" + vlog + "\"";
    } else {
        vlog = "\"FAIL" + vlog + "\"";
    }
    *payloadSizeBytes = vlog.size();
    *payload = (char *)malloc(*payloadSizeBytes + 1);
    (*payload)[*payloadSizeBytes] = '\0';
    memcpy(*payload, vlog.c_str(), *payloadSizeBytes);
    return 0;
};

int ComplianceMmiSet(const char *componentName, const char *objectName, const char *payload, const int payloadSizeBytes, void *log) {
    int status = 0; 
    OsConfigLogInfo(log, "ComplianceMmiSet(%s, %s, %s, %d) called with arguments", componentName, objectName, payload, payloadSizeBytes);
    if ((NULL == componentName) || (NULL == objectName))
    {
        OsConfigLogError(log, "ComplianceMmiSet(%s, %s, %s, %d) called with invalid arguments", componentName, objectName, payload, payloadSizeBytes);
        return EINVAL;
    }

    (void)payload;
    (void)payloadSizeBytes;

    return status;

};
