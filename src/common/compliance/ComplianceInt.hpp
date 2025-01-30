#ifndef _COMPLIANCE_INT_H
#define _COMPLIANCE_INT_H

#include <string>
#include <map>
#include <sstream>

#include <parson.h>

typedef enum
{
  FALSE,
  TRUE,
  FAILURE
} tristate_t;

typedef tristate_t (*action_func_t)(const char *name, std::map<std::string, std::string> args, std::ostringstream &logstream, void *log);

#define AUDIT_FN(fn_name) \
  tristate_t ___Audit_##fn_name(const char *name, std::map<std::string, std::string> args, std::ostringstream &logstream, void *log)

#define REMEDIATE_FN(fn_name) \
  tristate_t ___Remediate_##fn_name(const char *name, std::map<std::string, std::string> args, std::ostringstream &logstream, void *log)

#endif // _COMPLIANCE_INT_H