#ifndef _COMPLIANCE_INT_H
#define _COMPLIANCE_INT_H

#include <string>
#include <map>

#include <parson.h>

typedef enum
{
  FALSE,
  TRUE,
  FAILURE
} tristate_t;

typedef tristate_t (*action_func_t)(const char *name, std::map<std::string, std::string> args, std::string &vlog, void *log);
void RegisterAuditFn(const char *name, action_func_t fn);
void RegisterRemediationFn(const char *name, action_func_t fn);

#define AUDIT_FN(fn_name)                                                                                                            \
  tristate_t ___Audit_##fn_name(const char *name, std::map<std::string, std::string> args, std::string &vlog, void *log); \
                                                                                                                                     \
  __attribute__((                                                                                                                    \
      constructor,used)) void ___RegisterAudit_##fn_name()                                                                    \
  {                                                                                                                                  \
    RegisterAuditFn(#fn_name, ___Audit_##fn_name);                                                                                   \
  };                                                                                                                                 \
  tristate_t ___Audit_##fn_name(const char *name, std::map<std::string, std::string> args, std::string &vlog, void *log)

#define REMEDIATE_FN(fn_name)                                                                                                            \
  static tristate_t ___Remediate_##fn_name(const char *name, std::map<std::string, std::string> args, std::string &vlog, void *log); \
                                                                                                                                         \
  __attribute__((                                                                                                                        \
      constructor,used)) static void ___RegisterRemediate_##fn_name()                                                                    \
  {                                                                                                                                      \
    RegisterRemediateFn(#fn_name, ___Remediate_##fn_name);                                                                               \
  };                                                                                                                                     \
  static tristate_t ___Remediate_##fn_name(const char *name, std::map<std::string, std::string> args, std::string &vlog, void *log)

#endif // _COMPLIANCE_INT_H