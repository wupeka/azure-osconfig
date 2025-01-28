#!/usr/bin/env python
from __future__ import print_function
import sys
import os
import re

procedure_map = {}

for filename in os.listdir(sys.argv[1]):
    filepath = os.path.join(sys.argv[1], filename)
    if os.path.isfile(filepath):
        with open(filepath, 'r') as file:
            for line in file:
                audit_match = re.match(r'AUDIT_FN\((.*)\)', line)
                if audit_match:
                    procedure_name = audit_match.group(1)
                    if procedure_name not in procedure_map:
                        procedure_map[procedure_name] = [None, None]
                    procedure_map[procedure_name][0] = "___Audit_{}".format(procedure_name)
                
                remediate_match = re.match(r'REMEDIATE_FN\((.*)\)', line)
                if remediate_match:
                    procedure_name = remediate_match.group(1)
                    if procedure_name not in procedure_map:
                        procedure_map[procedure_name] = [None, None]
                    procedure_map[procedure_name][1] = "___Remediate_{}".format(procedure_name)

with open('ProcedureMap.cpp', 'w') as cpp_file:
    cpp_file.write("""#include <map>
#include <string>
typedef enum
{
  FALSE,
  TRUE,
  FAILURE
} tristate_t;

typedef tristate_t (*action_func_t)(const char *name, std::map<std::string, std::string> args, std::string &vlog, void *log);
                  
""")
    
    for procedure_name, functions in procedure_map.items():
        if functions[0]:
            cpp_file.write('tristate_t {}(const char *name, std::map<std::string, std::string> args, std::string &vlog, void *log);\n'.format(functions[0]))
        if functions[1]:
            cpp_file.write('tristate_t {}(const char *name, std::map<std::string, std::string> args, std::string &vlog, void *log);\n'.format(functions[1]))
    cpp_file.write('std::map<std::string, std::pair<action_func_t, action_func_t> > complianceProcedureMap = {\n')
    
    for procedure_name, functions in procedure_map.items():
        audit_fn = functions[0] if functions[0] else 'nullptr'
        remediation_fn = functions[1] if functions[1] else 'nullptr'
        cpp_file.write('    {{"{}", {{{}, {}}}}},\n'.format(procedure_name, audit_fn, remediation_fn))
    
    cpp_file.write('};\n')