#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include "../ComplianceInt.hpp"

AUDIT_FN(returnFailure) {
    (void)args;
    (void)vlog;
    (void)name;
    (void)log;
    return FAILURE;
}

AUDIT_FN(ensureFilePermissions) {
        (void)vlog;
    (void)name;
    (void)log;

  struct stat statbuf;
  if (args.find("filename") == args.end()) {
    vlog += "No filename provided";
    return FAILURE;
  }
  if (stat(args["filename"].c_str(), &statbuf) < 0) {
    vlog += "Stat error";
    return FAILURE;
  }
  if (args.find("user") != args.end()) {
    struct passwd *pwd = getpwuid(statbuf.st_uid);
    if (pwd == NULL) {
      vlog += "No user with uid";
      return FALSE;
    }
    if (strcmp(pwd->pw_name, args["user"].c_str())) {
      vlog += "Invalid user";
      return FALSE;
    }
  }
  if (args.find("group") != args.end()) {
    struct group *grp = getgrgid(statbuf.st_gid);
    if (grp == NULL) {
      vlog += "No group with gid";
      return FALSE;
    }
    if (strcmp(grp->gr_name, args["group"].c_str())) {
      vlog += "Invalid group";
      return FALSE;
    }
  }
  if (args.find("permissions") != args.end()) {
    unsigned short perms = strtol(args["permissions"].c_str(), NULL, 8);
    unsigned short mask = 0xFFF;
    if (args.find("permissions_mask") != args.end())  {
      mask = strtol(args["permissions_mask"].c_str(), NULL, 8);
    }
    if ((perms & mask) != (statbuf.st_mode & mask)) {
        vlog += "Invalid perms ";
        return FALSE;
    }
  }
  return TRUE;
}

AUDIT_FN(packageInstalled) {
    (void)vlog;
    (void)name;
    (void)log;
    if (args.find("packageName") == args.end())
    {
        return FAILURE;
    }
  char buf[256];
  snprintf(buf, 256, "dpkg -L %s > /dev/null 2>&1", args["packageName"].c_str());
  int rv = system(buf);
  return (rv == 0) ? TRUE : FALSE;
}
