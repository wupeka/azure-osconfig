#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include "../ComplianceInt.hpp"

AUDIT_FN(returnFail) {
    (void)name;
    (void)log;
    if (args.find("message") != args.end()) {
        logstream << args["message"];
    }
    return FALSE;
}

AUDIT_FN(ensureFilePermissions) {
    (void)name;
    (void)log;

  struct stat statbuf;
  if (args.find("filename") == args.end()) {
    logstream << "No filename provided";
    return FAILURE;
  }
  logstream << "ensureFilePermissions for " << args["filename"];
  if (stat(args["filename"].c_str(), &statbuf) < 0) {
    logstream << "Stat error";
    return FAILURE;
  }
  if (args.find("user") != args.end()) {
    struct passwd *pwd = getpwuid(statbuf.st_uid);
    if (pwd == NULL) {
      logstream << "No user with uid " << statbuf.st_uid;
      return FALSE;
    }
    if (strcmp(pwd->pw_name, args["user"].c_str())) {
      logstream << "Invalid user - is " << pwd->pw_name << " should be " << args["user"];
      return FALSE;
    }
  }
  if (args.find("group") != args.end()) {
    struct group *grp = getgrgid(statbuf.st_gid);
    if (grp == NULL) {
      logstream << "No group with gid " << statbuf.st_gid;
      return FALSE;
    }
    if (strcmp(grp->gr_name, args["group"].c_str())) {
      logstream << "Invalid group - is " << statbuf.st_gid << " should be " << args["group"];
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
        logstream << "Invalid permissions - are " << std::oct << statbuf.st_mode << " should be " << std::oct << perms << " with mask " << std::oct << mask << std::dec;
        return FALSE;
    }
  }
  return TRUE;
}

AUDIT_FN(packageInstalled) {
    (void)name;
    (void)log;
    if (args.find("packageName") == args.end())
    {
        logstream << "No package name provided";
        return FAILURE;
    }
    logstream << "packageInstalled for " << args["packageName"];
    char buf[256];
    snprintf(buf, 256, "dpkg -L %s > /dev/null 2>&1", args["packageName"].c_str());
    int rv = system(buf);
    return (rv == 0) ? TRUE : FALSE;
}
