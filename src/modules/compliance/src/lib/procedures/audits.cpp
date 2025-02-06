#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include "Evaluator.hpp"
namespace compliance
{

AUDIT_FN(returnFail)
{
  if (args.find("message") != args.end())
  {
    logstream << args["message"];
  }
  return false;
}

AUDIT_FN(ensureFilePermissions) {
  struct stat statbuf;
  if (args.find("filename") == args.end()) {
    return Error("No filename provided");
  }
  logstream << "ensureFilePermissions for " << args["filename"];
  if (stat(args["filename"].c_str(), &statbuf) < 0) {
    return Error("Stat error");
  }
  if (args.find("user") != args.end()) {
    struct passwd *pwd = getpwuid(statbuf.st_uid);
    if (pwd == NULL) {
      logstream << "No user with uid " << statbuf.st_uid;
      return false;
    }
    if (strcmp(pwd->pw_name, args["user"].c_str())) {
      logstream << "Invalid user - is " << pwd->pw_name << " should be " << args["user"];
      return false;
    }
  }
  if (args.find("group") != args.end()) {
    struct group *grp = getgrgid(statbuf.st_gid);
    if (grp == NULL) {
      logstream << "No group with gid " << statbuf.st_gid;
      return false;
    }
    if (strcmp(grp->gr_name, args["group"].c_str())) {
      logstream << "Invalid group - is " << statbuf.st_gid << " should be " << args["group"];
      return false;
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
        return false;
    }
  }
  return true;
}

AUDIT_FN(packageInstalled) {
    if (args.find("packageName") == args.end())
    {
        logstream << "No package name provided";
        return Error("No package name provided");
    }
    logstream << "packageInstalled for " << args["packageName"];
    char buf[256];
    snprintf(buf, 256, "dpkg -L %s > /dev/null 2>&1", args["packageName"].c_str());
    int rv = system(buf);
    return rv == 0;
}
}
