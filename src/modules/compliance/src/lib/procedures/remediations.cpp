#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include "../Evaluator.hpp"

namespace compliance {

REMEDIATE_FN(returnFailure) {
    (void)args;
    (void)logstream;
    return false;
}

REMEDIATE_FN(ensureFilePermissions) {
    struct stat statbuf;
    if (args.find("filename") == args.end()) {
        logstream << "ERROR: No filename provided";
        return Error("No filename provided");
    }
    if (stat(args["filename"].c_str(), &statbuf) < 0) {
        logstream << "ERROR: Stat error";
        return Error("No filename provided");
    }
    uid_t uid = statbuf.st_uid;
    gid_t gid = statbuf.st_gid;
    bool owner_changed = false;
    if (args.find("user") != args.end()) {
        struct passwd *pwd = getpwnam(args["user"].c_str());
        if (pwd == NULL) {
            logstream << "ERROR: No user with name " << args["user"];
            return false;
        }
        uid = pwd->pw_uid;
        owner_changed = true;
    }
    if (args.find("group") != args.end()) {
        struct group *grp = getgrnam(args["group"].c_str());
        if (grp == NULL) {
            logstream << "ERROR: No group with name " << args["group"];
            return false;
        }
        gid = grp->gr_gid;
        owner_changed = true;
    }
    if (owner_changed) {
        if (chown(args["filename"].c_str(), uid, gid) < 0) {
            logstream << "ERROR: Chown error";
            return Error("Chown error");
        }
    }
    if (args.find("permissions") != args.end()) {
        unsigned short perms = strtol(args["permissions"].c_str(), NULL, 8);
        unsigned short mask = 0xFFF;
        if (args.find("permissions_mask") != args.end()) {
            mask = strtol(args["permissions_mask"].c_str(), NULL, 8);
        }
        unsigned short new_perms = (statbuf.st_mode & ~mask) | (perms & mask);
        if (new_perms != statbuf.st_mode) {
            if (chmod(args["filename"].c_str(), new_perms) < 0) {
                logstream << "ERROR: Chmod error";
                return Error("Chmod error");
            }
        }
    }
    return true;
}
}
