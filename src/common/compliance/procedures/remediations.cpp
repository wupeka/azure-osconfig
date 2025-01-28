#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include "../ComplianceInt.hpp"

REMEDIATE_FN(returnFailure) {
    (void)args;
    (void)vlog;
    (void)name;
    (void)log;
    return FAILURE;
}

REMEDIATE_FN(ensureFilePermissions) {
    (void)log;
    (void)name;
    struct stat statbuf;
    if (args.find("filename") == args.end()) {
        vlog += "No filename provided";
        return FAILURE;
    }
    if (stat(args["filename"].c_str(), &statbuf) < 0) {
        vlog += "Stat error";
        return FAILURE;
    }
    uid_t uid = statbuf.st_uid;
    gid_t gid = statbuf.st_gid;
    bool owner_changed = false;
    if (args.find("user") != args.end()) {
        struct passwd *pwd = getpwnam(args["user"].c_str());
        if (pwd == NULL) {
            vlog += "No user with name";
            return FAILURE;
        }
        uid = pwd->pw_uid;
        owner_changed = true;
    }
    if (args.find("group") != args.end()) {
        struct group *grp = getgrnam(args["group"].c_str());
        if (grp == NULL) {
            vlog += "No group with name";
            return FAILURE;
        }
        gid = grp->gr_gid;
        owner_changed = true;
    }
    if (owner_changed) {
        if (chown(args["filename"].c_str(), uid, gid) < 0) {
            vlog += "Chown error";
            return FAILURE;
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
                vlog += "Chmod error";
                return FAILURE;
            }
        }
    }
    return TRUE;
}