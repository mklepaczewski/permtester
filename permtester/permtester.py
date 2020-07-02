import os
import stat as libstat
from textwrap import wrap
from typing import List, Dict


class CheckStatus:
    def __init__(self, path: str, status: str,  message: str):
        self.path = path
        self.message = message
        self.status = status

    def __repr__(self):
        return "[" + self.status + "]\t'" + self.path + "' => " + self.message


class UnitPerm:
    def __init__(self, read: str, write: str, execute: str):
        self.read = read
        self.write = write
        self.execute = execute

    def test(self, other, path: str) -> bool:
        read = (self.read == "?") or self.read == other.read
        write = (self.write == "?") or self.write == other.write

        if self.execute == "?":
            execute = True
        elif self.execute == "X":
            if os.path.isdir(path) and not other.execute:
                execute = False
            else:
                execute = True
        else:
            execute = self.execute == other.execute

        return read and write and execute

    def __repr__(self):
        return self.read + self.write + self.execute


class Perm:
    def __init__(self, user: UnitPerm, group: UnitPerm, others: UnitPerm):
        self.user = user
        self.group = group
        self.others = others

    @staticmethod
    def from_stat(stat):
        user = UnitPerm(
            "r" if stat.st_mode & libstat.S_IRUSR > 0 else "-",
            "w" if stat.st_mode & libstat.S_IWUSR > 0 else "-",
            "x" if stat.st_mode & libstat.S_IXUSR > 0 else "-"
        )
        group = UnitPerm(
            "r" if stat.st_mode & libstat.S_IRGRP > 0 else "-",
            "w" if stat.st_mode & libstat.S_IWGRP > 0 else "-",
            "x" if stat.st_mode & libstat.S_IXGRP > 0 else "-"
        )
        others = UnitPerm(
            "r" if stat.st_mode & libstat.S_IROTH > 0 else "-",
            "w" if stat.st_mode & libstat.S_IWOTH > 0 else "-",
            "x" if stat.st_mode & libstat.S_IXOTH > 0 else "-"
        )
        return Perm(user, group, others)

    @staticmethod
    def from_string(mode: str):
        (userPerms, grouPerms, othersPerms) = wrap(mode, 3)
        user = UnitPerm(userPerms[0], userPerms[1], userPerms[2])
        group = UnitPerm(grouPerms[0], grouPerms[1], grouPerms[2])
        others = UnitPerm(othersPerms[0], othersPerms[1], othersPerms[2])
        return Perm(user, group, others)

    def test(self, perm, path: str) -> bool:
        return self.user.test(perm.user, path) \
               and self.group.test(perm.group, path) \
               and self.others.test(perm.others, path)

    def __repr__(self):
        return f"[u:{str(self.user)} g:{str(self.group)} o:{str(self.others)}]"


class PermRule:
    def __init__(self, uid: int, gid: int, perms: Perm, recursive: bool = True, must_exist: bool = True, overrides: Dict = None):
        self.uid = uid
        self.gid = gid
        self.perms = perms
        self.recursive = recursive
        self.mustExist = must_exist
        self.overrides = overrides if overrides is not None else {}

        # Directories in overrides are currently unsupported
        for p in self.overrides.keys():
            if os.path.isdir(p):
                raise Exception("Directories in overrides are not supported")

    def has_override(self, path: str) -> bool:
        return self.get_override(path) is not None

    def get_override(self, path: str):
        if path in self.overrides:
            return self.overrides[path]

    def test(self, path: str) -> List[CheckStatus]:

        results = []

        if self.has_override(path):
            return self.get_override(path).test(path)

        if not os.path.exists(path):
            if not self.mustExist:
                results.append(CheckStatus(path,  "WARN", "Path doesn't exist - but it's not required"))
                return results
            results.append(CheckStatus(path,  "ERROR", "Path doesn't exist"))
            return results
        else:
            results.append(CheckStatus(path,  "SUCCESS", "Path exists"))

        stat = os.stat(path)

        if stat.st_uid != self.uid:
            results.append(CheckStatus(path, "ERROR", f"Expected UID = {self.uid}, got {stat.st_uid}"))
        else:
            results.append(CheckStatus(path, "SUCCESS", f"Correct UID = {self.uid}"))

        if stat.st_gid != self.gid:
            results.append(CheckStatus(path, "ERROR", f"Expected GID = {self.gid}, got {stat.st_gid}"))
        else:
            results.append(CheckStatus(path, "SUCCESS", f"Correct GID = {self.gid}"))

        path_perms = Perm.from_stat(stat)
        if not self.perms.test(path_perms, path):
            results.append(CheckStatus(path, "ERROR", f"Expected perms = {self.perms}, got {path_perms}"))
        else:
            results.append(CheckStatus(path, "SUCCESS", f"Correct perms = {self.perms}, git {path_perms}"))

        if self.recursive and os.path.isdir(path):
            with os.scandir(path) as it:
                entry: os.DirEntry
                for entry in it:
                    results.extend(self.test(entry.path))

        return results


class PermRuleGroup:
    def __init__(self, perm_checkers: Dict[str, PermRule]):
        self.permCheckers = perm_checkers

    def test(self) -> List[CheckStatus]:
        results = []
        for path, checker in self.permCheckers.items():
            results.extend(checker.test(path))
        return results
