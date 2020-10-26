import os
import stat as libstat
from textwrap import wrap
from typing import List, Dict
import json
import copy


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

    def __eq__(self, other):
        return self.read == other.read and self.write == other.write and self.execute == other.execute

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
        user = UnitPerm(mode[0], mode[1], mode[2])
        group = UnitPerm(mode[3], mode[4], mode[5])
        others = UnitPerm(mode[6], mode[7], mode[8])
        return Perm(user, group, others)

    def test(self, perm, path: str) -> bool:
        return self.user.test(perm.user, path) \
               and self.group.test(perm.group, path) \
               and self.others.test(perm.others, path)

    def _overlay_onto_unit(self, perm_unit: UnitPerm, st_mode: int, read_bits: int, write_bits: int, execute_bits: int) -> int:
        new_perms = 0

        if perm_unit.read == "r":
            new_perms = new_perms | read_bits
        elif perm_unit.read == "?":
            new_perms = new_perms | (st_mode & read_bits)

        if perm_unit.write == "w":
            new_perms = new_perms | write_bits
        elif perm_unit.write == "?":
            new_perms = new_perms | (st_mode & write_bits)

        if perm_unit.execute == "x":
            new_perms = new_perms | execute_bits
        elif perm_unit.execute == "?":
            new_perms = new_perms | (st_mode & execute_bits)
        elif perm_unit.execute == "X":
            # with X - if path is a file then copy whatever we have
            # if it's a dir - mark it as executable
            if libstat.S_ISDIR(st_mode):
                new_perms = new_perms | execute_bits
            else:
                new_perms = new_perms | (st_mode & execute_bits)

        return new_perms

    def overlay_onto(self, path:  str) -> int:
        path_stat = os.stat(path)

        new_perms = self._overlay_onto_unit(self.user, path_stat.st_mode, libstat.S_IRUSR, libstat.S_IWUSR, libstat.S_IXUSR) \
                    | self._overlay_onto_unit(self.group, path_stat.st_mode, libstat.S_IRGRP, libstat.S_IWGRP, libstat.S_IXGRP) \
                    | self._overlay_onto_unit(self.others, path_stat.st_mode, libstat.S_IROTH, libstat.S_IWOTH, libstat.S_IXOTH)

        return new_perms

    def __eq__(self, other):
        return self.user == other.user and self.group == other.group and self.others == other.others

    def __repr__(self):
        return f"[u:{str(self.user)} g:{str(self.group)} o:{str(self.others)}]"


class PermFixer:
    def __init__(self, dry_mode: bool):
        self.dry_mode = dry_mode

    def fix_uid_gid(self, path: str, uid: int, gid: int) -> CheckStatus:
        try:
            if self.dry_mode:
                return CheckStatus(path, "NOTICE", f"Changed UID to {uid}, GID to {gid} (dry mode)")
            os.chown(path, uid, gid)
            return CheckStatus(path, "NOTICE", f"Changed UID to {uid}, GID to {gid}")
        except OSError as err:
            return CheckStatus(path, "ERROR", err.strerror)

    def fix_perms(self, path: str, expected_perms: Perm) -> CheckStatus:
        try:
            # expected_perms may have wildcard permission "?" so we need to overlay it onto existing permissions of
            # the path
            target_numeric_perms = expected_perms.overlay_onto(path)
            if not self.dry_mode:
                os.chmod(path, target_numeric_perms)
                return CheckStatus(path, "NOTICE", f"Changed perms to {oct(target_numeric_perms)}")
            return CheckStatus(path, "NOTICE", f"Changed perms to {oct(target_numeric_perms)} (dry mode)")
        except OSError as err:
            return CheckStatus(path, "ERROR", err.strerror)

class Policy:
    def __init__(self, id: str, uid: int, gid: int, permissions: Perm):
        self.id = id
        self.permissions = permissions
        self.uid = uid
        self.gid = gid

    def __eq__(self, other):
        return self.id == other.id and self.permissions == other.permissions and self.uid == other.uid and self.gid == other.gid

    def __repr__(self):
        return f"[id={self.id}, uid={self.uid}, gid={self.gid}, permissions={self.permissions}]"

class PermRule:
    def __init__(self, path: str, policy: Policy, recursive: bool = True, must_exist: bool = True, overrides: Dict = None):
        self.path = path
        self.policy = policy
        self.recursive = recursive
        self.mustExist = must_exist
        self.overrides = {}
        overrides = overrides if overrides is not None else {}

        # Directories in overrides are currently unsupported
        # normalize paths in case we have a directory path and it ends with "/"

        for p in overrides.keys():
            value = overrides[p]
            if p.endswith("/"):
                original_p = p
                p = p.rstrip("/")
                if p in overrides:
                    raise Exception(f"Duplicate rules - one '{original_p}' and '{p}'")
            self.overrides[p] = value

    def has_override(self, path: str) -> bool:
        return self.get_override(path) is not None

    def get_override(self, path: str):
        if path in self.overrides:
            return self.overrides[path]

    def test(self, path: str, fixer: PermFixer = None) -> List[CheckStatus]:

        results = []

        # normalize path - we expect directories to not end with "/"
        if path.endswith("/"):
            path = path.rstrip("/")

        if self.has_override(path):
            return self.get_override(path).test(path, fixer=fixer)

        if not os.path.exists(path):
            if not self.mustExist:
                results.append(CheckStatus(path,  "WARN", "Path doesn't exist - but it's not required"))
                return results
            results.append(CheckStatus(path,  "ERROR", "Path doesn't exist"))
            return results
        else:
            results.append(CheckStatus(path,  "SUCCESS", "Path exists"))

        stat = os.stat(path)

        fix_uid_gid = False
        if stat.st_uid != self.policy.uid:
            results.append(CheckStatus(path, "ERROR", f"Expected UID = {self.policy.uid}, got {stat.st_uid}"))
            fix_uid_gid = True
        else:
            results.append(CheckStatus(path, "SUCCESS", f"Correct UID = {self.policy.uid}"))

        if stat.st_gid != self.policy.gid:
            results.append(CheckStatus(path, "ERROR", f"Expected GID = {self.policy.gid}, got {stat.st_gid}"))
            fix_uid_gid = True
        else:
            results.append(CheckStatus(path, "SUCCESS", f"Correct GID = {self.policy.gid}"))

        if fixer and fix_uid_gid:
            results.append(fixer.fix_uid_gid(path, self.policy.uid, self.policy.gid))

        path_perms = Perm.from_stat(stat)
        if not self.policy.permissions.test(path_perms, path):
            results.append(CheckStatus(path, "ERROR", f"Expected perms = {self.policy.permissions}, got {path_perms}"))
            if fixer:
                results.append(fixer.fix_perms(path, self.policy.permissions))
        else:
            results.append(CheckStatus(path, "SUCCESS", f"Correct perms = {self.policy.permissions}, git {path_perms}"))

        if self.recursive and os.path.isdir(path):
            with os.scandir(path) as it:
                entry: os.DirEntry
                for entry in it:
                    results.extend(self.test(entry.path, fixer=fixer))

        return results


class SkipRule(PermRule):
    def __init__(self):
        pass

    def test(self, path: str, fixer: PermFixer = None) -> List[CheckStatus]:
        return [ CheckStatus(path, "WARN", "Skipped") ]


class PermRuleGroup:

    def __init__(self, perm_checkers: Dict[str, PermRule]):
        self.permCheckers = perm_checkers

    def test(self, fixer: PermFixer = None) -> List[CheckStatus]:
        results = []
        for path, checker in self.permCheckers.items():
            results.extend(checker.test(path, fixer=fixer))
        return results


class Config:
    def __init__(self, policies: Dict[str, Policy], rules: PermRuleGroup):
        self.policies = policies
        self.rules = rules


class JsonRuleReader:
    def __init__(self, path: str):
        self.path = path

        self.rule_stack = []
        self.policies = {}

    def get_rules(self) -> Config:
        # Make sure the file exists
        if not os.path.exists(self.path):
            raise IOError("File doesn't exist: " + self.path)
        pass

        data = None

        # Read the JSON file
        with open(self.path, 'r') as file:
            data = file.read()

        decoded = json.loads(data)

        self.policies = self._parse_policies(decoded['policies'])
        rules = self._parse_rules(decoded['rules'])
        
        result = Config(self.policies, rules)

        return result

    def _parse_policies(self, policies: Dict) -> Dict[str, Policy]:
        results = {}
        for policy_id in policies:
            results[policy_id] = Policy(policy_id, policies[policy_id]["uid"], policies[policy_id]["gid"], Perm.from_string(policies[policy_id]["permissions"]))
        return results

    def _parse_rules(self, rules: Dict) -> PermRuleGroup:
        parsed_rules = {}
        for rule_id in rules:
            rule = self._parse_rule(rule_id, rules[rule_id])
            parsed_rules[rule.path] = rule

        return PermRuleGroup(parsed_rules)

    def _get_policy(self, id: str) -> Policy:
        if id not in self.policies:
            raise ValueError("No such policy: " + id)
        return self.policies[id]

    def _parse_rule(self, rule_id: str, rule_dict: Dict) -> PermRule:
        # We inherit everything from parent, and change what is specified. But we don't inherit overrides
        policy = None
        recursive = None
        mustExist = None
        path = None
        overrides = None

        # for policy construction in case we don't inherit it
        uid = None
        gid = None
        permissions = None

        self_uid = None
        self_gid = None
        self_permissions = None

        if len(self.rule_stack):
            policy = copy.copy(self.rule_stack[-1].policy)
            recursive = self.rule_stack[-1].recursive
            mustExist = self.rule_stack[-1].mustExist
            path = self.rule_stack[-1].path

        for key in rule_dict:
            if key == "path":
                # Is it absolute or parent-relative path?
                if rule_dict[key][0] != "/":
                    # Assure we have a parent
                    if len(self.rule_stack) == 0:
                        raise ValueError("Tried to create parent-relative path but there's no parent: " + str(rule_dict[key]))
                    path = self.rule_stack[-1].path + rule_dict[key]
                else:
                    path = rule_dict[key]
            elif key == "recursive":
                recursive = rule_dict[key]
            elif key == "policy":
                policy = self._get_policy(rule_dict[key])
            elif key == "uid":
                uid = rule_dict[key]
            elif key == "gid":
                gid = rule_dict[key]
            elif key == "permissions":
                permissions = rule_dict[key]
            elif key == "self-uid":
                self_uid = rule_dict[key]
            elif key == "self-gid":
                self_gid = rule_dict[key]
            elif key == "self-permissions":
                self_permissions = rule_dict[key]
            elif key == "overrides":
                # We need to have current rule constructed to allow overrides to inherit from it. For that reason we're
                # going to process overrides later
                pass
            else:
                print("Ignoring key: " + key)

        if not policy:
            policy = Policy("runtime", uid, gid, permissions)
        else:
            # Allow for overrides of the policy
            if uid is not None:
                policy.uid = uid
                policy.id = "runtime"

            if gid is not None:
                policy.gid = gid
                policy.id = "runtime"

            if permissions is not None:
                policy.permissions = Perm.from_string(permissions)
                policy.id = "runtime"

        result = PermRule(path, policy, recursive, mustExist, overrides)

        if "overrides" in rule_dict:
            self.rule_stack.append(result)
            overrides = self._parse_rules(rule_dict["overrides"])
            self.rule_stack.pop()
            result.overrides = overrides

        return result