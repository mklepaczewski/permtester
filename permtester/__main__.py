import argparse
from argparse import ArgumentParser

from permtester import JsonRuleReader
from permtester.permtester import PermissionChecker, PermRuleGroup

if __name__ == "__main__" or __name__ == "permtester.permtester":
    parser = ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        "-d",
        "--dry-mode",
        help="Dry mode - don't fix anything. Implies --fix",
        default=False,
        action='store_true'
    )

    parser.add_argument(
        "-f",
        "--fix",
        help="Fix permissions when issues are spotted",
        default=False,
        action='store_true'
    )

    parser.add_argument(
        "-g",
        "--group",
        help="Run only for specified group",
        default=False
    )

    parser.add_argument(
        "-r",
        "--rules",
        help="Rules file",
        default="rules.json"
    )

    parser.add_argument(
        "-v",
        "--verbose",
        help="Verbose, reports successful checks",
        default=False,
        action='store_true'
    )

    parser.add_argument(
        "-l",
        "--list-rules",
        help="List available permission rules",
        default=False,
        action='store_true'
    )

    parser.add_argument(
        "-i",
        "--ignore-rule",
        help="Ignore specific rule by rule id. Can be specified multiple times",
        default=None,
        action='append',
        # nargs='*'
    )

    parser.add_argument(
        "-o",
        "--only-rule",
        help="Run only this rule (can be specified multiple times)",
        default=None,
        action='append',
        # nargs='*'
    )

    parser.add_argument(
        "-b",
        "--base-dir",
        help="Base directory to use.",
        default=None,
    )

    parser.add_argument(
        "--debug-host",
        help="PyCharm debug host, format: ip:port",
        default=None
    )

    options = parser.parse_args()

    if options.debug_host:
        host,port = options.debug_host.split(":")
        import pydevd_pycharm
        pydevd_pycharm.settrace(host, port=int(port), stdoutToServer=True, stderrToServer=True, suspend=False)

    config = JsonRuleReader(options.rules, options.base_dir).get_config()

    if options.only_rule:
        permChecks = {k: v for k,v in config.rules.permCheckers.items() if v.ruleId in options.only_rule}
        config.rules = PermRuleGroup(permChecks)

    if options.list_rules:
        for perm_rule_id, perm_rule in config.rules.permCheckers.items():
            print(perm_rule.ruleId + ":" + perm_rule.path)
        exit(0)

    permChecker = PermissionChecker(config.rules, options.fix, options.dry_mode, options.verbose, options.ignore_rule)
    permChecker.process()
