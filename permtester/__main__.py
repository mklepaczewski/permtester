import argparse
from argparse import ArgumentParser

from permtester import JsonRuleReader
from permtester.permtester import PermissionChecker

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
        "-b",
        "--base-dir",
        help="Base directory to use.",
        default=None,
    )

    options = parser.parse_args()

    config = JsonRuleReader(options.rules, options.base_dir).get_config()

    permChecker = PermissionChecker(config.rules, options.fix, options.dry_mode, options.verbose)
    permChecker.process()
