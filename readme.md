# Purpose

Unit tests for file permissions / ownership. Sort of ;-)

Tools in the package check if permissions and ownership of files adhere to expectations. Permission /
ownership related issues are quite common, yet they're tedious to debug. This tool is mean to make it easier.


You define list of expected permissions and ownership once, then run the script which reports on any found
issues. The tool can also fix the permissions and ownership for you (check the advanced example)

## Examples of use case
- configuration files stored in git repo. When you do `git pull` or `git checkout file.conf` ownership and
  permissions might change. Also, `git clone` probably doesn't result in the right ownership / permissions.  
- someone runs an app as a different user (e.g. `root`), which results in some files having wrong permission / ownership,
- some user had issues with permissions so they used `chmod -R 0777 .` Yay! 

# Example
This is not guaranteed to work, as the code may change too quickly to keep them valid. Still, the examples
should give you an idea of how to use the package.

## Basic example
```python
from permtester import PermRule, Perm

SYS_UID_ROOT = 0
SYS_GID_ROOT = 0
tester = PermRule(
    SYS_UID_ROOT,
    SYS_GID_ROOT,
    Perm.from_string("rwXr-Xr-X"),
)

results = tester.test("/var/www/html/example.com/")
for result in results:
    if result.status != "SUCCESS":
        print(result)
```
## Advanced - with different rules for some child files
```python
from permtester import *

MYSQL_DATA_DIR="/var/lib/mysql/"
MYSQL_UID_MYSQL = 102
MYSQL_GID_MYSQL = 103

PERM_CHECKER_MYSQL_CERTS_PRIVATE=PermRule(
    MYSQL_UID_MYSQL,
    MYSQL_GID_MYSQL,
    Perm.from_string("rw-------")
)

PERM_CHECKER_MYSQL_CERTS_PUBLIC=PermRule(
    MYSQL_UID_MYSQL,
    MYSQL_GID_MYSQL,
    Perm.from_string("rw-r--r--")
)

tester = PermRuleGroup({
    MYSQL_DATA_DIR: PermRule(
        MYSQL_UID_MYSQL,
        MYSQL_GID_MYSQL,
        Perm.from_string("rwXr-X---"),
        overrides={
            MYSQL_DATA_DIR + "ca-key.pem": PERM_CHECKER_MYSQL_CERTS_PRIVATE,
            MYSQL_DATA_DIR + "client-key.pem": PERM_CHECKER_MYSQL_CERTS_PRIVATE,
            MYSQL_DATA_DIR + "private_key.pem": PERM_CHECKER_MYSQL_CERTS_PRIVATE,
            MYSQL_DATA_DIR + "server-key.pem": PERM_CHECKER_MYSQL_CERTS_PRIVATE,

            MYSQL_DATA_DIR + "ca.pem": PERM_CHECKER_MYSQL_CERTS_PUBLIC,
            MYSQL_DATA_DIR + "client-cert.pem": PERM_CHECKER_MYSQL_CERTS_PUBLIC,
            MYSQL_DATA_DIR + "public_key.pem": PERM_CHECKER_MYSQL_CERTS_PUBLIC,
            MYSQL_DATA_DIR + "server-cert.pem": PERM_CHECKER_MYSQL_CERTS_PUBLIC,
        }
    )
})

perm_fixer = None
if True:
    perm_fixer = PermFixer()

results = tester.test(fixer=perm_fixer)
for result in results:
    if result.status != "SUCCESS":
        print(result)
```

# Rule definitions

- format `rwxrwxrwx` (user, group, others)
- currently there's no support for setuid, setgid, sticky bit,
- `X` in rule means that:
    - directory must be executable,
    - file might be executable
- `?` means "whatever", i.e. `r?x----` means that a file must have read and execute permissions, and we don't care about
  write permission

# Future improvements
- add support for `setuid, setgid, sticky bit`
- support for rules like `ug+rwX,o+r-wx`
- wildcard support in paths (e.g. apply the `PermRule` to `*.pem` files),
- relative paths in overrides,
- define rules in yml / text files,
- docker support (e.g. "user www-data from container php can write to /var/run/mysqld/mysqld.sock"),
- make code more pythonic