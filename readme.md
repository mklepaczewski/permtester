# Purpose

Unit tests for file permissions / ownership. Sort of ;-)

Tools in the package check if permissions and ownership of files adhere to expectations. Permission /
ownership related issues are quite common, yet they're tedious to debug. This tool is mean to make it easier.


You define list of expected permissions and ownership once, then run the script which reports on any found
issues. The tool can also fix the permissions and ownership for you (check the advanced example)

In nutshell this tool can:
- test permissions / ownership (user and group) of directory structure,
- fix any inconsistencies of permissions / ownership (you must be able to perform `chmod` and/or `chown`),
- has dry mode  

## Examples of use case
- configuration files stored in git repo. When you do `git pull` or `git checkout file.conf` ownership and
  permissions might change. Also, `git clone` probably doesn't result in the right ownership / permissions.  
- someone runs an app as a different user (e.g. `root`), which results in some files having wrong permission / ownership,
- some user had issues with permissions so they used `chmod -R 0777 .` Yay! 

# Example
This is not guaranteed to work, as the code may change too quickly to keep them valid. Still, the examples
should give you an idea of how to use the package.

## Basic example
```bash
python3 -m permtester -r rules.json
```
Sample json - check `rules.sample.json`. 
```json
{
  "policies": {
    "web-readable": {
      "uid": 33,
      "gid": 33,
      "permissions": "rwXrwX---"
    },
    "mysql-certs-private": {
      "uid": 102,
      "gid": 103,
      "permissions": "rw-------"
    },

    "mysql-certs-public": {
      "uid": 102,
      "gid": 103,
      "permissions": "rw-r--r--"
    }
  },
  "rules": {
    "web-dir": {
      "path": "/var/www/example.com",
      "policy": "web-readable",
      ""
    },
    "mysql-data": {
      "path": "/opt/tapeso-app/containers_data/var/lib/mysql/",
      "uid": 102,
      "gid": 103,
      "permissions": "rwXr-X---",
      "overrides": {
        "certs-private-1": {
          "path": "ca-key.pem",
          "policy": "mysql-certs-private"
        },
        "certs-private-2": {
          "path": "client-key.pem",
          "policy": "mysql-certs-private"
        },
        "certs-private-3": {
          "path": "private_key.pem",
          "policy": "mysql-certs-private"
        },
        "certs-private-4": {
          "path": "server-key.pem",
          "policy": "mysql-certs-private"
        },

        "certs-public-1": {
          "path": "ca.pem",
          "policy": "mysql-certs-public"
        },
        "certs-public-2": {
          "path": "client-cert.pem",
          "policy": "mysql-certs-public"
        },
        "certs-public-3": {
          "path": "public_key.pem",
          "policy": "mysql-certs-public"
        },
        "certs-public-4": {
          "path": "server-cert.pem",
          "policy": "mysql-certs-public"
        }
      }
    }
  }
}
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
- [ ] add support for `setuid, setgid, sticky bit`
- [ ] support for rules like `ug+rwX,o+r-wx`
- [ ] wildcard support in paths (e.g. apply the `PermRule` to `*.pem` files),
- [X] relative paths in overrides,
- [ ] switch to using `yield` to preserve memory,
- [X] define rules in yml / text files (done using JSON)
- [ ] docker support (e.g. "user www-data from container php can write to /var/run/mysqld/mysqld.sock"),
- [ ] make code more pythonic
