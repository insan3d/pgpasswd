# `pgpasswd.py`

Encrypt lines from STDIN as [PostgreSQL SCRAM-SHA-256](https://www.postgresql.org/docs/current/auth-password.html) passwords. Useful for generating [pgBouncer](https://www.pgbouncer.org/config.html)'s [`userlist.txt`](https://github.com/pgbouncer/pgbouncer/blob/master/etc/userlist.txt) with encrypted passwords.

## Command-line usage

- `-h`, `--help`: Print help message and exit
- `-v`, `--version`: Show program's version number and exit
- `-s`, `--size`: Specify salt length (16 by default)
- `-d`, `--digest-len`: Specify digest length (32 by default)
- `-i`, `--iterations`: Specify PBKDF2 iterations count (4096 by default)

### Example

```bash session
echo 'myPgBouncerPassword' | pgpasswd.py
```
