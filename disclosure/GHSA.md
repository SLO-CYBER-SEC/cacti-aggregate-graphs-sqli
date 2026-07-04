# GitHub Security Advisory

## Advisory title

Authenticated SQL injection in Cacti `aggregate_graphs.php` via `local_graph_id`

## Product

Cacti

## Affected versions

- Affected: `1.3.0-dev` / `develop` branch
- Confirmed not affected: stable `1.2.31`
- Fixed version: pending vendor fix

## Severity

High

Suggested CVSS v3.1:

```text
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L
```

## CWE

CWE-89: Improper Neutralization of Special Elements used in an SQL Command

## Summary

An authenticated SQL injection vulnerability exists in Cacti `1.3.0-dev` / `develop` branch in `aggregate_graphs.php`. The `form_save()` function, in the `save_component_item` branch, passes the raw `local_graph_id` request parameter to `get_sequence()` as part of a string-based SQL `WHERE` clause.

The value is obtained through `get_request_var()` / `grv()` before integer validation is applied, and `get_sequence()` executes the resulting query without parameter binding when the group query is supplied as a string.

## Impact

An authenticated Cacti console user with aggregate-graph management access can exploit this issue by sending a crafted POST request to `/cacti/aggregate_graphs.php?action=save`. Successful exploitation can allow authenticated arbitrary database read. Sensitive database contents may include administrator credential hashes and operational secrets.

## Proof of concept

Safe timing-only proof:

```http
POST /cacti/aggregate_graphs.php?action=save HTTP/1.1
Cookie: Cacti=<authenticated session>
Content-Type: application/x-www-form-urlencoded

__csrf_magic=<token>&save_component_input=1&save_component_item=1&graph_type_id=4&local_graph_id=0 UNION SELECT SLEEP(2)
```

The `sequence` parameter is intentionally omitted to force the vulnerable `get_sequence()` branch.

A vulnerable instance responds with a measurable delay.

## Remediation

Validate `local_graph_id` as an integer before it is used in a SQL-related context. Prefer parameterized/array group queries instead of raw string `WHERE` fragments.

Recommended pattern:

```php
$local_graph_id = gfrv('local_graph_id');
srv('sequence', get_sequence($sequence, 'sequence', 'graph_templates_item',
                             ['local_graph_id' => $local_graph_id]));
```

## Credit

Reported by CYBER-SEC.

PoC author: CYBER-SEC.

Disclosure contact: `info@cyber-sec.si`.
