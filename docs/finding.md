# Authenticated SQL Injection in Cacti `aggregate_graphs.php` via `local_graph_id`

| Field | Value |
|---|---|
| Product | Cacti |
| Affected version | `1.3.0-dev` / `develop` branch |
| Confirmed not affected | Stable `1.2.31` |
| Component | `aggregate_graphs.php` -> `form_save()` -> `save_component_item` branch |
| Vulnerability class | CWE-89: SQL Injection |
| Privilege required | Authenticated console user with aggregate-graph management access |
| Attack vector | Network, HTTP POST |
| Severity | High |
| Suggested CVSS | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L` |
| Credit | CYBER-SEC |
| PoC author | Bahatte from CYBER-SEC |
| Contact | `zan.urbancic@cyber-sec.si` |

## Summary

`aggregate_graphs.php`, when handling the graph-item save action, builds a SQL `WHERE` fragment by concatenating the raw, unvalidated `local_graph_id` request variable and passes it to `get_sequence()`, which can execute the resulting string without parameterization.

The issue is reachable by an authenticated Cacti console user with aggregate-graph management access. The injection occurs in a numeric `WHERE` context and can be confirmed with a time-based SQL payload.

## Root cause

### Source

`grv()` / `get_request_var()` returns the raw request value when a variable has not already been registered through a validating reader.

### Sink

`get_sequence()` accepts a string `$group_query`. When `$id` is empty and `$group_query` is a string, the string is used directly as the SQL `WHERE` clause with an empty parameter array.

### Vulnerable call pattern

```php
srv('sequence', get_sequence($sequence, 'sequence', 'graph_templates_item',
                             'local_graph_id=' . grv('local_graph_id')));
```

The validated `gfrv('local_graph_id')` read occurs after this sink in the affected save path.

## Trigger conditions

The vulnerable path is reached when:

- Request path: `/cacti/aggregate_graphs.php?action=save`
- Authenticated Cacti console session is present
- Valid `__csrf_magic` token is supplied
- `save_component_input=1`
- `save_component_item=1`
- `graph_type_id=4`
- `local_graph_id` contains the injected numeric-context payload
- `sequence` is omitted or empty, forcing `get_sequence()` to calculate the next value

## Safe reproduction

Baseline request:

```text
local_graph_id=0
```

Time-delay confirmation request:

```text
local_graph_id=0 UNION SELECT SLEEP(2)
```

A vulnerable instance responds to the second request with a measurable delay.

## Impact

Successful exploitation can allow authenticated arbitrary database read. Database contents may include user credential hashes and operational secrets. This report does not include public tooling to dump such data.

## Novelty

Stable Cacti `1.2.31` was checked and is not affected because the vulnerable `get_sequence()` caller is not present in the same save path. The issue appears to be introduced by the `1.3.0-dev` refactor in the `develop` branch.

## Remediation

Validate `local_graph_id` as an integer before use and avoid raw string `WHERE` fragments.

Recommended pattern:

```php
$local_graph_id = gfrv('local_graph_id');
srv('sequence', get_sequence($sequence, 'sequence', 'graph_templates_item',
                             ['local_graph_id' => $local_graph_id]));
```

More broadly, `get_sequence()` should avoid accepting raw string `WHERE` clauses or should require parameterized input.
