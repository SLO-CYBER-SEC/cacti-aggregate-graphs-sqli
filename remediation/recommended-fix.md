# Recommended fix

## Immediate fix

Validate `local_graph_id` before it is used in `get_sequence()`.

Unsafe pattern:

```php
srv('sequence', get_sequence($sequence, 'sequence', 'graph_templates_item',
                             'local_graph_id=' . grv('local_graph_id')));
```

Safer pattern:

```php
$local_graph_id = gfrv('local_graph_id');
srv('sequence', get_sequence($sequence, 'sequence', 'graph_templates_item',
                             ['local_graph_id' => $local_graph_id]));
```

## Defense-in-depth

`get_sequence()` should avoid accepting raw string `WHERE` clauses. Prefer array-based conditions that are converted into parameterized queries by `build_where_from_array()`.

If string-based group queries must remain for compatibility, audit all callers and ensure attacker-controlled input cannot enter the string path.
