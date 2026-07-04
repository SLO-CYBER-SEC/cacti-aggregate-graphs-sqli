# PoC

`poc.py` is a timing-based validation script for the Cacti `aggregate_graphs.php` / `local_graph_id` SQL injection.

It validates:

- Authentication and CSRF handling
- Baseline response timing
- SQL-controlled `SLEEP()` delay
- Boolean true/false oracle sanity check

## Usage

```bash
pip3 install -r requirements.txt
python3 poc/poc.py
```
