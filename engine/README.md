# soclab engine

A small Sigma rule evaluator and a CLI that runs the rules in `../detections`
over event logs, with optional rule-to-query conversion through pySigma.

It was written for this project rather than reusing `pysigma`'s evaluation
(pySigma converts rules to backend queries; it does not match events in
Python). The evaluator supports only the slice of Sigma the rules here use;
`soclab/sigma.py` lists exactly what that is.

## Install

```
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[convert,dev]'   # drop [convert] to skip the pySigma backends
```

## Use

```
soclab list-rules detections
soclab run --rules detections data/events/win_lsass_comsvcs.jsonl
soclab run --rules detections --json out/hits.json data/events/*.jsonl
soclab convert --target lucene detections
soclab convert --target splunk detections/windows/win_proc_lsass_dump_comsvcs.yml
soclab normalise -f auditd /var/log/audit/audit.log -o out/audit.jsonl
```

## Layout

| Module | What it does |
|---|---|
| `sigma.py` | rule model, value matching, condition grammar, event matching |
| `events.py` | load JSONL, normalise Sysmon XML and auditd text to flat dicts |
| `engine.py` | route events to rules by log source, run rules, collect hits |
| `convert.py` | optional pySigma conversion to Splunk SPL / Lucene |
| `cli.py` | the `soclab` command |
