# Datasets

The detections in this repo are validated against attack telemetry that other
people recorded in their own labs and published. Nothing here was captured in a
home lab (there is no lab yet; see `lab/`), and no log data is invented.

`fetch.py` downloads the specific files the rules and write-ups use. Large data
is never committed: everything downloaded lands in `data/raw/` and
`data/events/`, both gitignored. A few tiny extracts live in `tests/fixtures/`
so the tests run without a download; those carry attribution below.

## Sources and licences

| Dataset | Licence | Used for |
|---|---|---|
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | MIT | most Windows rules; the Log4Shell Linux write-up |
| [splunk/attack_data](https://github.com/splunk/attack_data) | Apache-2.0 | the Linux rules and write-ups |

Both licences permit redistribution with attribution, so the small fixtures in
`tests/fixtures/` are allowed. Each fixture file names the exact source path it
was extracted from in a header, and `tests/fixtures/SOURCES.md` lists them all.

The Splunk `attack_data` repository stores its logs with Git LFS. `fetch.py`
downloads them from the `media.githubusercontent.com` LFS endpoint, which does
not need the `git-lfs` client.

## Usage

```
python3 data/fetch.py --list            # show what can be fetched
python3 data/fetch.py windows-core      # one group
python3 data/fetch.py all               # everything the write-ups use
```

Downloaded OTRF files are unzipped into `data/events/`. Run the rules over them:

```
soclab run --rules detections data/events/*.json
```
