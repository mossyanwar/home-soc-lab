"""Convert Sigma rules to Splunk SPL or Elasticsearch Lucene queries.

This is a thin wrapper over pySigma and its Splunk and Elasticsearch backends.
It is optional: install it with ``pip install -e .[convert]``. If the backends
are not present, :func:`convert_file` raises :class:`ConvertUnavailable` with a
short message, and the CLI reports it without failing the rest of the tool.

The right processing pipeline is chosen from each rule's ``logsource.product``
so Windows rules come out with Sysmon / ECS field names.
"""

from __future__ import annotations


class ConvertUnavailable(RuntimeError):
    pass


def _require_pysigma():
    try:
        import sigma.collection  # noqa: F401
    except ImportError as exc:  # pragma: no cover - exercised without extras
        raise ConvertUnavailable(
            "pySigma is not installed; run: pip install -e '.[convert]'"
        ) from exc


def _product_of(path: str) -> str:
    import yaml

    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    return (data.get("logsource") or {}).get("product", "")


def _backend(target: str, product: str):
    if target == "splunk":
        from sigma.backends.splunk import SplunkBackend

        if product == "windows":
            from sigma.pipelines.splunk import splunk_windows_pipeline

            return SplunkBackend(splunk_windows_pipeline())
        return SplunkBackend()
    if target == "lucene":
        from sigma.backends.elasticsearch import LuceneBackend

        if product == "windows":
            from sigma.pipelines.elasticsearch.windows import ecs_windows

            return LuceneBackend(ecs_windows())
        return LuceneBackend()
    raise ValueError(f"unknown conversion target '{target}'")


def convert_file(path: str, target: str) -> list[str]:
    """Return the converted query strings for one rule file."""
    _require_pysigma()
    from sigma.collection import SigmaCollection

    product = _product_of(path)
    backend = _backend(target, product)
    with open(path, encoding="utf-8") as fh:
        collection = SigmaCollection.from_yaml(fh.read())
    return backend.convert(collection)
