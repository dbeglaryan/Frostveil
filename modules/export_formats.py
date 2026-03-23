"""
Frostveil — Forensic export format converters.

Converts artifact rows to industry-standard forensic interchange formats:
  - STIX 2.1 Bundle (JSON)
  - Bodyfile / Mactime (Sleuthkit-compatible)
  - CASE / UCO Ontology (JSON-LD)
  - Elasticsearch Bulk API (NDJSON)

All functions accept a list of row dicts with keys:
    browser, artifact, url, title, visit_time_utc, extra, profile
and return the output file path.

Only stdlib imports — no third-party dependencies.
"""

import json
import uuid
import hashlib
import calendar
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_FROSTVEIL_NAMESPACE = uuid.UUID("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d")
_FROSTVEIL_IDENTITY_ID = f"identity--{uuid.uuid5(_FROSTVEIL_NAMESPACE, 'frostveil')}"


def _stix_id(stype: str, seed: str) -> str:
    """Generate a deterministic STIX-compatible ID: ``type--uuid5(ns, seed)``."""
    return f"{stype}--{uuid.uuid5(_FROSTVEIL_NAMESPACE, seed)}"


def _parse_iso_to_unix(iso_str: str):
    """Parse an ISO-8601 timestamp string to a Unix epoch integer, or None."""
    if not iso_str:
        return None
    try:
        # Handle both with and without trailing 'Z'
        cleaned = iso_str.rstrip("Z")
        dt = datetime.fromisoformat(cleaned).replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except (ValueError, TypeError, OSError):
        return None


def _row_id(row: dict) -> str:
    """Produce a stable hash string for a row (used as document _id, etc.)."""
    blob = "|".join(str(row.get(k, "")) for k in ("browser", "artifact", "url", "title", "visit_time_utc", "profile"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]


def _write_json(data: dict, path: str) -> str:
    p = Path(path)
    p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# 1. STIX 2.1 Bundle
# ---------------------------------------------------------------------------

def export_stix(rows: list, output_path: str = "frostveil_stix.json") -> str:
    """Export artifact rows as a STIX 2.1 JSON bundle.

    Mapping:
        history   -> url SCO + observed-data SDO
        cookies   -> url SCO with custom extension
        logins    -> user-account SCO
        iocs      -> indicator SDO with STIX pattern
        downloads -> file SCO + url SCO
    """
    objects = []

    # Frostveil identity
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": _FROSTVEIL_IDENTITY_ID,
        "created": "2025-01-01T00:00:00.000Z",
        "modified": "2025-01-01T00:00:00.000Z",
        "name": "Frostveil Forensic Collector",
        "identity_class": "system",
    }
    objects.append(identity)

    for row in rows:
        artifact = (row.get("artifact") or "").lower()
        url_val = row.get("url") or ""
        title = row.get("title") or ""
        browser = row.get("browser") or ""
        profile = row.get("profile") or ""
        visit_time = row.get("visit_time_utc") or ""
        extra = row.get("extra") or ""
        seed_base = f"{browser}|{artifact}|{url_val}|{title}|{visit_time}|{profile}"

        timestamp = visit_time if visit_time else "1970-01-01T00:00:00.000Z"
        if not timestamp.endswith("Z"):
            timestamp += "Z"

        if artifact in ("history", "urls", "visits"):
            # url SCO
            url_obj = {
                "type": "url",
                "spec_version": "2.1",
                "id": _stix_id("url", seed_base),
                "value": url_val,
            }
            objects.append(url_obj)

            # observed-data SDO
            obs = {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": _stix_id("observed-data", seed_base),
                "created": timestamp,
                "modified": timestamp,
                "first_observed": timestamp,
                "last_observed": timestamp,
                "number_observed": 1,
                "created_by_ref": _FROSTVEIL_IDENTITY_ID,
                "object_refs": [url_obj["id"]],
                "x_frostveil_browser": browser,
                "x_frostveil_profile": profile,
                "x_frostveil_title": title,
            }
            objects.append(obs)

        elif artifact in ("cookies", "cookie"):
            url_obj = {
                "type": "url",
                "spec_version": "2.1",
                "id": _stix_id("url", seed_base),
                "value": url_val,
                "extensions": {
                    "x-frostveil-cookie": {
                        "browser": browser,
                        "profile": profile,
                        "extra": extra,
                    }
                },
            }
            objects.append(url_obj)

        elif artifact in ("logins", "credentials", "saved_logins"):
            # Extract username from extra or title
            username = ""
            if extra:
                # extra may contain 'username: foo' or just be the username
                if ":" in extra:
                    username = extra.split(":", 1)[1].strip()
                else:
                    username = extra
            elif title:
                username = title

            # Derive domain from url
            domain = ""
            if url_val:
                try:
                    parts = url_val.split("/")
                    if len(parts) >= 3:
                        domain = parts[2]
                except Exception:
                    pass

            acct = {
                "type": "user-account",
                "spec_version": "2.1",
                "id": _stix_id("user-account", seed_base),
                "account_login": username,
                "x_frostveil_domain": domain,
                "x_frostveil_browser": browser,
                "x_frostveil_profile": profile,
            }
            objects.append(acct)

        elif artifact in ("ioc", "iocs", "indicators"):
            pattern = f"[url:value = '{url_val}']" if url_val else "[file:name = 'unknown']"
            indicator = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": _stix_id("indicator", seed_base),
                "created": timestamp,
                "modified": timestamp,
                "created_by_ref": _FROSTVEIL_IDENTITY_ID,
                "name": title or "Frostveil IOC",
                "description": extra or f"IOC detected by Frostveil in {browser}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": timestamp,
            }
            objects.append(indicator)

        elif artifact in ("downloads", "download"):
            # file SCO
            filename = title or url_val.rsplit("/", 1)[-1] if url_val else "unknown"
            file_obj = {
                "type": "file",
                "spec_version": "2.1",
                "id": _stix_id("file", seed_base),
                "name": filename,
                "x_frostveil_browser": browser,
                "x_frostveil_profile": profile,
            }
            objects.append(file_obj)

            # url SCO for the download source
            url_obj = {
                "type": "url",
                "spec_version": "2.1",
                "id": _stix_id("url", seed_base + "|dlurl"),
                "value": url_val,
            }
            objects.append(url_obj)

        else:
            # Generic fallback — observed-data with a url ref
            url_obj = {
                "type": "url",
                "spec_version": "2.1",
                "id": _stix_id("url", seed_base),
                "value": url_val,
            }
            objects.append(url_obj)

            obs = {
                "type": "observed-data",
                "spec_version": "2.1",
                "id": _stix_id("observed-data", seed_base),
                "created": timestamp,
                "modified": timestamp,
                "first_observed": timestamp,
                "last_observed": timestamp,
                "number_observed": 1,
                "created_by_ref": _FROSTVEIL_IDENTITY_ID,
                "object_refs": [url_obj["id"]],
                "x_frostveil_artifact": artifact,
                "x_frostveil_browser": browser,
                "x_frostveil_profile": profile,
            }
            objects.append(obs)

    bundle = {
        "type": "bundle",
        "id": _stix_id("bundle", "frostveil-export"),
        "objects": objects,
    }

    return _write_json(bundle, output_path)


# ---------------------------------------------------------------------------
# 2. Bodyfile / Mactime (Sleuthkit)
# ---------------------------------------------------------------------------

def export_bodyfile(rows: list, output_path: str = "frostveil_bodyfile.txt") -> str:
    """Export timed artifacts to bodyfile format for mactime / Sleuthkit.

    Format per line:
        MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

    Only rows with a parseable visit_time_utc are included.
    """
    lines = []
    for row in rows:
        ts = _parse_iso_to_unix(row.get("visit_time_utc"))
        if ts is None:
            continue

        browser = row.get("browser") or "unknown"
        artifact = row.get("artifact") or "artifact"
        url_val = row.get("url") or ""
        title = row.get("title") or ""

        name_parts = [f"[{browser}]", f"{artifact}:"]
        if title:
            name_parts.append(title)
        if url_val:
            name_parts.append(url_val)
        name = " ".join(name_parts)

        # MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
        line = f"0|{name}|0||0|0|0|{ts}|{ts}|{ts}|{ts}"
        lines.append(line)

    p = Path(output_path)
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------------------
# 3. CASE / UCO Ontology (JSON-LD)
# ---------------------------------------------------------------------------

def export_case(rows: list, output_path: str = "frostveil_case.json") -> str:
    """Export artifacts to CASE (Cyber-investigation Analysis Standard Expression)
    JSON-LD format using the UCO ontology vocabulary.
    """
    context = {
        "@context": {
            "case-investigation": "https://ontology.caseontology.org/case/investigation/",
            "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
            "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
            "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
            "kb": "http://example.org/kb/",
            "xsd": "http://www.w3.org/2001/XMLSchema#",
        }
    }

    graph_objects = []

    # Investigation action (provenance)
    investigation = {
        "@id": f"kb:{uuid.uuid5(_FROSTVEIL_NAMESPACE, 'investigation')}",
        "@type": "case-investigation:InvestigativeAction",
        "uco-core:name": "Frostveil Browser Forensic Collection",
        "uco-core:description": "Automated browser artifact extraction by Frostveil",
        "uco-core:createdBy": f"kb:{uuid.uuid5(_FROSTVEIL_NAMESPACE, 'frostveil-tool')}",
    }
    graph_objects.append(investigation)

    # Tool identity
    tool = {
        "@id": f"kb:{uuid.uuid5(_FROSTVEIL_NAMESPACE, 'frostveil-tool')}",
        "@type": "uco-core:Tool",
        "uco-core:name": "Frostveil",
        "uco-core:version": "2.0.0",
    }
    graph_objects.append(tool)

    for row in rows:
        artifact = (row.get("artifact") or "").lower()
        url_val = row.get("url") or ""
        title = row.get("title") or ""
        browser = row.get("browser") or ""
        profile = row.get("profile") or ""
        visit_time = row.get("visit_time_utc") or ""
        extra = row.get("extra") or ""
        seed_base = f"{browser}|{artifact}|{url_val}|{title}|{visit_time}|{profile}"
        obj_id = f"kb:{uuid.uuid5(_FROSTVEIL_NAMESPACE, seed_base)}"

        if artifact in ("logins", "credentials", "saved_logins"):
            username = ""
            if extra:
                username = extra.split(":", 1)[-1].strip() if ":" in extra else extra
            elif title:
                username = title

            obj = {
                "@id": obj_id,
                "@type": "uco-observable:ObservableObject",
                "uco-core:hasFacet": [
                    {
                        "@type": "uco-observable:AccountFacet",
                        "uco-observable:accountIdentifier": username,
                    },
                    {
                        "@type": "uco-observable:URLFacet",
                        "uco-observable:fullValue": url_val,
                    },
                ],
                "uco-core:description": f"Credential from {browser} (profile: {profile})",
            }
        else:
            facets = [
                {
                    "@type": "uco-observable:URLFacet",
                    "uco-observable:fullValue": url_val,
                }
            ]
            if title:
                facets.append({
                    "@type": "uco-observable:ContentDataFacet",
                    "uco-observable:dataPayload": title,
                })

            obj = {
                "@id": obj_id,
                "@type": "uco-observable:ObservableObject",
                "uco-core:hasFacet": facets,
                "uco-core:description": f"{artifact} from {browser} (profile: {profile})",
            }

        if visit_time:
            obj["uco-observable:observableCreatedTime"] = {
                "@type": "xsd:dateTime",
                "@value": visit_time if visit_time.endswith("Z") else visit_time + "Z",
            }

        graph_objects.append(obj)

    bundle = {
        **context,
        "@type": "uco-core:Bundle",
        "@id": f"kb:{uuid.uuid5(_FROSTVEIL_NAMESPACE, 'case-bundle')}",
        "@graph": graph_objects,
    }

    return _write_json(bundle, output_path)


# ---------------------------------------------------------------------------
# 4. Elasticsearch Bulk API (NDJSON)
# ---------------------------------------------------------------------------

def export_elasticsearch(
    rows: list,
    index_name: str = "frostveil",
    output_path: str = "frostveil_es_bulk.ndjson",
) -> str:
    """Export artifacts to Elasticsearch bulk API NDJSON format.

    Each entry consists of two lines:
        {"index": {"_index": "<index>", "_id": "<hash>"}}
        {<row fields with @timestamp>}
    """
    lines = []
    for row in rows:
        doc_id = _row_id(row)
        action = {"index": {"_index": index_name, "_id": doc_id}}

        source = dict(row)
        # Add @timestamp from visit_time_utc
        visit_time = row.get("visit_time_utc") or ""
        if visit_time:
            ts = visit_time if visit_time.endswith("Z") else visit_time + "Z"
        else:
            ts = None
        source["@timestamp"] = ts

        lines.append(json.dumps(action, default=str))
        lines.append(json.dumps(source, default=str))

    p = Path(output_path)
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return str(p)
