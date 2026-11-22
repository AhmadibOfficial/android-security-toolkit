"""Deterministic Android manifest attack-surface inventory.

This module analyzes declarations; it never claims exploitability or contacts a target.
All edges indicate manifest declarations only.
"""
from __future__ import annotations

from collections import Counter

ANDROID_NS = "http://schemas.android.com/apk/res/android"
KINDS = {"activity", "activity-alias", "service", "receiver", "provider"}
MAX_COMPONENTS = 1000
MAX_FILTERS = 40
MAX_DATA_ITEMS = 30
MAX_STRING = 500
MAX_NODES = 8000
MAX_EDGES = 15000


def _attr(element, key):
    if element is None:
        return None
    value = element.get(f"{{{ANDROID_NS}}}{key}")
    return str(value)[:MAX_STRING] if value is not None else None


def _parse_sdk(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _tag(element):
    return element.tag.rsplit("}", 1)[-1]


def _component_name(package, raw):
    if not raw:
        return None
    if raw.startswith("."):
        return package + raw
    if "." not in raw and package:
        return package + "." + raw
    return raw


def _exported(declared, kind, has_filters, target_sdk):
    if declared == "true":
        return True, "explicit"
    if declared == "false":
        return False, "explicit"
    if declared is not None:
        return None, "invalid_attribute"
    if kind == "provider":
        if target_sdk is None:
            return None, "target_sdk_unknown"
        return target_sdk <= 16, "sdk_default"
    if target_sdk is not None and target_sdk >= 31 and has_filters:
        return None, "missing_exported_for_target_31_plus"
    return bool(has_filters), "intent_filter_default"


def build_surface_map(manifest, *, package_name=None, target_sdk=None):
    """Return typed nodes/edges and entry-point records from decoded manifest XML.

    Works with both ElementTree and lxml-like Android manifest objects.
    Bounded output and string lengths protect consumers against pathological
    manifest sizes. There is no code execution, enumeration or network call.
    """
    sdk = _parse_sdk(target_sdk)
    if manifest is None:
        raise ValueError("Decoded Android manifest is missing")
    package = str(package_name or manifest.get("package") or "")[:MAX_STRING]
    application = next((e for e in manifest if _tag(e) == "application"), None)
    if application is None:
        raise ValueError("Manifest has no application element")

    nodes = {}
    edges = {}
    components = []
    truncated = False

    def node(key, kind, label):
        nonlocal truncated
        if key in nodes:
            return
        if len(nodes) >= MAX_NODES:
            truncated = True
            return
        nodes[key] = {"id": key, "type": kind, "label": str(label)[:MAX_STRING]}

    def edge(source, target, relation):
        nonlocal truncated
        key = (source, target, relation)
        if key in edges:
            return
        if source not in nodes or target not in nodes or len(edges) >= MAX_EDGES:
            truncated = True
            return
        edges[key] = {"source": source, "target": target,
                      "relation": relation, "evidence_source": "AndroidManifest.xml"}

    app_id = "app:" + package
    node(app_id, "app", package)
    app_disabled = _attr(application, "enabled") == "false"

    for child in application:
        kind = _tag(child)
        if kind not in KINDS:
            continue
        if len(components) >= MAX_COMPONENTS:
            truncated = True
            break
        name = _component_name(package, _attr(child, "name"))
        if name is None:
            continue
        filters = []
        for filter_element in child:
            if _tag(filter_element) != "intent-filter":
                continue
            if len(filters) >= MAX_FILTERS:
                truncated = True
                break
            actions, categories, data_items = set(), set(), []
            for item in filter_element:
                item_kind = _tag(item)
                if item_kind == "action":
                    value = _attr(item, "name")
                    if value:
                        actions.add(value)
                elif item_kind == "category":
                    value = _attr(item, "name")
                    if value:
                        categories.add(value)
                elif item_kind == "data":
                    if len(data_items) >= MAX_DATA_ITEMS:
                        truncated = True
                        continue
                    attrs = {key: _attr(item, key) for key in (
                        "scheme", "host", "port", "path", "pathPrefix", "pathPattern",
                        "pathAdvancedPattern", "mimeType")}
                    data_items.append({key: value for key, value in attrs.items() if value is not None})
            filters.append({"actions": sorted(actions), "categories": sorted(categories),
                            "data": data_items, "auto_verify": _attr(filter_element, "autoVerify") == "true"})

        explicit = _attr(child, "exported")
        exported, export_basis = _exported(explicit, kind, bool(filters), sdk)
        enabled = not (app_disabled or _attr(child, "enabled") == "false")
        declared_permission = _attr(child, "permission") or _attr(application, "permission")
        component = {
            "name": name, "kind": kind, "enabled": enabled,
            "exported": exported, "export_basis": export_basis,
            "declared_exported": explicit, "permission": declared_permission,
            "read_permission": _attr(child, "readPermission") if kind == "provider" else None,
            "write_permission": _attr(child, "writePermission") if kind == "provider" else None,
            "authorities": _attr(child, "authorities") if kind == "provider" else None,
            "filters": filters,
        }
        components.append(component)
        cid = "component:" + kind + ":" + name
        node(cid, kind, name)
        edge(app_id, cid, "declares_component")
        for perm in filter(None, {declared_permission, component["read_permission"], component["write_permission"]}):
            pid = "permission:" + perm
            node(pid, "permission", perm)
            edge(cid, pid, "declares_permission")
        for intent_filter in filters:
            for action in intent_filter["actions"]:
                aid = "action:" + action
                node(aid, "intent_action", action)
                edge(cid, aid, "accepts_action")
            for data in intent_filter["data"]:
                for field, category in (("scheme", "uri_scheme"), ("host", "uri_host")):
                    if field in data:
                        did = category + ":" + data[field]
                        node(did, category, data[field])
                        edge(cid, did, "declares_" + field)
    components.sort(key=lambda item: (item["kind"], item["name"]))
    results = {
        "schema_version": "surface/1.0", "source": "decoded_android_manifest",
        "package": package, "target_sdk": sdk, "truncated": truncated,
        "components": components,
        "nodes": sorted(nodes.values(), key=lambda n: n["id"]),
        "edges": sorted(edges.values(), key=lambda e: (e["source"], e["relation"], e["target"])),
        "summary": {
            "components": len(components),
            "exported_enabled": sum(item["enabled"] and item["exported"] is True for item in components),
            "unknown_export_state": sum(item["exported"] is None for item in components),
            "deep_link_handlers": sum(any(data.get("scheme") or data.get("host") for f in item["filters"] for data in f["data"]) for item in components),
            "by_kind": dict(sorted(Counter(item["kind"] for item in components).items())),
        },
        "limitations": [
            "Graph edges indicate manifest declarations, not confirmed runtime communication.",
            "Declared permission presence does not establish permission strength or enforcement.",
            "Intent data elements can be combined by Android and do not each define an independent URI.",
            "Export status is a manifest-derived inference, not proof that a component can be exploited.",
        ],
    }
    return results
