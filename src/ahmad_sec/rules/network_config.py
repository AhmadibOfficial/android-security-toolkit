"""Inspect packaged Android Network Security Config XML with cautious evidence.

Only explicit XML policy observations are reported; no runtime exploitation,
application traffic, or TLS verification is claimed. Uses synthetic-friendly
APK methods and Androguard's AXMLPrinter for compiled Android XML.
"""

import re
from xml.etree import ElementTree

ANDROID_NS = "http://schemas.android.com/apk/res/android"
MAX_XML_BYTES = 1024 * 1024


def _local(tag):
    return str(tag).rsplit("}", 1)[-1]


def _children(parent, kind):
    return [x for x in parent if _local(x.tag) == kind]


def _read_xml(data):
    if len(data) > MAX_XML_BYTES:
        raise ValueError("XML resource exceeds safe size limit")
    if data.lstrip().startswith(b"<"):
        if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
            raise ValueError("XML entities are not supported")
        return ElementTree.fromstring(data)
    from androguard.core.axml import AXMLPrinter

    printer = AXMLPrinter(data)
    if not printer.is_valid():
        raise ValueError("Android binary XML is invalid")
    return printer.get_xml_obj()


def _reference_paths(apk, reference):
    """Resolve @xml/name or @0x7f... using resource table when available."""
    files = set(apk.get_files())
    candidates = set()
    resource_ids = []
    parser = None
    if hasattr(apk, "get_android_resources"):
        try:
            parser = apk.get_android_resources()
        except (KeyError, ValueError):
            parser = None

    named = re.fullmatch(r"@(?:(?P<package>[\w.]+):)?xml/(?P<name>[\w.]+)", reference)
    numeric = re.fullmatch(r"@(?:0x)?(?P<hex>[0-9a-fA-F]{8})", reference)
    if named:
        name = named.group("name")
        for path in files:
            if re.fullmatch(r"res/xml(?:-[\w-]+)?/" + re.escape(name) + r"\.xml", path):
                candidates.add(path)
        if parser is not None:
            package = named.group("package") or (apk.get_package() if hasattr(apk, "get_package") else "")
            try:
                rid = parser.get_res_id_by_key(package, "xml", name)
                if rid is not None:
                    resource_ids.append(rid)
            except (KeyError, ValueError):
                pass
    elif numeric:
        resource_ids.append(int(numeric.group("hex"), 16))
    else:
        return []

    for rid in resource_ids:
        if parser is None:
            continue
        try:
            for _, value in parser.get_resolved_res_configs(rid):
                if isinstance(value, str) and value in files:
                    candidates.add(value)
        except (KeyError, ValueError, TypeError):
            pass

    return sorted(candidates)


def _finding(identifier, title, severity, evidence, assessment, source, scope="application"):
    return {
        "id": identifier,
        "severity": severity,
        "confidence": "HIGH",
        "title": title,
        "cwe": "CWE-319" if "cleartext" in title.lower() else None,
        "file": source,
        "component": scope,
        "evidence": evidence,
        "assessment": assessment,
    }


def _review(reference, reason):
    return [{
        "id": "AST-SEC-001-CONFIG",
        "severity": "INFO",
        "confidence": "HIGH",
        "title": "Cleartext setting requires Network Security Config review",
        "evidence": f"android:networkSecurityConfig={reference}",
        "assessment": "Parse the referenced config before determining effective policy. " + reason,
    }]


def _trust_observations(node, source, scope):
    result = []
    for anchors in _children(node, "trust-anchors"):
        for cert in _children(anchors, "certificates"):
            src = cert.get("src", "")
            override = cert.get("overridePins", "false")
            if src == "user" or src.startswith("@raw/") or override == "true":
                result.append(_finding(
                    "AST-NET-TRUST", "Custom or user trust anchor requires review", "INFO",
                    f"trust-anchor src={src}; overridePins={override}",
                    "Trust anchors are configuration evidence, not proof of a TLS bypass. "
                    "Check certificate source and effective platform policy.",
                    source, scope,
                ))
    for pins in _children(node, "pin-set"):
        expiry = pins.get("expiration", "")
        count = len(_children(pins, "pin"))
        result.append(_finding(
            "AST-NET-PINS", "Certificate pinning configuration observed", "INFO",
            f"pin-set count={count}; expiration={expiry or 'none'}",
            "Inspect pin coverage, validity and expiration; no TLS connection was tested.",
            source, scope,
        ))
    return result


def _policy_observations(root, source, target_sdk, debuggable):
    if _local(root.tag) != "network-security-config":
        raise ValueError("Unexpected Network Security Config root element")

    findings = []
    default_allowed = None if target_sdk is None else target_sdk < 28
    base_nodes = _children(root, "base-config")
    if len(base_nodes) > 1:
        raise ValueError("Multiple base-config elements")
    base = base_nodes[0] if base_nodes else None
    value = base.get("cleartextTrafficPermitted") if base is not None else None
    if value is not None and value not in {"true", "false"}:
        raise ValueError("Invalid base-config cleartext value")
    base_allowed = (value == "true") if value is not None else default_allowed
    if value == "true":
        findings.append(_finding(
            "AST-NET-CLEARTEXT-BASE", "Cleartext permitted by base-config", "MEDIUM",
            'base-config cleartextTrafficPermitted="true"',
            "Static configuration permits cleartext in the base scope. "
            "Actual insecure connections and exploitability are not established.",
            source,
        ))
    if base is not None:
        findings.extend(_trust_observations(base, source, "application"))
    if base_allowed is True and value is None:
        findings.append(_finding(
            "AST-NET-CLEARTEXT-DEFAULT", "Legacy target SDK cleartext default", "INFO",
            f"targetSdk={target_sdk}; base-config cleartextTrafficPermitted=unset",
            "The target SDK has a permissive platform default; assess supported "
            "devices and observed traffic before assigning risk.",
            source,
        ))

    def visit(node, inherited, parent_scope):
        explicit = node.get("cleartextTrafficPermitted")
        if explicit is not None and explicit not in {"true", "false"}:
            raise ValueError("Invalid domain-config cleartext value")
        effective = (explicit == "true") if explicit is not None else inherited
        domains = [
            f"{(d.text or '').strip()} (subdomains={d.get('includeSubdomains') == 'true'})"
            for d in _children(node, "domain") if (d.text or "").strip()
        ]
        scope = ", ".join(domains) if domains else parent_scope
        if explicit == "true":
            findings.append(_finding(
                "AST-NET-CLEARTEXT-DOMAIN", "Cleartext permitted for domain", "MEDIUM",
                f"domain-config={scope}; cleartextTrafficPermitted=true",
                "Explicit domain policy permits cleartext for the specified scope. "
                "Nested domain-config rules may override this policy. "
                "No actual HTTP usage has been confirmed.",
                source, scope,
            ))
        findings.extend(_trust_observations(node, source, scope))
        for child in _children(node, "domain-config"):
            visit(child, effective, scope)

    for domain in _children(root, "domain-config"):
        visit(domain, base_allowed, "application")

    debug_nodes = _children(root, "debug-overrides")
    if len(debug_nodes) > 1:
        raise ValueError("Multiple debug-overrides elements")
    for debug in debug_nodes:
        certs = [
            c.get("src", "")
            for anchors in _children(debug, "trust-anchors")
            for c in _children(anchors, "certificates")
        ]
        findings.append(_finding(
            "AST-NET-DEBUG-TRUST", "Debug trust overrides declared", "INFO",
            f"debug-overrides sources={','.join(certs) or 'none'}; debuggable={debuggable}",
            "Debug overrides affect TLS trust only in debuggable builds. "
            "They are not applied in non-debuggable releases.",
            source,
        ))
    return findings


def analyze_network_config(apk, reference):
    """Resolve all resource variants; never choose an arbitrary one."""
    try:
        paths = _reference_paths(apk, reference)
    except (AttributeError, OSError, TypeError, ValueError):
        return _review(reference, "Resource-table lookup failed.")
    if not paths:
        return _review(reference, "Referenced XML was not found in this APK.")

    if len(paths) > 1:
        return _review(
            reference,
            f"Multiple resource variants ({len(paths)}) exist: " + ", ".join(paths[:10])
            + ". Device-specific selection is not yet modeled.",
        )

    path = paths[0]
    try:
        data = apk.get_file(path)
        root = _read_xml(data)
        manifest = apk.get_android_manifest_xml()
        app = manifest.find("application") if manifest is not None else None
        debuggable = app is not None and app.get(f"{{{ANDROID_NS}}}debuggable") == "true"
        raw_target = apk.get_target_sdk_version() if hasattr(apk, "get_target_sdk_version") else None
        target_sdk = int(raw_target) if raw_target is not None else None
        return _policy_observations(root, path, target_sdk, debuggable)
    except (ValueError, TypeError, AttributeError, OSError, ElementTree.ParseError) as exc:
        return _review(reference, f"Could not parse {path}: {type(exc).__name__}.")
