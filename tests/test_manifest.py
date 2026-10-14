from ahmad_sec.rules.manifest import analyze_manifest


def test_manifest_function_exists():
    assert callable(analyze_manifest)
