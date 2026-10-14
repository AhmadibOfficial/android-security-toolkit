from ahmad_sec.rules.secrets import scan_text


def test_synthetic_google_key_detected():
    # Invented fixture; not a working credential. Never commit real secrets.
    test_key = 'AIza' + 'A' * 35
    findings = scan_text('test=' + test_key)
    assert any('Google API Key' in f['title'] for f in findings)


def test_unrelated_text_does_not_match():
    assert scan_text('A benign training example with no keys') == []
