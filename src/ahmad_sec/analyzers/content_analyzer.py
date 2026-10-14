from zipfile import ZipFile


def extract_text(apk_path):
    results = []

    with ZipFile(apk_path) as apk:
        for name in apk.namelist():
            if name.endswith((".xml", ".json", ".txt", ".properties")):
                try:
                    data = apk.read(name).decode("utf-8", errors="ignore")
                    results.append((name, data))
                except Exception:
                    pass

    return results
