import hashlib
from pathlib import Path
from androguard.core.apk import APK


class APKAnalyzer:

    def __init__(self, path):
        self.path = Path(path)
        self.apk = APK(str(self.path))

    def analyze(self):
        sha256 = hashlib.sha256(self.path.read_bytes()).hexdigest()

        return {
            "metadata": {
                "File": self.path.name,
                "Package": self.apk.get_package(),
                "App Name": self.apk.get_app_name(),
                "Version": self.apk.get_androidversion_name(),
                "Min SDK": self.apk.get_min_sdk_version(),
                "Target SDK": self.apk.get_target_sdk_version(),
                "SHA-256": sha256,
            },
            "permissions": self.apk.get_permissions(),
            "activities": self.apk.get_activities(),
            "services": self.apk.get_services(),
            "receivers": self.apk.get_receivers(),
            "providers": self.apk.get_providers(),
        }
