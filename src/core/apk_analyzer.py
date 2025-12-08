"""
APK Analyzer - Static analysis using androguard
"""
from pathlib import Path
from typing import Dict, Optional


class APKAnalyzer:
    """Basic APK analyzer using androguard"""

    def __init__(self, apk_path: str):
        self.apk_path = Path(apk_path)
        self.apk = None
        self._info = {}

    def load_apk(self) -> bool:
        """Load and parse APK file"""
        try:
            from androguard.core.apk import APK
            self.apk = APK(str(self.apk_path))
            return True
        except Exception as e:
            print(f"Error loading APK: {e}")
            return False

    def get_basic_info(self) -> Dict[str, any]:
        """Extract basic information from APK"""
        if not self.apk:
            if not self.load_apk():
                return {}

        try:
            return {
                'filename': self.apk_path.name,
                'package_name': self.apk.get_package(),
                'version_name': self.apk.get_androidversion_name(),
                'version_code': self.apk.get_androidversion_code(),
                'min_sdk': self.apk.get_min_sdk_version(),
                'target_sdk': self.apk.get_target_sdk_version(),
                'size_mb': self.apk_path.stat().st_size / (1024 * 1024),
                'permissions_count': len(self.apk.get_permissions()),
                'activities_count': len(self.apk.get_activities()),
                'services_count': len(self.apk.get_services()),
                'receivers_count': len(self.apk.get_receivers())
            }
        except Exception as e:
            print(f"Error extracting info: {e}")
            return {}

    def get_file_size_mb(self) -> float:
        """Get APK file size in MB"""
        try:
            return self.apk_path.stat().st_size / (1024 * 1024)
        except Exception:
            return 0.0
