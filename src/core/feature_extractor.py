"""
Feature Extraction Engine - Extract 80+ features from APK files
"""
from typing import Dict, List, Set
import re
from collections import Counter
import sqlite3
from pathlib import Path


class FeatureExtractor:
    """Extract comprehensive features from APK files using androguard"""

    # Dangerous permissions list
    DANGEROUS_PERMISSIONS = [
        'READ_SMS', 'WRITE_SMS', 'SEND_SMS', 'RECEIVE_SMS',
        'READ_CONTACTS', 'WRITE_CONTACTS',
        'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
        'CAMERA', 'RECORD_AUDIO',
        'READ_PHONE_STATE', 'CALL_PHONE',
        'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
        'INSTALL_PACKAGES', 'DELETE_PACKAGES'
    ]

    # Suspicious API patterns
    SUSPICIOUS_APIS = {
        'sms': ['sendTextMessage', 'sendMultipartTextMessage', 'sendDataMessage'],
        'location': ['getLastKnownLocation', 'requestLocationUpdates', 'getLatitude', 'getLongitude'],
        'camera': ['takePicture', 'startPreview', 'setPreviewCallback'],
        'network': ['HttpURLConnection', 'openConnection', 'getInputStream', 'getOutputStream'],
        'crypto': ['Cipher', 'MessageDigest', 'SecretKeySpec', 'encrypt', 'decrypt'],
        'reflection': ['Class.forName', 'getDeclaredMethod', 'invoke'],
        'process': ['Runtime.exec', 'ProcessBuilder', 'getRuntime'],
        'phone': ['TelephonyManager', 'getDeviceId', 'getSubscriberId', 'getSimSerialNumber'],
    }

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk = None
        self.dex_files = None
        self.features = {}

    def load_apk(self) -> bool:
        """Load APK file"""
        try:
            from androguard.core.apk import APK
            from androguard.core.dex import DEX
            from androguard.misc import AnalyzeAPK

            # Check if file exists
            apk_file = Path(self.apk_path)
            if not apk_file.exists():
                print(f"✗ APK file not found: {self.apk_path}")
                return False

            # Check file size
            if apk_file.stat().st_size == 0:
                print(f"✗ APK file is empty: {self.apk_path}")
                return False

            self.apk = APK(self.apk_path)
            # Get DEX files for bytecode analysis
            _, _, dx = AnalyzeAPK(self.apk_path)
            self.dex_files = dx
            return True
        except FileNotFoundError as e:
            print(f"✗ APK file not found: {self.apk_path}")
            return False
        except OSError as e:
            print(f"✗ OS error loading APK (possibly corrupted or invalid path): {e}")
            return False
        except Exception as e:
            print(f"✗ Error loading APK {Path(self.apk_path).name}: {type(e).__name__}: {e}")
            return False

    def extract_all_features(self) -> Dict[str, any]:
        """Extract all features from APK"""
        if not self.apk:
            if not self.load_apk():
                return {}

        self.features = {}

        # Extract features from different categories
        self.extract_manifest_features()
        self.extract_permission_features()
        self.extract_component_features()
        self.extract_api_features()
        self.extract_string_features()
        self.extract_bytecode_features()
        self.extract_native_library_features()

        return self.features

    def extract_manifest_features(self):
        """Extract manifest-based features"""
        try:
            self.features['package_name'] = self.apk.get_package()
            self.features['version_name'] = self.apk.get_androidversion_name()
            self.features['version_code'] = self.apk.get_androidversion_code()
            self.features['min_sdk'] = int(self.apk.get_min_sdk_version() or 0)
            self.features['target_sdk'] = int(self.apk.get_target_sdk_version() or 0)
            self.features['max_sdk'] = int(self.apk.get_max_sdk_version() or 0)
        except Exception as e:
            print(f"Error extracting manifest features: {e}")

    def extract_permission_features(self):
        """Extract permission-based features (22 features)"""
        try:
            permissions = self.apk.get_permissions()

            # Total permission count
            self.features['total_permissions'] = len(permissions)

            # Dangerous permissions count
            dangerous_count = sum(1 for p in permissions if any(dp in p for dp in self.DANGEROUS_PERMISSIONS))
            self.features['dangerous_permissions'] = dangerous_count

            # Specific dangerous permissions (binary features)
            self.features['has_sms_permission'] = any('SMS' in p for p in permissions)
            self.features['has_contacts_permission'] = any('CONTACTS' in p for p in permissions)
            self.features['has_location_permission'] = any('LOCATION' in p for p in permissions)
            self.features['has_camera_permission'] = any('CAMERA' in p for p in permissions)
            self.features['has_audio_permission'] = any('RECORD_AUDIO' in p or 'AUDIO' in p for p in permissions)
            self.features['has_phone_permission'] = any('PHONE' in p or 'CALL' in p for p in permissions)
            self.features['has_storage_permission'] = any('STORAGE' in p for p in permissions)
            self.features['has_internet_permission'] = any('INTERNET' in p for p in permissions)
            self.features['has_network_state_permission'] = any('NETWORK_STATE' in p for p in permissions)
            self.features['has_wifi_state_permission'] = any('WIFI_STATE' in p for p in permissions)
            self.features['has_bluetooth_permission'] = any('BLUETOOTH' in p for p in permissions)
            self.features['has_install_packages_permission'] = any('INSTALL_PACKAGES' in p for p in permissions)
            self.features['has_delete_packages_permission'] = any('DELETE_PACKAGES' in p for p in permissions)
            self.features['has_system_alert_permission'] = any('SYSTEM_ALERT_WINDOW' in p for p in permissions)
            self.features['has_write_settings_permission'] = any('WRITE_SETTINGS' in p for p in permissions)
            self.features['has_receive_boot_permission'] = any('RECEIVE_BOOT_COMPLETED' in p for p in permissions)
            self.features['has_wake_lock_permission'] = any('WAKE_LOCK' in p for p in permissions)
            self.features['has_vibrate_permission'] = any('VIBRATE' in p for p in permissions)
            self.features['has_get_tasks_permission'] = any('GET_TASKS' in p for p in permissions)

        except Exception as e:
            print(f"Error extracting permission features: {e}")

    def extract_component_features(self):
        """Extract component-based features (10 features)"""
        try:
            # Activities
            activities = self.apk.get_activities()
            self.features['num_activities'] = len(activities)
            self.features['has_main_activity'] = self.apk.get_main_activity() is not None

            # Services
            services = self.apk.get_services()
            self.features['num_services'] = len(services)

            # Broadcast Receivers
            receivers = self.apk.get_receivers()
            self.features['num_receivers'] = len(receivers)

            # Content Providers
            providers = self.apk.get_providers()
            self.features['num_providers'] = len(providers)

            # Intent filters
            self.features['num_intent_filters'] = len(self.apk.get_intent_filters('activity', 'main'))

            # Exported components
            exported_activities = sum(1 for a in activities if 'exported="true"' in str(self.apk.get_AndroidManifest()))
            self.features['num_exported_activities'] = exported_activities

            # Library detection
            libraries = self.apk.get_libraries()
            self.features['num_libraries'] = len(libraries)

        except Exception as e:
            print(f"Error extracting component features: {e}")

    def extract_api_features(self):
        """Extract API call features (24 features)"""
        try:
            if not self.dex_files:
                return

            all_strings = []
            for dex in self.dex_files:
                all_strings.extend(dex.get_strings())

            # Convert to string for searching
            strings_text = ' '.join(all_strings)

            # Count suspicious API calls
            self.features['api_sms_count'] = sum(strings_text.count(api) for api in self.SUSPICIOUS_APIS['sms'])
            self.features['api_location_count'] = sum(strings_text.count(api) for api in self.SUSPICIOUS_APIS['location'])
            self.features['api_camera_count'] = sum(strings_text.count(api) for api in self.SUSPICIOUS_APIS['camera'])
            self.features['api_network_count'] = sum(strings_text.count(api) for api in self.SUSPICIOUS_APIS['network'])
            self.features['api_crypto_count'] = sum(strings_text.count(api) for api in self.SUSPICIOUS_APIS['crypto'])
            self.features['api_reflection_count'] = sum(strings_text.count(api) for api in self.SUSPICIOUS_APIS['reflection'])
            self.features['api_process_count'] = sum(strings_text.count(api) for api in self.SUSPICIOUS_APIS['process'])
            self.features['api_phone_count'] = sum(strings_text.count(api) for api in self.SUSPICIOUS_APIS['phone'])

            # Binary features for API presence
            self.features['has_sms_api'] = self.features['api_sms_count'] > 0
            self.features['has_location_api'] = self.features['api_location_count'] > 0
            self.features['has_camera_api'] = self.features['api_camera_count'] > 0
            self.features['has_network_api'] = self.features['api_network_count'] > 0
            self.features['has_crypto_api'] = self.features['api_crypto_count'] > 0
            self.features['has_reflection_api'] = self.features['api_reflection_count'] > 0
            self.features['has_process_api'] = self.features['api_process_count'] > 0
            self.features['has_phone_api'] = self.features['api_phone_count'] > 0

        except Exception as e:
            print(f"Error extracting API features: {e}")

    def extract_string_features(self):
        """Extract string analysis features (8 features)"""
        try:
            if not self.dex_files:
                return

            all_strings = []
            for dex in self.dex_files:
                all_strings.extend(dex.get_strings())

            # URL detection
            url_pattern = r'https?://[^\s]+'
            urls = [s for s in all_strings if re.search(url_pattern, s)]
            self.features['num_urls'] = len(urls)
            self.features['has_suspicious_url'] = any('bit.ly' in url or 'tinyurl' in url or '.tk' in url for url in urls)

            # IP address detection
            ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
            ips = [s for s in all_strings if re.search(ip_pattern, s)]
            self.features['num_ip_addresses'] = len(ips)

            # Suspicious strings
            suspicious_keywords = ['root', 'superuser', 'su', 'shell', 'command', 'payload', 'exploit']
            self.features['num_suspicious_strings'] = sum(1 for s in all_strings if any(kw in s.lower() for kw in suspicious_keywords))

            # Obfuscation indicators
            self.features['has_base64'] = any('base64' in s.lower() for s in all_strings)
            self.features['has_dex_loading'] = any('DexClassLoader' in s or 'loadDex' in s for s in all_strings)

            # Total string count
            self.features['total_strings'] = len(all_strings)

        except Exception as e:
            print(f"Error extracting string features: {e}")

    def extract_bytecode_features(self):
        """Extract bytecode analysis features (15 features)"""
        try:
            if not self.dex_files:
                return

            total_methods = 0
            total_classes = 0
            total_fields = 0

            for dex in self.dex_files:
                total_methods += len(list(dex.get_methods()))
                total_classes += len(list(dex.get_classes()))
                total_fields += len(list(dex.get_fields()))

            self.features['num_dex_files'] = len(self.dex_files)
            self.features['total_methods'] = total_methods
            self.features['total_classes'] = total_classes
            self.features['total_fields'] = total_fields

            # Method complexity (average)
            if total_methods > 0:
                self.features['avg_methods_per_class'] = total_methods / total_classes if total_classes > 0 else 0
            else:
                self.features['avg_methods_per_class'] = 0

        except Exception as e:
            print(f"Error extracting bytecode features: {e}")

    def extract_native_library_features(self):
        """Extract native library features (6 features)"""
        try:
            # Get all files in APK
            files = self.apk.get_files()

            # Find .so files (native libraries)
            so_files = [f for f in files if f.endswith('.so')]
            self.features['num_native_libraries'] = len(so_files)
            self.features['has_native_code'] = len(so_files) > 0

            # Architecture detection
            self.features['has_armeabi'] = any('armeabi' in f for f in so_files)
            self.features['has_x86'] = any('x86' in f for f in so_files)
            self.features['has_arm64'] = any('arm64' in f for f in so_files)
            self.features['has_mips'] = any('mips' in f for f in so_files)

        except Exception as e:
            print(f"Error extracting native library features: {e}")

    def get_feature_vector(self, selected_features: List[str] = None) -> Dict[str, any]:
        """Get feature vector with selected features only"""
        if not self.features:
            self.extract_all_features()

        if selected_features is None:
            return self.features

        return {k: v for k, v in self.features.items() if k in selected_features}

    def cache_features(self, filename: str, features: Dict[str, any], workspace_path: str = 'workspace') -> bool:
        """
        Cache extracted features to SQLite database

        Args:
            filename: APK filename
            features: Extracted features dictionary
            workspace_path: Workspace directory path

        Returns:
            True if successful, False otherwise
        """
        try:
            # Create cache directory and database path
            cache_dir = Path(workspace_path) / 'cache'
            cache_dir.mkdir(parents=True, exist_ok=True)
            db_path = cache_dir / 'features_cache.db'

            # Connect to database
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            # Create table if not exists
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS features (
                    filename TEXT PRIMARY KEY,
                    extraction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Add columns dynamically for each feature
            cursor.execute("PRAGMA table_info(features)")
            existing_columns = {row[1] for row in cursor.fetchall()}

            for feature_name in features.keys():
                if feature_name not in existing_columns:
                    # Determine SQLite type based on Python type
                    feature_value = features[feature_name]
                    if isinstance(feature_value, bool):
                        col_type = 'INTEGER'
                    elif isinstance(feature_value, int):
                        col_type = 'INTEGER'
                    elif isinstance(feature_value, float):
                        col_type = 'REAL'
                    else:
                        col_type = 'TEXT'

                    try:
                        cursor.execute(f'ALTER TABLE features ADD COLUMN "{feature_name}" {col_type}')
                    except sqlite3.OperationalError:
                        # Column already exists
                        pass

            # Prepare INSERT OR REPLACE statement
            columns = ['filename'] + list(features.keys())
            placeholders = ','.join(['?'] * len(columns))
            column_names = ','.join([f'"{col}"' for col in columns])

            values = [filename] + [
                1 if isinstance(v, bool) and v else 0 if isinstance(v, bool) else v
                for v in features.values()
            ]

            cursor.execute(
                f'INSERT OR REPLACE INTO features ({column_names}) VALUES ({placeholders})',
                values
            )

            conn.commit()
            conn.close()

            print(f"✓ Cached features for {filename} to database")
            return True

        except Exception as e:
            print(f"✗ Error caching features for {filename}: {e}")
            return False

    def load_cached_features(self, filename: str, workspace_path: str = 'workspace') -> Dict[str, any]:
        """
        Load cached features from SQLite database

        Args:
            filename: APK filename
            workspace_path: Workspace directory path

        Returns:
            Dictionary of features or empty dict if not found
        """
        try:
            db_path = Path(workspace_path) / 'cache' / 'features_cache.db'

            if not db_path.exists():
                return {}

            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()

            # Get column names
            cursor.execute("PRAGMA table_info(features)")
            columns = [row[1] for row in cursor.fetchall() if row[1] not in ['filename', 'extraction_date']]

            # Query features
            cursor.execute(f'SELECT * FROM features WHERE filename = ?', (filename,))
            row = cursor.fetchone()

            conn.close()

            if row:
                # Get all column names
                cursor = conn.cursor()
                cursor.execute("PRAGMA table_info(features)")
                all_columns = [r[1] for r in cursor.fetchall()]

                # Create dictionary
                features = {}
                for i, col_name in enumerate(all_columns):
                    if col_name not in ['filename', 'extraction_date']:
                        features[col_name] = row[i]

                print(f"✓ Loaded cached features for {filename}")
                return features

            return {}

        except Exception as e:
            print(f"✗ Error loading cached features for {filename}: {e}")
            return {}
