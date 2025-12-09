"""
APK Inspector Tab - Deep inspection of APK files with Androguard
View extracted features, permissions, APIs, strings, and more
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QGroupBox, QTextEdit, QTreeWidget,
                             QTreeWidgetItem, QTabWidget, QTableWidget,
                             QTableWidgetItem, QHeaderView, QSplitter,
                             QMessageBox, QComboBox, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from pathlib import Path
from typing import Dict, List


class InspectionWorker(QThread):
    """Worker thread for deep APK inspection"""

    finished = pyqtSignal(dict)  # inspection results
    error = pyqtSignal(str)

    def __init__(self, apk_path: str):
        super().__init__()
        self.apk_path = apk_path

    def run(self):
        """Perform deep inspection"""
        try:
            from androguard.core.apk import APK
            from androguard.misc import AnalyzeAPK
            from core.feature_extractor import FeatureExtractor

            # Load APK
            apk = APK(self.apk_path)
            _, _, dx = AnalyzeAPK(self.apk_path)

            # Extract comprehensive information
            results = {
                'apk': apk,
                'dx': dx,
                'basic_info': self._extract_basic_info(apk),
                'permissions': self._extract_permissions(apk),
                'components': self._extract_components(apk),
                'api_calls': self._extract_api_calls(dx),
                'strings': self._extract_strings(dx),
                'bytecode': self._extract_bytecode_info(dx),
                'native_libs': self._extract_native_libs(apk),
                'certificates': self._extract_certificates(apk),
                'risk_score': self._calculate_risk_score(apk, dx)
            }

            # Extract features
            extractor = FeatureExtractor(self.apk_path)
            results['features'] = extractor.extract_all_features()

            self.finished.emit(results)

        except Exception as e:
            self.error.emit(f"Error inspecting APK: {str(e)}")

    def _extract_basic_info(self, apk) -> Dict:
        """Extract basic manifest information"""
        return {
            'filename': Path(self.apk_path).name,
            'package': apk.get_package(),
            'version_name': apk.get_androidversion_name(),
            'version_code': apk.get_androidversion_code(),
            'min_sdk': apk.get_min_sdk_version(),
            'target_sdk': apk.get_target_sdk_version(),
            'max_sdk': apk.get_max_sdk_version(),
            'main_activity': apk.get_main_activity(),
            'size_mb': Path(self.apk_path).stat().st_size / (1024 * 1024)
        }

    def _extract_permissions(self, apk) -> List[Dict]:
        """Extract permissions with risk levels"""
        from core.feature_extractor import FeatureExtractor

        permissions = apk.get_permissions()
        result = []

        dangerous_keywords = FeatureExtractor.DANGEROUS_PERMISSIONS

        for perm in permissions:
            perm_name = perm.split('.')[-1]
            is_dangerous = any(keyword in perm for keyword in dangerous_keywords)

            result.append({
                'name': perm,
                'short_name': perm_name,
                'is_dangerous': is_dangerous,
                'risk_level': 'HIGH' if is_dangerous else 'NORMAL'
            })

        return result

    def _extract_components(self, apk) -> Dict:
        """Extract components (activities, services, etc.)"""
        activities = apk.get_activities()
        services = apk.get_services()
        receivers = apk.get_receivers()
        providers = apk.get_providers()

        # Check for exported components
        manifest_str = str(apk.get_AndroidManifest())

        return {
            'activities': [{'name': a, 'exported': 'exported="true"' in manifest_str} for a in activities],
            'services': [{'name': s, 'exported': 'exported="true"' in manifest_str} for s in services],
            'receivers': [{'name': r, 'exported': 'exported="true"' in manifest_str} for r in receivers],
            'providers': [{'name': p, 'exported': 'exported="true"' in manifest_str} for p in providers]
        }

    def _extract_api_calls(self, dx) -> Dict:
        """Extract suspicious API calls"""
        from core.feature_extractor import FeatureExtractor

        suspicious_apis = FeatureExtractor.SUSPICIOUS_APIS
        found_apis = {category: [] for category in suspicious_apis.keys()}

        # Get all strings from DEX
        all_strings = []
        if dx:
            for dex in dx:
                all_strings.extend(dex.get_strings())

        # Search for suspicious APIs
        for category, apis in suspicious_apis.items():
            for api in apis:
                count = sum(1 for s in all_strings if api in s)
                if count > 0:
                    found_apis[category].append({'api': api, 'count': count})

        return found_apis

    def _extract_strings(self, dx) -> Dict:
        """Extract and analyze strings"""
        import re

        all_strings = []
        if dx:
            for dex in dx:
                all_strings.extend(dex.get_strings())

        # URL detection
        url_pattern = r'https?://[^\s]+'
        urls = [s for s in all_strings if re.search(url_pattern, s)]

        # IP addresses
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ips = [s for s in all_strings if re.search(ip_pattern, s) and 'http' not in s]

        # Suspicious strings
        suspicious_keywords = ['root', 'superuser', 'su', 'shell', 'command',
                              'payload', 'exploit', 'crack', 'patch']
        suspicious = [s for s in all_strings
                     if any(kw in s.lower() for kw in suspicious_keywords)]

        # Base64 patterns
        base64_pattern = r'^[A-Za-z0-9+/]{20,}={0,2}$'
        base64_strings = [s for s in all_strings if re.match(base64_pattern, s)]

        return {
            'total': len(all_strings),
            'urls': urls[:50],  # Limit to 50
            'ips': ips[:30],
            'suspicious': suspicious[:50],
            'base64': base64_strings[:20]
        }

    def _extract_bytecode_info(self, dx) -> Dict:
        """Extract bytecode statistics"""
        if not dx:
            return {}

        total_methods = 0
        total_classes = 0
        total_fields = 0

        for dex in dx:
            total_methods += len(list(dex.get_methods()))
            total_classes += len(list(dex.get_classes()))
            total_fields += len(list(dex.get_fields()))

        return {
            'dex_count': len(dx),
            'total_methods': total_methods,
            'total_classes': total_classes,
            'total_fields': total_fields,
            'methods_per_class': total_methods / total_classes if total_classes > 0 else 0
        }

    def _extract_native_libs(self, apk) -> List[Dict]:
        """Extract native library information"""
        files = apk.get_files()
        so_files = [f for f in files if f.endswith('.so')]

        libs = []
        for so_file in so_files:
            arch = 'unknown'
            if 'armeabi-v7a' in so_file:
                arch = 'armeabi-v7a'
            elif 'arm64-v8a' in so_file:
                arch = 'arm64-v8a'
            elif 'x86' in so_file:
                arch = 'x86'
            elif 'x86_64' in so_file:
                arch = 'x86_64'

            libs.append({
                'name': Path(so_file).name,
                'path': so_file,
                'arch': arch
            })

        return libs

    def _extract_certificates(self, apk) -> Dict:
        """Extract certificate information"""
        try:
            cert = apk.get_certificate_der(apk.get_signature_names()[0])
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend

            cert_obj = x509.load_der_x509_certificate(cert, default_backend())

            return {
                'subject': str(cert_obj.subject),
                'issuer': str(cert_obj.issuer),
                'serial': str(cert_obj.serial_number),
                'valid_from': str(cert_obj.not_valid_before),
                'valid_to': str(cert_obj.not_valid_after)
            }
        except Exception:
            return {'error': 'Could not extract certificate info'}

    def _calculate_risk_score(self, apk, dx) -> Dict:
        """Calculate risk score based on suspicious indicators"""
        score = 0
        reasons = []

        # Check permissions
        permissions = apk.get_permissions()
        dangerous_count = sum(1 for p in permissions if any(d in p for d in ['SMS', 'CONTACTS', 'LOCATION', 'CAMERA']))

        if dangerous_count > 5:
            score += 20
            reasons.append(f"{dangerous_count} dangerous permissions")

        # Check for reflection
        all_strings = []
        if dx:
            for dex in dx:
                all_strings.extend(dex.get_strings())

        if any('Class.forName' in s or 'getDeclaredMethod' in s for s in all_strings):
            score += 15
            reasons.append("Uses Java reflection")

        # Check for DexClassLoader
        if any('DexClassLoader' in s for s in all_strings):
            score += 20
            reasons.append("Dynamic code loading detected")

        # Check for Runtime.exec
        if any('Runtime.exec' in s for s in all_strings):
            score += 25
            reasons.append("Shell command execution")

        # Check for native code
        files = apk.get_files()
        if any(f.endswith('.so') for f in files):
            score += 10
            reasons.append("Contains native code")

        # Determine risk level
        if score >= 60:
            risk_level = 'CRITICAL'
            color = 'red'
        elif score >= 40:
            risk_level = 'HIGH'
            color = 'orange'
        elif score >= 20:
            risk_level = 'MEDIUM'
            color = 'yellow'
        else:
            risk_level = 'LOW'
            color = 'green'

        return {
            'score': score,
            'level': risk_level,
            'color': color,
            'reasons': reasons
        }


class InspectorTab(QWidget):
    """APK Inspector Tab - Deep analysis visualization"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_apk_path = None
        self.inspection_data = None
        self.worker = None
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()

        # Title and controls
        header_layout = QHBoxLayout()

        title = QLabel("🔍 APK Deep Inspector")
        title.setStyleSheet("font-size: 18px; font-weight: bold; padding: 10px;")
        header_layout.addWidget(title)

        header_layout.addStretch()

        # APK selector
        self.apk_combo = QComboBox()
        self.apk_combo.setMinimumWidth(300)
        self.apk_combo.setPlaceholderText("Select APK to inspect...")
        header_layout.addWidget(QLabel("APK:"))
        header_layout.addWidget(self.apk_combo)

        self.inspect_btn = QPushButton("🔍 Inspect")
        self.inspect_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 8px 20px; font-weight: bold;")
        self.inspect_btn.clicked.connect(self.start_inspection)
        header_layout.addWidget(self.inspect_btn)

        layout.addLayout(header_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Main content area (tabs for different views)
        self.content_tabs = QTabWidget()
        self.content_tabs.setVisible(False)

        # Create sub-tabs
        self.create_overview_tab()
        self.create_permissions_tab()
        self.create_components_tab()
        self.create_apis_tab()
        self.create_strings_tab()
        self.create_features_tab()

        layout.addWidget(self.content_tabs)

        # Info message
        self.info_label = QLabel("ℹ️ Select an APK from the APK Management tab, then click 'Inspect' to view detailed analysis")
        self.info_label.setStyleSheet("padding: 20px; background-color: #e3f2fd; border-radius: 5px; font-size: 12px;")
        self.info_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.info_label)

        self.setLayout(layout)

    def create_overview_tab(self):
        """Create overview tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Risk score display
        self.risk_group = QGroupBox("🎯 Risk Assessment")
        risk_layout = QVBoxLayout()

        self.risk_score_label = QLabel("Score: --")
        self.risk_score_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        risk_layout.addWidget(self.risk_score_label)

        self.risk_reasons = QTextEdit()
        self.risk_reasons.setReadOnly(True)
        self.risk_reasons.setMaximumHeight(100)
        risk_layout.addWidget(self.risk_reasons)

        self.risk_group.setLayout(risk_layout)
        layout.addWidget(self.risk_group)

        # Basic info
        self.info_group = QGroupBox("📋 Basic Information")
        info_layout = QVBoxLayout()

        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self.info_text.setMaximumHeight(200)
        info_layout.addWidget(self.info_text)

        self.info_group.setLayout(info_layout)
        layout.addWidget(self.info_group)

        # Bytecode statistics
        self.bytecode_group = QGroupBox("📊 Bytecode Statistics")
        bytecode_layout = QVBoxLayout()

        self.bytecode_text = QTextEdit()
        self.bytecode_text.setReadOnly(True)
        self.bytecode_text.setMaximumHeight(150)
        bytecode_layout.addWidget(self.bytecode_text)

        self.bytecode_group.setLayout(bytecode_layout)
        layout.addWidget(self.bytecode_group)

        layout.addStretch()
        widget.setLayout(layout)
        self.content_tabs.addTab(widget, "Overview")

    def create_permissions_tab(self):
        """Create permissions tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Summary
        self.perm_summary = QLabel()
        self.perm_summary.setStyleSheet("font-weight: bold; padding: 5px;")
        layout.addWidget(self.perm_summary)

        # Permissions table
        self.perm_table = QTableWidget()
        self.perm_table.setColumnCount(3)
        self.perm_table.setHorizontalHeaderLabels(["Permission", "Short Name", "Risk Level"])
        self.perm_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.perm_table.setAlternatingRowColors(True)
        layout.addWidget(self.perm_table)

        widget.setLayout(layout)
        self.content_tabs.addTab(widget, "Permissions")

    def create_components_tab(self):
        """Create components tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Tree widget for components
        self.components_tree = QTreeWidget()
        self.components_tree.setHeaderLabels(["Component", "Details"])
        self.components_tree.setAlternatingRowColors(True)
        layout.addWidget(self.components_tree)

        widget.setLayout(layout)
        self.content_tabs.addTab(widget, "Components")

    def create_apis_tab(self):
        """Create API calls tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # API summary
        self.api_summary = QLabel()
        self.api_summary.setStyleSheet("font-weight: bold; padding: 5px;")
        layout.addWidget(self.api_summary)

        # API tree
        self.api_tree = QTreeWidget()
        self.api_tree.setHeaderLabels(["Category", "API Call", "Count"])
        self.api_tree.setAlternatingRowColors(True)
        layout.addWidget(self.api_tree)

        widget.setLayout(layout)
        self.content_tabs.addTab(widget, "API Calls")

    def create_strings_tab(self):
        """Create strings analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # String tabs
        string_tabs = QTabWidget()

        # URLs
        self.urls_text = QTextEdit()
        self.urls_text.setReadOnly(True)
        string_tabs.addTab(self.urls_text, "URLs")

        # IPs
        self.ips_text = QTextEdit()
        self.ips_text.setReadOnly(True)
        string_tabs.addTab(self.ips_text, "IP Addresses")

        # Suspicious
        self.suspicious_text = QTextEdit()
        self.suspicious_text.setReadOnly(True)
        string_tabs.addTab(self.suspicious_text, "Suspicious Strings")

        # Base64
        self.base64_text = QTextEdit()
        self.base64_text.setReadOnly(True)
        string_tabs.addTab(self.base64_text, "Base64 Strings")

        layout.addWidget(string_tabs)
        widget.setLayout(layout)
        self.content_tabs.addTab(widget, "Strings")

    def create_features_tab(self):
        """Create extracted features tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Features table
        self.features_table = QTableWidget()
        self.features_table.setColumnCount(2)
        self.features_table.setHorizontalHeaderLabels(["Feature", "Value"])
        self.features_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.features_table.setAlternatingRowColors(True)
        layout.addWidget(self.features_table)

        widget.setLayout(layout)
        self.content_tabs.addTab(widget, "Extracted Features")

    def set_apk_list(self, apk_table):
        """Set APK list from APK Manager tab"""
        self.apk_combo.clear()

        for row in range(apk_table.rowCount()):
            filename_item = apk_table.item(row, 1)
            path_item = apk_table.item(row, 5)

            if filename_item and path_item:
                filename = filename_item.text()
                apk_path = path_item.text()
                self.apk_combo.addItem(filename, apk_path)

    def start_inspection(self):
        """Start APK inspection"""
        if self.apk_combo.currentIndex() == -1:
            QMessageBox.warning(self, "No APK", "Please select an APK to inspect")
            return

        apk_path = self.apk_combo.currentData()
        if not apk_path or not Path(apk_path).exists():
            QMessageBox.warning(self, "Error", "APK file not found")
            return

        self.current_apk_path = apk_path

        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.inspect_btn.setEnabled(False)
        self.info_label.setText("🔄 Analyzing APK...")

        # Start worker
        self.worker = InspectionWorker(apk_path)
        self.worker.finished.connect(self.on_inspection_finished)
        self.worker.error.connect(self.on_inspection_error)
        self.worker.start()

    def on_inspection_finished(self, results: dict):
        """Handle inspection completion"""
        self.inspection_data = results

        # Hide progress
        self.progress_bar.setVisible(False)
        self.inspect_btn.setEnabled(True)
        self.info_label.setVisible(False)
        self.content_tabs.setVisible(True)

        # Populate all tabs
        self.populate_overview(results)
        self.populate_permissions(results['permissions'])
        self.populate_components(results['components'])
        self.populate_apis(results['api_calls'])
        self.populate_strings(results['strings'])
        self.populate_features(results['features'])

    def on_inspection_error(self, error_msg: str):
        """Handle inspection error"""
        self.progress_bar.setVisible(False)
        self.inspect_btn.setEnabled(True)
        self.info_label.setText(f"❌ Error: {error_msg}")

        QMessageBox.critical(self, "Inspection Error", error_msg)

    def populate_overview(self, results: dict):
        """Populate overview tab"""
        # Risk score
        risk = results['risk_score']
        color_map = {'red': '#f44336', 'orange': '#ff9800', 'yellow': '#ffc107', 'green': '#4caf50'}

        self.risk_score_label.setText(f"Score: {risk['score']}/100 - {risk['level']}")
        self.risk_score_label.setStyleSheet(
            f"font-size: 24px; font-weight: bold; color: {color_map.get(risk['color'], 'black')};"
        )

        reasons_text = "Risk Factors:\n" + "\n".join(f"• {r}" for r in risk['reasons'])
        if not risk['reasons']:
            reasons_text = "✓ No significant risk factors detected"
        self.risk_reasons.setText(reasons_text)

        # Basic info
        info = results['basic_info']
        info_text = f"""
<b>Filename:</b> {info['filename']}<br>
<b>Package:</b> {info['package']}<br>
<b>Version:</b> {info['version_name']} (Code: {info['version_code']})<br>
<b>SDK:</b> Min {info['min_sdk']}, Target {info['target_sdk']}, Max {info['max_sdk']}<br>
<b>Main Activity:</b> {info['main_activity']}<br>
<b>Size:</b> {info['size_mb']:.2f} MB
        """
        self.info_text.setHtml(info_text)

        # Bytecode stats
        bytecode = results['bytecode']
        bytecode_text = f"""
<b>DEX Files:</b> {bytecode['dex_count']}<br>
<b>Classes:</b> {bytecode['total_classes']:,}<br>
<b>Methods:</b> {bytecode['total_methods']:,}<br>
<b>Fields:</b> {bytecode['total_fields']:,}<br>
<b>Methods per Class:</b> {bytecode['methods_per_class']:.2f}
        """
        self.bytecode_text.setHtml(bytecode_text)

    def populate_permissions(self, permissions: List[Dict]):
        """Populate permissions table"""
        self.perm_table.setRowCount(len(permissions))

        dangerous_count = sum(1 for p in permissions if p['is_dangerous'])
        self.perm_summary.setText(
            f"Total Permissions: {len(permissions)} | "
            f"Dangerous: {dangerous_count} | Normal: {len(permissions) - dangerous_count}"
        )

        for row, perm in enumerate(permissions):
            # Permission name
            name_item = QTableWidgetItem(perm['name'])
            if perm['is_dangerous']:
                name_item.setBackground(QColor(255, 235, 235))
            self.perm_table.setItem(row, 0, name_item)

            # Short name
            self.perm_table.setItem(row, 1, QTableWidgetItem(perm['short_name']))

            # Risk level
            risk_item = QTableWidgetItem(perm['risk_level'])
            if perm['is_dangerous']:
                risk_item.setForeground(QColor(255, 0, 0))
                risk_item.setFont(QFont('Arial', 10, QFont.Bold))
            self.perm_table.setItem(row, 2, risk_item)

    def populate_components(self, components: Dict):
        """Populate components tree"""
        self.components_tree.clear()

        # Activities
        activities_node = QTreeWidgetItem(self.components_tree, [f"Activities ({len(components['activities'])})", ""])
        for act in components['activities']:
            exported = "⚠️ EXPORTED" if act['exported'] else "Internal"
            item = QTreeWidgetItem(activities_node, [act['name'], exported])
            if act['exported']:
                item.setForeground(1, QColor(255, 152, 0))

        # Services
        services_node = QTreeWidgetItem(self.components_tree, [f"Services ({len(components['services'])})", ""])
        for svc in components['services']:
            exported = "⚠️ EXPORTED" if svc['exported'] else "Internal"
            item = QTreeWidgetItem(services_node, [svc['name'], exported])
            if svc['exported']:
                item.setForeground(1, QColor(255, 152, 0))

        # Receivers
        receivers_node = QTreeWidgetItem(self.components_tree, [f"Receivers ({len(components['receivers'])})", ""])
        for rcv in components['receivers']:
            exported = "⚠️ EXPORTED" if rcv['exported'] else "Internal"
            QTreeWidgetItem(receivers_node, [rcv['name'], exported])

        # Providers
        providers_node = QTreeWidgetItem(self.components_tree, [f"Providers ({len(components['providers'])})", ""])
        for prv in components['providers']:
            exported = "⚠️ EXPORTED" if prv['exported'] else "Internal"
            QTreeWidgetItem(providers_node, [prv['name'], exported])

        self.components_tree.expandAll()

    def populate_apis(self, api_calls: Dict):
        """Populate API calls tree"""
        self.api_tree.clear()

        total_calls = sum(len(apis) for apis in api_calls.values())
        self.api_summary.setText(f"Suspicious API Categories Found: {sum(1 for v in api_calls.values() if v)} | Total Calls: {total_calls}")

        for category, apis in api_calls.items():
            if not apis:
                continue

            category_node = QTreeWidgetItem(self.api_tree, [f"{category.upper()} ({len(apis)})", "", ""])

            for api_info in apis:
                item = QTreeWidgetItem(category_node, ["", api_info['api'], str(api_info['count'])])
                item.setForeground(2, QColor(255, 87, 34))

        self.api_tree.expandAll()

    def populate_strings(self, strings: Dict):
        """Populate strings tabs"""
        # URLs
        self.urls_text.setText(f"Found {len(strings['urls'])} URLs:\n\n" + "\n".join(strings['urls']))

        # IPs
        self.ips_text.setText(f"Found {len(strings['ips'])} IP Addresses:\n\n" + "\n".join(strings['ips']))

        # Suspicious
        self.suspicious_text.setText(
            f"Found {len(strings['suspicious'])} Suspicious Strings:\n\n" + "\n".join(strings['suspicious'])
        )

        # Base64
        self.base64_text.setText(
            f"Found {len(strings['base64'])} Base64 Strings:\n\n" + "\n".join(strings['base64'])
        )

    def populate_features(self, features: Dict):
        """Populate extracted features table"""
        self.features_table.setRowCount(len(features))

        for row, (feature, value) in enumerate(sorted(features.items())):
            self.features_table.setItem(row, 0, QTableWidgetItem(feature))
            self.features_table.setItem(row, 1, QTableWidgetItem(str(value)))

    def refresh_translations(self):
        """Refresh translations"""
        pass  # Technical content, no translation needed
