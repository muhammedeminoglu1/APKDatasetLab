"""
Feature Selection Tab - Select features to extract
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QGroupBox, QCheckBox, QScrollArea,
                             QMessageBox)
from PyQt5.QtCore import Qt


class FeaturesTab(QWidget):
    """Feature selection tab"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.selected_features = set()
        self.feature_checkboxes = {}
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()

        # Title
        title = QLabel("Select Features to Extract")
        title.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(title)

        # Quick selection buttons
        button_layout = QHBoxLayout()

        select_all_btn = QPushButton("Select All")
        select_all_btn.clicked.connect(self.select_all_features)
        button_layout.addWidget(select_all_btn)

        deselect_all_btn = QPushButton("Deselect All")
        deselect_all_btn.clicked.connect(self.deselect_all_features)
        button_layout.addWidget(deselect_all_btn)

        recommended_btn = QPushButton("Recommended Features")
        recommended_btn.clicked.connect(self.select_recommended_features)
        button_layout.addWidget(recommended_btn)

        layout.addLayout(button_layout)

        # Create scroll area for feature groups
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        # Create feature groups
        scroll_layout.addWidget(self.create_manifest_features_group())
        scroll_layout.addWidget(self.create_permission_features_group())
        scroll_layout.addWidget(self.create_component_features_group())
        scroll_layout.addWidget(self.create_api_features_group())
        scroll_layout.addWidget(self.create_string_features_group())
        scroll_layout.addWidget(self.create_bytecode_features_group())
        scroll_layout.addWidget(self.create_native_features_group())

        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)

        # Status label
        self.status_label = QLabel("0 features selected")
        self.status_label.setStyleSheet("padding: 10px; background-color: #f0f0f0; font-weight: bold;")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

        # Select recommended features by default
        self.select_recommended_features()

    def create_manifest_features_group(self) -> QGroupBox:
        """Create manifest features group"""
        group = QGroupBox("Manifest Features (6)")
        layout = QVBoxLayout()

        features = [
            'min_sdk', 'target_sdk', 'max_sdk',
            'version_code', 'package_name', 'version_name'
        ]

        for feature in features:
            checkbox = QCheckBox(feature)
            checkbox.stateChanged.connect(self.update_selected_features)
            self.feature_checkboxes[feature] = checkbox
            layout.addWidget(checkbox)

        group.setLayout(layout)
        return group

    def create_permission_features_group(self) -> QGroupBox:
        """Create permission features group"""
        group = QGroupBox("Permission Features (20)")
        layout = QVBoxLayout()

        features = [
            'total_permissions', 'dangerous_permissions',
            'has_sms_permission', 'has_contacts_permission',
            'has_location_permission', 'has_camera_permission',
            'has_audio_permission', 'has_phone_permission',
            'has_storage_permission', 'has_internet_permission',
            'has_network_state_permission', 'has_wifi_state_permission',
            'has_bluetooth_permission', 'has_install_packages_permission',
            'has_delete_packages_permission', 'has_system_alert_permission',
            'has_write_settings_permission', 'has_receive_boot_permission',
            'has_wake_lock_permission', 'has_vibrate_permission',
            'has_get_tasks_permission'
        ]

        for feature in features:
            checkbox = QCheckBox(feature)
            checkbox.stateChanged.connect(self.update_selected_features)
            self.feature_checkboxes[feature] = checkbox
            layout.addWidget(checkbox)

        group.setLayout(layout)
        return group

    def create_component_features_group(self) -> QGroupBox:
        """Create component features group"""
        group = QGroupBox("Component Features (9)")
        layout = QVBoxLayout()

        features = [
            'num_activities', 'has_main_activity',
            'num_services', 'num_receivers', 'num_providers',
            'num_intent_filters', 'num_exported_activities',
            'num_libraries'
        ]

        for feature in features:
            checkbox = QCheckBox(feature)
            checkbox.stateChanged.connect(self.update_selected_features)
            self.feature_checkboxes[feature] = checkbox
            layout.addWidget(checkbox)

        group.setLayout(layout)
        return group

    def create_api_features_group(self) -> QGroupBox:
        """Create API features group"""
        group = QGroupBox("API Call Features (16)")
        layout = QVBoxLayout()

        features = [
            'api_sms_count', 'api_location_count',
            'api_camera_count', 'api_network_count',
            'api_crypto_count', 'api_reflection_count',
            'api_process_count', 'api_phone_count',
            'has_sms_api', 'has_location_api',
            'has_camera_api', 'has_network_api',
            'has_crypto_api', 'has_reflection_api',
            'has_process_api', 'has_phone_api'
        ]

        for feature in features:
            checkbox = QCheckBox(feature)
            checkbox.stateChanged.connect(self.update_selected_features)
            self.feature_checkboxes[feature] = checkbox
            layout.addWidget(checkbox)

        group.setLayout(layout)
        return group

    def create_string_features_group(self) -> QGroupBox:
        """Create string analysis features group"""
        group = QGroupBox("String Analysis Features (7)")
        layout = QVBoxLayout()

        features = [
            'num_urls', 'has_suspicious_url',
            'num_ip_addresses', 'num_suspicious_strings',
            'has_base64', 'has_dex_loading',
            'total_strings'
        ]

        for feature in features:
            checkbox = QCheckBox(feature)
            checkbox.stateChanged.connect(self.update_selected_features)
            self.feature_checkboxes[feature] = checkbox
            layout.addWidget(checkbox)

        group.setLayout(layout)
        return group

    def create_bytecode_features_group(self) -> QGroupBox:
        """Create bytecode features group"""
        group = QGroupBox("Bytecode Features (5)")
        layout = QVBoxLayout()

        features = [
            'num_dex_files', 'total_methods',
            'total_classes', 'total_fields',
            'avg_methods_per_class'
        ]

        for feature in features:
            checkbox = QCheckBox(feature)
            checkbox.stateChanged.connect(self.update_selected_features)
            self.feature_checkboxes[feature] = checkbox
            layout.addWidget(checkbox)

        group.setLayout(layout)
        return group

    def create_native_features_group(self) -> QGroupBox:
        """Create native library features group"""
        group = QGroupBox("Native Library Features (6)")
        layout = QVBoxLayout()

        features = [
            'num_native_libraries', 'has_native_code',
            'has_armeabi', 'has_x86',
            'has_arm64', 'has_mips'
        ]

        for feature in features:
            checkbox = QCheckBox(feature)
            checkbox.stateChanged.connect(self.update_selected_features)
            self.feature_checkboxes[feature] = checkbox
            layout.addWidget(checkbox)

        group.setLayout(layout)
        return group

    def select_all_features(self):
        """Select all features"""
        for checkbox in self.feature_checkboxes.values():
            checkbox.setChecked(True)
        self.update_selected_features()

    def deselect_all_features(self):
        """Deselect all features"""
        for checkbox in self.feature_checkboxes.values():
            checkbox.setChecked(False)
        self.update_selected_features()

    def select_recommended_features(self):
        """Select recommended features for malware detection"""
        # Deselect all first
        self.deselect_all_features()

        # Recommended features for malware detection
        recommended = [
            # Permissions
            'total_permissions', 'dangerous_permissions',
            'has_sms_permission', 'has_location_permission',
            'has_internet_permission', 'has_receive_boot_permission',
            'has_system_alert_permission',
            # Components
            'num_activities', 'num_services', 'num_receivers',
            'num_exported_activities',
            # APIs
            'has_sms_api', 'has_location_api', 'has_network_api',
            'has_crypto_api', 'has_reflection_api', 'has_process_api',
            # Strings
            'num_urls', 'has_suspicious_url', 'num_suspicious_strings',
            'has_dex_loading',
            # Bytecode
            'num_dex_files', 'total_methods', 'total_classes',
            # Native
            'has_native_code', 'num_native_libraries'
        ]

        for feature in recommended:
            if feature in self.feature_checkboxes:
                self.feature_checkboxes[feature].setChecked(True)

        self.update_selected_features()

    def update_selected_features(self):
        """Update selected features set"""
        self.selected_features.clear()
        for feature, checkbox in self.feature_checkboxes.items():
            if checkbox.isChecked():
                self.selected_features.add(feature)

        count = len(self.selected_features)
        self.status_label.setText(f"{count} features selected")

    def get_selected_features(self) -> list:
        """Get list of selected features"""
        return list(self.selected_features)

    def refresh_translations(self):
        """Refresh UI text after language change"""
        # Feature names are technical terms, no translation needed
        # Just update the count label
        self.update_selected_features()
