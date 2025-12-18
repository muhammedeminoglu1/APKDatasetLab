"""
Export Dataset Tab - Export processed dataset to various formats
Supports: Tabular (CSV/Excel/JSON/ARFF/LIBSVM), Images (PNG), Sequences (JSON)
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QGroupBox, QRadioButton, QFileDialog,
                             QMessageBox, QCheckBox, QLineEdit, QComboBox,
                             QSpinBox, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from pathlib import Path
from datetime import datetime


class ExportWorker(QThread):
    """Worker thread for dataset export"""

    progress = pyqtSignal(str)  # status message
    finished = pyqtSignal(dict)  # export results
    error = pyqtSignal(str)  # error message

    def __init__(self, export_config):
        super().__init__()
        self.config = export_config

    def run(self):
        """Run export process"""
        try:
            from core.dataset_exporter import DatasetExporter

            exporter = DatasetExporter(self.config['workspace_path'])
            results = {}

            # Export tabular data
            if self.config['export_tabular']:
                self.progress.emit("Exporting tabular data...")

                format_ext_map = {
                    'CSV': 'csv',
                    'Excel': 'xlsx',
                    'JSON': 'json',
                    'ARFF': 'arff',
                    'LIBSVM': 'libsvm'
                }

                format_key = self.config['tabular_format']
                ext = format_ext_map[format_key]

                output_path = Path(self.config['output_dir']) / f"{self.config['filename']}.{ext}"

                tabular_results = exporter.export_tabular(
                    output_path=output_path,
                    format=ext,
                    selected_features=self.config.get('selected_features'),
                    include_labels=True,
                    train_test_split_ratio=0.2 if self.config['split_train_test'] else None
                )

                results['tabular'] = tabular_results

            # Export images
            if self.config['export_images']:
                self.progress.emit("Converting bytecode to images...")

                images_dir = Path(self.config['output_dir']) / 'images'

                image_results = exporter.export_images(
                    output_path=images_dir,
                    image_size=self.config['image_size'],
                    image_method=self.config.get('image_method', 'raw')
                )

                results['images'] = image_results

            # Export sequences
            if self.config['export_sequences']:
                self.progress.emit("Extracting sequences...")

                sequences_path = Path(self.config['output_dir']) / f"{self.config['filename']}_sequences.json"

                sequence_results = exporter.export_sequences(
                    output_path=sequences_path,
                    sequence_type=self.config['sequence_type']
                )

                results['sequences'] = sequence_results

            self.finished.emit(results)

        except Exception as e:
            self.error.emit(str(e))


class ExportTab(QWidget):
    """Export dataset tab with multiple format options"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.analysis_tab = None
        self.features_tab = None
        self.worker = None
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()

        # Title
        title = QLabel("Export Dataset")
        title.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(title)

        # Export type selection
        type_group = self.create_export_type_group()
        layout.addWidget(type_group)

        # Tabular export options
        self.tabular_group = self.create_tabular_group()
        layout.addWidget(self.tabular_group)

        # Image export options
        self.image_group = self.create_image_group()
        self.image_group.setVisible(False)
        layout.addWidget(self.image_group)

        # Sequence export options
        self.sequence_group = self.create_sequence_group()
        self.sequence_group.setVisible(False)
        layout.addWidget(self.sequence_group)

        # Output configuration
        output_group = self.create_output_group()
        layout.addWidget(output_group)

        # Export button
        self.export_btn = QPushButton("🚀 Start Export")
        self.export_btn.setStyleSheet("background-color: #2196F3; color: white; padding: 15px; font-weight: bold; font-size: 14px;")
        self.export_btn.clicked.connect(self.start_export)
        layout.addWidget(self.export_btn)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("Ready to export")
        self.status_label.setStyleSheet("padding: 10px; background-color: #f0f0f0;")
        layout.addWidget(self.status_label)

        # Dataset info
        info_group = self.create_info_group()
        layout.addWidget(info_group)

        layout.addStretch()
        self.setLayout(layout)

    def create_export_type_group(self) -> QGroupBox:
        """Create export type selection group"""
        group = QGroupBox("Export Types (Select one or more)")
        layout = QVBoxLayout()

        # Tabular data checkbox
        self.export_tabular_check = QCheckBox("📊 Tabular Data (CSV, Excel, JSON, ARFF, LIBSVM)")
        self.export_tabular_check.setChecked(True)
        self.export_tabular_check.stateChanged.connect(self.on_export_type_changed)
        layout.addWidget(self.export_tabular_check)

        # Images checkbox
        self.export_images_check = QCheckBox("🖼️ Images (Bytecode to PNG for CNN)")
        self.export_images_check.stateChanged.connect(self.on_export_type_changed)
        layout.addWidget(self.export_images_check)

        # Sequences checkbox
        self.export_sequences_check = QCheckBox("📜 Sequences (API calls, Opcodes for RNN/LSTM)")
        self.export_sequences_check.stateChanged.connect(self.on_export_type_changed)
        layout.addWidget(self.export_sequences_check)

        group.setLayout(layout)
        return group

    def create_tabular_group(self) -> QGroupBox:
        """Create tabular export options"""
        group = QGroupBox("Tabular Data Options")
        layout = QVBoxLayout()

        # Format selection
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Format:"))

        self.format_combo = QComboBox()
        self.format_combo.addItems(["CSV", "Excel", "JSON", "ARFF", "LIBSVM"])
        format_layout.addWidget(self.format_combo)
        format_layout.addStretch()
        layout.addLayout(format_layout)

        # Options
        self.split_train_test = QCheckBox("Split into train/test sets (80/20)")
        self.split_train_test.setChecked(True)
        layout.addWidget(self.split_train_test)

        self.include_header = QCheckBox("Include column headers")
        self.include_header.setChecked(True)
        layout.addWidget(self.include_header)

        group.setLayout(layout)
        return group

    def create_image_group(self) -> QGroupBox:
        """Create image export options"""
        group = QGroupBox("Image Export Options")
        layout = QVBoxLayout()

        # Image size
        size_layout = QHBoxLayout()
        size_layout.addWidget(QLabel("Image Size:"))

        self.image_size_spin = QSpinBox()
        self.image_size_spin.setRange(64, 512)
        self.image_size_spin.setValue(224)
        self.image_size_spin.setSingleStep(32)
        self.image_size_spin.setSuffix(" x " + str(self.image_size_spin.value()))
        size_layout.addWidget(self.image_size_spin)
        size_layout.addStretch()
        layout.addLayout(size_layout)

        # Method selection
        method_layout = QHBoxLayout()
        method_layout.addWidget(QLabel("Conversion Method:"))

        self.image_method_combo = QComboBox()
        self.image_method_combo.addItems([
            "Raw Bytecode", 
            "RGB (APK+DEX+Manifest)", 
            "Markov Matrix", 
            "Histogram", 
            "Entropy"
        ])
        method_layout.addWidget(self.image_method_combo)
        method_layout.addStretch()
        layout.addLayout(method_layout)

        info = QLabel("Images will be organized in folders by label (malware/benign)")
        info.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(info)

        group.setLayout(layout)
        return group

    def create_sequence_group(self) -> QGroupBox:
        """Create sequence export options"""
        group = QGroupBox("Sequence Export Options")
        layout = QVBoxLayout()

        # Sequence type
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Sequence Type:"))

        self.sequence_type_combo = QComboBox()
        self.sequence_type_combo.addItems(["API Calls", "Opcodes", "Permissions"])
        type_layout.addWidget(self.sequence_type_combo)
        type_layout.addStretch()
        layout.addLayout(type_layout)

        info = QLabel("Sequences exported as JSON for RNN/LSTM models")
        info.setStyleSheet("color: gray; font-size: 10px;")
        layout.addWidget(info)

        group.setLayout(layout)
        return group

    def create_output_group(self) -> QGroupBox:
        """Create output configuration group"""
        group = QGroupBox("Output Configuration")
        layout = QVBoxLayout()

        # Output directory
        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("Output Directory:"))

        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Select output directory...")
        default_export_dir = Path.cwd() / 'exports'
        self.path_input.setText(str(default_export_dir))
        path_layout.addWidget(self.path_input)

        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_output_path)
        path_layout.addWidget(browse_btn)
        layout.addLayout(path_layout)

        # Filename
        filename_layout = QHBoxLayout()
        filename_layout.addWidget(QLabel("Base Filename:"))

        self.filename_input = QLineEdit()
        self.filename_input.setText(f"dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        filename_layout.addWidget(self.filename_input)
        layout.addLayout(filename_layout)

        group.setLayout(layout)
        return group

    def create_info_group(self) -> QGroupBox:
        """Create dataset info group"""
        group = QGroupBox("Cache Statistics")
        layout = QVBoxLayout()

        self.info_label = QLabel("No cache information available")
        self.info_label.setStyleSheet("padding: 10px;")
        layout.addWidget(self.info_label)

        refresh_btn = QPushButton("🔄 Refresh Statistics")
        refresh_btn.clicked.connect(self.refresh_cache_info)
        layout.addWidget(refresh_btn)

        group.setLayout(layout)
        return group

    def on_export_type_changed(self):
        """Handle export type checkbox changes"""
        self.tabular_group.setVisible(self.export_tabular_check.isChecked())
        self.image_group.setVisible(self.export_images_check.isChecked())
        self.sequence_group.setVisible(self.export_sequences_check.isChecked())

    def set_analysis_tab(self, analysis_tab):
        """Set reference to analysis tab"""
        self.analysis_tab = analysis_tab

    def set_features_tab(self, features_tab):
        """Set reference to features tab"""
        self.features_tab = features_tab

    def browse_output_path(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            str(Path.home())
        )
        if directory:
            self.path_input.setText(directory)

    def refresh_cache_info(self):
        """Refresh cache statistics"""
        try:
            from core.dataset_exporter import DatasetExporter

            exporter = DatasetExporter()
            stats = exporter.get_export_statistics()

            info_text = f"📊 Cache Statistics:\n"
            info_text += f"  • Total Samples: {stats['total_samples']}\n"
            info_text += f"  • Total Features: {stats['total_features']}\n"
            info_text += f"  • Cache Size: {stats['cache_size_mb']:.2f} MB\n\n"

            if stats['total_samples'] == 0:
                info_text += "⚠️ No features cached yet. Please run feature extraction first."
            else:
                info_text += "✓ Ready to export"

            self.info_label.setText(info_text)

        except Exception as e:
            self.info_label.setText(f"Error loading cache info: {str(e)}")

    def start_export(self):
        """Start export process"""
        # Validate selections
        if not (self.export_tabular_check.isChecked() or
                self.export_images_check.isChecked() or
                self.export_sequences_check.isChecked()):
            QMessageBox.warning(self, "No Export Type",
                              "Please select at least one export type")
            return

        # Validate output path
        output_dir = self.path_input.text().strip()
        if not output_dir:
            QMessageBox.warning(self, "No Output Path",
                              "Please select an output directory")
            return

        filename = self.filename_input.text().strip()
        if not filename:
            QMessageBox.warning(self, "No Filename",
                              "Please enter a base filename")
            return

        # Build export configuration
        export_config = {
            'output_dir': output_dir,
            'filename': filename,
            'workspace_path': 'workspace',
            'export_tabular': self.export_tabular_check.isChecked(),
            'export_images': self.export_images_check.isChecked(),
            'export_sequences': self.export_sequences_check.isChecked(),
        }

        # Tabular options
        if self.export_tabular_check.isChecked():
            export_config['tabular_format'] = self.format_combo.currentText()
            export_config['split_train_test'] = self.split_train_test.isChecked()

            # Get selected features from features tab
            if self.features_tab:
                export_config['selected_features'] = self.features_tab.get_selected_features()

        # Image options
        if self.export_images_check.isChecked():
            export_config['image_size'] = self.image_size_spin.value()

            method_map = {
                "Raw Bytecode": "raw",
                "RGB (APK+DEX+Manifest)": "rgb_channels",
                "Markov Matrix": "markov",
                "Histogram": "histogram",
                "Entropy": "entropy"
            }
            export_config['image_method'] = method_map[self.image_method_combo.currentText()]

        # Sequence options
        if self.export_sequences_check.isChecked():
            type_map = {
                "API Calls": "api_calls",
                "Opcodes": "opcodes",
                "Permissions": "permissions"
            }
            export_config['sequence_type'] = type_map[self.sequence_type_combo.currentText()]

        # Start export worker
        self.export_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress

        self.worker = ExportWorker(export_config)
        self.worker.progress.connect(self.on_export_progress)
        self.worker.finished.connect(self.on_export_finished)
        self.worker.error.connect(self.on_export_error)
        self.worker.start()

    def on_export_progress(self, message: str):
        """Handle export progress update"""
        self.status_label.setText(message)

    def on_export_finished(self, results: dict):
        """Handle export completion"""
        self.export_btn.setEnabled(True)
        self.progress_bar.setVisible(False)

        # Build result message
        message = "Export completed successfully!\n\n"

        if 'tabular' in results:
            message += "📊 Tabular Data:\n"
            for key, path in results['tabular'].items():
                message += f"  • {key}: {path}\n"
            message += "\n"

        if 'images' in results:
            message += f"🖼️ Images:\n"
            message += f"  • Directory: {results['images']['images_dir']}\n"
            message += f"  • Count: {results['images']['count']}\n\n"

        if 'sequences' in results:
            message += f"📜 Sequences:\n"
            message += f"  • File: {results['sequences']['sequences']}\n"
            message += f"  • Count: {results['sequences']['count']}\n"

        self.status_label.setText("Export completed successfully!")

        QMessageBox.information(self, "Export Successful", message)

    def on_export_error(self, error_msg: str):
        """Handle export error"""
        self.export_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Export failed: {error_msg}")

        QMessageBox.critical(self, "Export Failed",
                           f"Failed to export dataset:\n\n{error_msg}")

    def refresh_translations(self):
        """Refresh UI text after language change"""
        # Most labels are technical and don't need translation
        pass
