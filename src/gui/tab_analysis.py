"""
Analysis & Processing Tab - Extract features from APKs
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QGroupBox, QProgressBar, QTextEdit,
                             QMessageBox, QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from pathlib import Path
from typing import List, Dict
import pandas as pd


class FeatureExtractionWorker(QThread):
    """Worker thread for feature extraction"""

    progress = pyqtSignal(int, int, str)  # current, total, apk_name
    finished = pyqtSignal(pd.DataFrame)
    error = pyqtSignal(str)

    def __init__(self, apk_table, selected_features):
        super().__init__()
        self.apk_table = apk_table
        self.selected_features = selected_features
        self.is_running = True

    def run(self):
        """Extract features from all APKs"""
        try:
            from core.feature_extractor import FeatureExtractor

            results = []
            total = self.apk_table.rowCount()

            for row in range(total):
                if not self.is_running:
                    break

                # Get APK info
                filename_item = self.apk_table.item(row, 1)
                label_item = self.apk_table.item(row, 2)
                path_item = self.apk_table.item(row, 4)

                if not (filename_item and label_item and path_item):
                    continue

                filename = filename_item.text()
                label = label_item.text()
                apk_path = path_item.text()

                self.progress.emit(row + 1, total, filename)

                # Extract features
                try:
                    extractor = FeatureExtractor(apk_path)
                    features = extractor.extract_all_features()

                    # Filter selected features
                    if self.selected_features:
                        features = {k: v for k, v in features.items()
                                   if k in self.selected_features}

                    # Add metadata
                    features['filename'] = filename
                    features['label'] = label
                    features['apk_path'] = apk_path

                    results.append(features)

                except Exception as e:
                    self.error.emit(f"Error processing {filename}: {str(e)}")
                    continue

            # Convert to DataFrame
            if results:
                df = pd.DataFrame(results)
                self.finished.emit(df)
            else:
                self.error.emit("No features extracted")

        except Exception as e:
            self.error.emit(f"Fatal error: {str(e)}")

    def stop(self):
        """Stop the worker"""
        self.is_running = False


class AnalysisTab(QWidget):
    """Analysis and processing tab"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.apk_table = None
        self.features_tab = None
        self.worker = None
        self.extracted_df = None
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()

        # Title
        title = QLabel("Feature Extraction & Processing")
        title.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(title)

        # Configuration group
        config_group = self.create_config_group()
        layout.addWidget(config_group)

        # Control buttons
        button_layout = QHBoxLayout()

        self.start_btn = QPushButton("Start Feature Extraction")
        self.start_btn.setStyleSheet("background-color: #4CAF50; color: white; padding: 10px; font-weight: bold;")
        self.start_btn.clicked.connect(self.start_extraction)
        button_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setStyleSheet("background-color: #f44336; color: white; padding: 10px;")
        self.stop_btn.clicked.connect(self.stop_extraction)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)

        layout.addLayout(button_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("Ready to extract features")
        self.status_label.setStyleSheet("padding: 10px; background-color: #e3f2fd;")
        layout.addWidget(self.status_label)

        # Log area
        log_group = QGroupBox("Extraction Log")
        log_layout = QVBoxLayout()
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(200)
        log_layout.addWidget(self.log_text)
        log_group.setLayout(log_layout)
        layout.addWidget(log_group)

        # Results group
        results_group = self.create_results_group()
        layout.addWidget(results_group)

        layout.addStretch()
        self.setLayout(layout)

    def create_config_group(self) -> QGroupBox:
        """Create configuration group"""
        group = QGroupBox("Configuration")
        layout = QVBoxLayout()

        # Normalization method
        norm_layout = QHBoxLayout()
        norm_label = QLabel("Normalization Method:")
        self.norm_combo = QComboBox()
        self.norm_combo.addItems(["None", "Standard Scaler", "Min-Max Scaler"])
        norm_layout.addWidget(norm_label)
        norm_layout.addWidget(self.norm_combo)
        norm_layout.addStretch()
        layout.addLayout(norm_layout)

        # Info text
        info = QLabel("Note: Make sure to select features in the 'Feature Selection' tab before extraction")
        info.setStyleSheet("color: #ff9800; font-size: 11px; padding: 5px;")
        layout.addWidget(info)

        group.setLayout(layout)
        return group

    def create_results_group(self) -> QGroupBox:
        """Create results group"""
        group = QGroupBox("Extraction Results")
        layout = QVBoxLayout()

        self.results_label = QLabel("No data extracted yet")
        self.results_label.setStyleSheet("padding: 10px;")
        layout.addWidget(self.results_label)

        # Preview button
        self.preview_btn = QPushButton("Preview Dataset")
        self.preview_btn.clicked.connect(self.preview_dataset)
        self.preview_btn.setEnabled(False)
        layout.addWidget(self.preview_btn)

        group.setLayout(layout)
        return group

    def set_apk_table(self, apk_table):
        """Set reference to APK table"""
        self.apk_table = apk_table

    def set_features_tab(self, features_tab):
        """Set reference to features tab"""
        self.features_tab = features_tab

    def start_extraction(self):
        """Start feature extraction process"""
        if not self.apk_table or self.apk_table.rowCount() == 0:
            QMessageBox.warning(self, "No APKs", "Please load APK files first")
            return

        if not self.features_tab:
            QMessageBox.warning(self, "Error", "Features tab not initialized")
            return

        selected_features = self.features_tab.get_selected_features()
        if not selected_features:
            reply = QMessageBox.question(
                self,
                "No Features Selected",
                "No features selected. Do you want to extract all features?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return

        # Start extraction
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.log_text.clear()
        self.log_text.append("Starting feature extraction...")

        # Create and start worker
        self.worker = FeatureExtractionWorker(self.apk_table, selected_features)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished.connect(self.on_finished)
        self.worker.error.connect(self.on_error)
        self.worker.start()

    def stop_extraction(self):
        """Stop extraction process"""
        if self.worker:
            self.worker.stop()
            self.log_text.append("Stopping extraction...")

    def on_progress(self, current: int, total: int, apk_name: str):
        """Handle progress update"""
        percentage = int((current / total) * 100)
        self.progress_bar.setValue(percentage)
        self.status_label.setText(f"Processing {current}/{total}: {apk_name}")
        self.log_text.append(f"[{current}/{total}] Extracting features from: {apk_name}")

    def on_finished(self, df: pd.DataFrame):
        """Handle extraction completion"""
        self.extracted_df = df

        # Apply normalization if selected
        norm_method = self.norm_combo.currentText()
        if norm_method != "None":
            try:
                from core.normalizer import DataNormalizer
                normalizer = DataNormalizer()

                method_map = {
                    "Standard Scaler": "standard",
                    "Min-Max Scaler": "minmax"
                }

                self.extracted_df = normalizer.normalize_dataset(
                    self.extracted_df,
                    method=method_map[norm_method]
                )
                self.log_text.append(f"Applied {norm_method} normalization")
            except Exception as e:
                self.log_text.append(f"Warning: Normalization failed: {str(e)}")

        # Update UI
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.preview_btn.setEnabled(True)

        rows, cols = df.shape
        self.results_label.setText(
            f"✓ Extraction completed!\n"
            f"Samples: {rows} | Features: {cols}\n"
            f"Memory usage: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB"
        )
        self.status_label.setText("Extraction completed successfully")
        self.log_text.append("=" * 50)
        self.log_text.append(f"Feature extraction completed!")
        self.log_text.append(f"Total samples: {rows}")
        self.log_text.append(f"Total features: {cols}")

        QMessageBox.information(
            self,
            "Extraction Complete",
            f"Successfully extracted features from {rows} APKs\n"
            f"Total features: {cols}"
        )

    def on_error(self, error_msg: str):
        """Handle extraction error"""
        self.log_text.append(f"ERROR: {error_msg}")
        self.status_label.setText("Error during extraction")

    def preview_dataset(self):
        """Preview extracted dataset"""
        if self.extracted_df is None:
            QMessageBox.warning(self, "No Data", "No dataset available to preview")
            return

        # Show first few rows
        preview_text = "Dataset Preview (first 5 rows):\n\n"
        preview_text += str(self.extracted_df.head())
        preview_text += f"\n\nShape: {self.extracted_df.shape}"
        preview_text += f"\n\nColumns: {list(self.extracted_df.columns)}"

        msg = QMessageBox(self)
        msg.setWindowTitle("Dataset Preview")
        msg.setText(preview_text)
        msg.setDetailedText(str(self.extracted_df.describe()))
        msg.exec_()

    def get_extracted_dataframe(self) -> pd.DataFrame:
        """Get extracted DataFrame"""
        return self.extracted_df

    def refresh_translations(self):
        """Refresh UI text after language change"""
        # Technical analysis UI, minimal translation needed
        pass
