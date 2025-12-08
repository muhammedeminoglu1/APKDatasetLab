"""
Export Dataset Tab - Export processed dataset to various formats
"""
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
                             QLabel, QGroupBox, QRadioButton, QFileDialog,
                             QMessageBox, QCheckBox, QLineEdit)
from PyQt5.QtCore import Qt
from pathlib import Path
import pandas as pd
from datetime import datetime


class ExportTab(QWidget):
    """Export dataset tab"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.analysis_tab = None
        self.init_ui()

    def init_ui(self):
        """Initialize UI"""
        layout = QVBoxLayout()

        # Title
        title = QLabel("Export Dataset")
        title.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        layout.addWidget(title)

        # Format selection group
        format_group = self.create_format_group()
        layout.addWidget(format_group)

        # Export options group
        options_group = self.create_options_group()
        layout.addWidget(options_group)

        # Output path selection
        path_layout = QHBoxLayout()
        path_label = QLabel("Output Path:")
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Select output directory...")
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self.browse_output_path)
        path_layout.addWidget(path_label)
        path_layout.addWidget(self.path_input)
        path_layout.addWidget(browse_btn)
        layout.addLayout(path_layout)

        # Filename
        filename_layout = QHBoxLayout()
        filename_label = QLabel("Filename:")
        self.filename_input = QLineEdit()
        self.filename_input.setText(f"dataset_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        filename_layout.addWidget(filename_label)
        filename_layout.addWidget(self.filename_input)
        layout.addLayout(filename_layout)

        # Export button
        self.export_btn = QPushButton("Export Dataset")
        self.export_btn.setStyleSheet("background-color: #2196F3; color: white; padding: 15px; font-weight: bold; font-size: 14px;")
        self.export_btn.clicked.connect(self.export_dataset)
        layout.addWidget(self.export_btn)

        # Status label
        self.status_label = QLabel("Ready to export")
        self.status_label.setStyleSheet("padding: 10px; background-color: #f0f0f0;")
        layout.addWidget(self.status_label)

        # Dataset info
        info_group = self.create_info_group()
        layout.addWidget(info_group)

        layout.addStretch()
        self.setLayout(layout)

    def create_format_group(self) -> QGroupBox:
        """Create format selection group"""
        group = QGroupBox("Export Format")
        layout = QVBoxLayout()

        self.format_csv = QRadioButton("CSV (Comma-Separated Values)")
        self.format_csv.setChecked(True)
        layout.addWidget(self.format_csv)

        self.format_excel = QRadioButton("Excel (.xlsx)")
        layout.addWidget(self.format_excel)

        self.format_json = QRadioButton("JSON")
        layout.addWidget(self.format_json)

        self.format_arff = QRadioButton("ARFF (Weka format)")
        layout.addWidget(self.format_arff)

        self.format_libsvm = QRadioButton("LIBSVM format")
        layout.addWidget(self.format_libsvm)

        group.setLayout(layout)
        return group

    def create_options_group(self) -> QGroupBox:
        """Create export options group"""
        group = QGroupBox("Export Options")
        layout = QVBoxLayout()

        self.include_index = QCheckBox("Include row index")
        layout.addWidget(self.include_index)

        self.include_header = QCheckBox("Include column headers")
        self.include_header.setChecked(True)
        layout.addWidget(self.include_header)

        self.split_train_test = QCheckBox("Split into train/test sets (80/20)")
        layout.addWidget(self.split_train_test)

        group.setLayout(layout)
        return group

    def create_info_group(self) -> QGroupBox:
        """Create dataset info group"""
        group = QGroupBox("Dataset Information")
        layout = QVBoxLayout()

        self.info_label = QLabel("No dataset loaded")
        self.info_label.setStyleSheet("padding: 10px;")
        layout.addWidget(self.info_label)

        refresh_btn = QPushButton("Refresh Info")
        refresh_btn.clicked.connect(self.refresh_dataset_info)
        layout.addWidget(refresh_btn)

        group.setLayout(layout)
        return group

    def set_analysis_tab(self, analysis_tab):
        """Set reference to analysis tab"""
        self.analysis_tab = analysis_tab

    def browse_output_path(self):
        """Browse for output directory"""
        directory = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory",
            str(Path.home())
        )
        if directory:
            self.path_input.setText(directory)

    def refresh_dataset_info(self):
        """Refresh dataset information"""
        if not self.analysis_tab:
            self.info_label.setText("Analysis tab not initialized")
            return

        df = self.analysis_tab.get_extracted_dataframe()
        if df is None or df.empty:
            self.info_label.setText("No dataset available. Please extract features first.")
            return

        # Calculate statistics
        rows, cols = df.shape
        memory_mb = df.memory_usage(deep=True).sum() / 1024**2

        # Count labels
        label_counts = df['label'].value_counts() if 'label' in df.columns else {}

        info_text = f"Dataset Statistics:\n"
        info_text += f"- Total samples: {rows}\n"
        info_text += f"- Total features: {cols}\n"
        info_text += f"- Memory usage: {memory_mb:.2f} MB\n\n"

        if label_counts:
            info_text += "Label Distribution:\n"
            for label, count in label_counts.items():
                percentage = (count / rows) * 100
                info_text += f"  {label}: {count} ({percentage:.1f}%)\n"

        self.info_label.setText(info_text)

    def export_dataset(self):
        """Export dataset to selected format"""
        if not self.analysis_tab:
            QMessageBox.warning(self, "Error", "Analysis tab not initialized")
            return

        df = self.analysis_tab.get_extracted_dataframe()
        if df is None or df.empty:
            QMessageBox.warning(
                self,
                "No Dataset",
                "No dataset available to export. Please extract features first."
            )
            return

        # Validate inputs
        output_path = self.path_input.text().strip()
        if not output_path:
            QMessageBox.warning(self, "No Path", "Please select an output directory")
            return

        filename = self.filename_input.text().strip()
        if not filename:
            QMessageBox.warning(self, "No Filename", "Please enter a filename")
            return

        # Determine format and extension
        if self.format_csv.isChecked():
            extension = ".csv"
            format_name = "CSV"
        elif self.format_excel.isChecked():
            extension = ".xlsx"
            format_name = "Excel"
        elif self.format_json.isChecked():
            extension = ".json"
            format_name = "JSON"
        elif self.format_arff.isChecked():
            extension = ".arff"
            format_name = "ARFF"
        elif self.format_libsvm.isChecked():
            extension = ".libsvm"
            format_name = "LIBSVM"
        else:
            QMessageBox.warning(self, "No Format", "Please select an export format")
            return

        # Create full path
        if not filename.endswith(extension):
            filename += extension

        full_path = Path(output_path) / filename

        try:
            # Split train/test if requested
            if self.split_train_test.isChecked():
                self.export_train_test_split(df, full_path, extension, format_name)
            else:
                self.export_single_file(df, full_path, format_name)

            self.status_label.setText(f"Successfully exported to: {full_path}")
            QMessageBox.information(
                self,
                "Export Successful",
                f"Dataset exported successfully to:\n{full_path}"
            )

        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Failed",
                f"Failed to export dataset:\n{str(e)}"
            )
            self.status_label.setText(f"Export failed: {str(e)}")

    def export_single_file(self, df: pd.DataFrame, file_path: Path, format_name: str):
        """Export to a single file"""
        include_index = self.include_index.isChecked()
        include_header = self.include_header.isChecked()

        if format_name == "CSV":
            df.to_csv(file_path, index=include_index, header=include_header)
        elif format_name == "Excel":
            df.to_excel(file_path, index=include_index, header=include_header)
        elif format_name == "JSON":
            df.to_json(file_path, orient='records', indent=2)
        elif format_name == "ARFF":
            self.export_arff(df, file_path)
        elif format_name == "LIBSVM":
            self.export_libsvm(df, file_path)

    def export_train_test_split(self, df: pd.DataFrame, base_path: Path, extension: str, format_name: str):
        """Export with train/test split"""
        from sklearn.model_selection import train_test_split

        # Split dataset
        train_df, test_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df['label'] if 'label' in df.columns else None)

        # Create filenames
        base_name = base_path.stem
        train_path = base_path.parent / f"{base_name}_train{extension}"
        test_path = base_path.parent / f"{base_name}_test{extension}"

        # Export both files
        self.export_single_file(train_df, train_path, format_name)
        self.export_single_file(test_df, test_path, format_name)

        QMessageBox.information(
            self,
            "Split Export Successful",
            f"Dataset split and exported:\n"
            f"Train set: {train_path} ({len(train_df)} samples)\n"
            f"Test set: {test_path} ({len(test_df)} samples)"
        )

    def export_arff(self, df: pd.DataFrame, file_path: Path):
        """Export to ARFF format (Weka)"""
        with open(file_path, 'w') as f:
            # Header
            f.write(f"@RELATION android_malware\n\n")

            # Attributes
            for col in df.columns:
                if col == 'label':
                    unique_labels = df[col].unique()
                    labels_str = ','.join(str(l) for l in unique_labels)
                    f.write(f"@ATTRIBUTE {col} {{{labels_str}}}\n")
                elif df[col].dtype == 'object':
                    f.write(f"@ATTRIBUTE {col} STRING\n")
                elif df[col].dtype == 'bool':
                    f.write(f"@ATTRIBUTE {col} {{0,1}}\n")
                elif df[col].dtype in ['int64', 'float64']:
                    f.write(f"@ATTRIBUTE {col} NUMERIC\n")

            # Data
            f.write("\n@DATA\n")
            for _, row in df.iterrows():
                values = [str(v) for v in row.values]
                f.write(','.join(values) + '\n')

    def export_libsvm(self, df: pd.DataFrame, file_path: Path):
        """Export to LIBSVM format"""
        # Convert labels to numeric
        if 'label' in df.columns:
            label_map = {label: idx for idx, label in enumerate(df['label'].unique())}
            labels = df['label'].map(label_map)
        else:
            labels = [0] * len(df)

        # Get feature columns (exclude metadata)
        feature_cols = [col for col in df.columns if col not in ['filename', 'label', 'apk_path', 'package_name']]

        with open(file_path, 'w') as f:
            for idx, (_, row) in enumerate(df.iterrows()):
                label = labels.iloc[idx]
                features = []
                for feat_idx, col in enumerate(feature_cols, start=1):
                    value = row[col]
                    if pd.notna(value) and value != 0:
                        features.append(f"{feat_idx}:{value}")

                f.write(f"{label} {' '.join(features)}\n")
