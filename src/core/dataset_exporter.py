"""
Dataset Exporter - Export features from cache to various ML formats
"""
import sqlite3
import pandas as pd
from pathlib import Path
from typing import List, Dict, Optional
from sklearn.model_selection import train_test_split


class DatasetExporter:
    """Export cached features to various dataset formats"""

    def __init__(self, workspace_path: str = 'workspace'):
        self.workspace_path = Path(workspace_path)
        self.cache_dir = self.workspace_path / 'cache'
        self.db_path = self.cache_dir / 'features_cache.db'

    def load_features_from_cache(self, selected_features: List[str] = None) -> pd.DataFrame:
        """
        Load all features from SQLite cache

        Args:
            selected_features: List of feature names to include (None = all)

        Returns:
            DataFrame with all cached features
        """
        if not self.db_path.exists():
            raise FileNotFoundError(f"Feature cache not found: {self.db_path}")

        conn = sqlite3.connect(str(self.db_path))

        # Load all features
        if selected_features:
            columns = ['filename'] + selected_features
            columns_str = ','.join([f'"{col}"' for col in columns])
            query = f'SELECT {columns_str} FROM features'
        else:
            query = 'SELECT * FROM features'

        df = pd.read_sql_query(query, conn)
        conn.close()

        # Remove extraction_date column if it exists
        if 'extraction_date' in df.columns:
            df = df.drop(columns=['extraction_date'])

        return df

    def merge_with_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Merge features with labels from workspace

        Args:
            df: DataFrame with features

        Returns:
            DataFrame with features and labels
        """
        from core.workspace_manager import WorkspaceManager

        workspace = WorkspaceManager(str(self.workspace_path))
        apks = workspace.get_all_apks()

        # Create label mapping
        label_map = {apk['filename']: {
            'label': apk['label'],
            'family': apk.get('family', None)
        } for apk in apks}

        # Add labels to dataframe
        df['label'] = df['filename'].map(lambda x: label_map.get(x, {}).get('label', 'UNLABELED'))
        df['family'] = df['filename'].map(lambda x: label_map.get(x, {}).get('family', None))

        return df

    def export_tabular(self, output_path: Path, format: str = 'csv',
                      selected_features: List[str] = None,
                      include_labels: bool = True,
                      train_test_split_ratio: float = None) -> Dict[str, Path]:
        """
        Export features as tabular data

        Args:
            output_path: Output file path
            format: Export format (csv, excel, json, arff, libsvm)
            selected_features: Features to include
            include_labels: Include label and family columns
            train_test_split_ratio: If set, split into train/test (e.g., 0.2 for 80/20)

        Returns:
            Dictionary of exported file paths
        """
        # Load features
        df = self.load_features_from_cache(selected_features)

        # Merge with labels
        if include_labels:
            df = self.merge_with_labels(df)

        # Split train/test if requested
        if train_test_split_ratio:
            return self._export_with_split(df, output_path, format, train_test_split_ratio)
        else:
            return self._export_single(df, output_path, format)

    def _export_single(self, df: pd.DataFrame, output_path: Path, format: str) -> Dict[str, Path]:
        """Export to single file"""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == 'csv':
            df.to_csv(output_path, index=False)
        elif format == 'excel':
            df.to_excel(output_path, index=False)
        elif format == 'json':
            df.to_json(output_path, orient='records', indent=2)
        elif format == 'arff':
            self._export_arff(df, output_path)
        elif format == 'libsvm':
            self._export_libsvm(df, output_path)
        else:
            raise ValueError(f"Unsupported format: {format}")

        print(f"✓ Exported {len(df)} samples to {output_path}")
        return {'dataset': output_path}

    def _export_with_split(self, df: pd.DataFrame, output_path: Path,
                          format: str, test_size: float) -> Dict[str, Path]:
        """Export with train/test split"""
        output_path = Path(output_path)

        # Split data
        stratify = df['label'] if 'label' in df.columns else None
        train_df, test_df = train_test_split(df, test_size=test_size,
                                             random_state=42, stratify=stratify)

        # Create file paths
        stem = output_path.stem
        ext = output_path.suffix
        train_path = output_path.parent / f"{stem}_train{ext}"
        test_path = output_path.parent / f"{stem}_test{ext}"

        # Export both
        self._export_single(train_df, train_path, format)
        self._export_single(test_df, test_path, format)

        print(f"✓ Split dataset: Train={len(train_df)}, Test={len(test_df)}")
        return {'train': train_path, 'test': test_path}

    def _export_arff(self, df: pd.DataFrame, output_path: Path):
        """Export to ARFF format (Weka)"""
        with open(output_path, 'w', encoding='utf-8') as f:
            # Header
            f.write("@RELATION android_malware_dataset\n\n")

            # Attributes
            for col in df.columns:
                if col == 'label':
                    unique_labels = df[col].unique()
                    labels_str = ','.join(str(l) for l in unique_labels)
                    f.write(f"@ATTRIBUTE {col} {{{labels_str}}}\n")
                elif col in ['filename', 'family']:
                    f.write(f"@ATTRIBUTE {col} STRING\n")
                elif df[col].dtype == 'bool':
                    f.write(f"@ATTRIBUTE {col} {{0,1}}\n")
                elif df[col].dtype in ['int64', 'float64']:
                    f.write(f"@ATTRIBUTE {col} NUMERIC\n")
                else:
                    f.write(f"@ATTRIBUTE {col} STRING\n")

            # Data
            f.write("\n@DATA\n")
            for _, row in df.iterrows():
                values = []
                for v in row.values:
                    if pd.isna(v):
                        values.append('?')
                    elif isinstance(v, str):
                        values.append(f'"{v}"')
                    else:
                        values.append(str(v))
                f.write(','.join(values) + '\n')

    def _export_libsvm(self, df: pd.DataFrame, output_path: Path):
        """Export to LIBSVM format"""
        # Convert labels to numeric
        if 'label' in df.columns:
            label_map = {label: idx for idx, label in enumerate(df['label'].unique())}
            labels = df['label'].map(label_map)

            # Save label mapping
            label_map_path = output_path.parent / f"{output_path.stem}_labels.txt"
            with open(label_map_path, 'w') as f:
                for label, idx in label_map.items():
                    f.write(f"{idx}: {label}\n")
        else:
            labels = [0] * len(df)

        # Get feature columns (exclude metadata)
        exclude_cols = ['filename', 'label', 'family', 'apk_path', 'package_name']
        feature_cols = [col for col in df.columns if col not in exclude_cols]

        with open(output_path, 'w') as f:
            for idx, (_, row) in enumerate(df.iterrows()):
                label = labels.iloc[idx]
                features = []

                for feat_idx, col in enumerate(feature_cols, start=1):
                    value = row[col]
                    if pd.notna(value) and value != 0:
                        features.append(f"{feat_idx}:{value}")

                f.write(f"{label} {' '.join(features)}\n")

    def export_images(self, output_path: Path, apk_list: List[str] = None,
                     image_size: int = 224, image_method: str = 'raw') -> Dict[str, Path]:
        """
        Export APK bytecode as images for CNN

        Args:
            output_path: Output directory path
            apk_list: List of APK filenames to convert (None = all)
            image_size: Output image size (default: 224x224)
            image_method: Conversion method ('raw', 'rgb_channels', 'markov', 'histogram', 'entropy')

        Returns:
            Dictionary with output paths
        """
        from core.bytecode_to_image import BytecodeToImage

        output_dir = Path(output_path)
        output_dir.mkdir(parents=True, exist_ok=True)

        converter = BytecodeToImage(image_size=image_size)

        # Get APK paths
        from core.workspace_manager import WorkspaceManager
        workspace = WorkspaceManager(str(self.workspace_path))
        apks = workspace.get_all_apks()

        if apk_list:
            apks = [apk for apk in apks if apk['filename'] in apk_list]

        exported_count = 0
        for apk in apks:
            try:
                label = apk['label']
                label_dir = output_dir / label.lower()
                label_dir.mkdir(exist_ok=True)

                image_path = label_dir / f"{Path(apk['filename']).stem}.png"
                
                # Use appropriate conversion method
                if image_method == 'rgb_channels':
                    converter.convert_apk_to_rgb_channels(apk['path'], str(image_path))
                elif image_method == 'raw':
                    converter.convert_apk_to_image(apk['path'], str(image_path))
                else:
                    # For texture-based methods (markov, histogram, entropy)
                    converter.convert_bytecode_to_texture(apk['path'], str(image_path), method=image_method)
                
                exported_count += 1

            except Exception as e:
                print(f"✗ Error converting {apk['filename']}: {e}")

        print(f"✓ Exported {exported_count} APKs as images to {output_dir}")
        return {'images_dir': output_dir, 'count': exported_count}

    def export_sequences(self, output_path: Path, apk_list: List[str] = None,
                        sequence_type: str = 'api_calls') -> Dict[str, Path]:
        """
        Export APK sequences (API calls, opcodes) for RNN/LSTM

        Args:
            output_path: Output JSON file path
            apk_list: List of APK filenames (None = all)
            sequence_type: Type of sequence ('api_calls', 'opcodes', 'permissions')

        Returns:
            Dictionary with output path
        """
        import json
        from androguard.core.bytecodes.apk import APK
        from androguard.misc import AnalyzeAPK

        from core.workspace_manager import WorkspaceManager
        workspace = WorkspaceManager(str(self.workspace_path))
        apks = workspace.get_all_apks()

        if apk_list:
            apks = [apk for apk in apks if apk['filename'] in apk_list]

        sequences = []

        for apk_info in apks:
            try:
                if sequence_type == 'api_calls':
                    sequence = self._extract_api_sequence(apk_info['path'])
                elif sequence_type == 'opcodes':
                    sequence = self._extract_opcode_sequence(apk_info['path'])
                elif sequence_type == 'permissions':
                    sequence = self._extract_permission_sequence(apk_info['path'])
                else:
                    raise ValueError(f"Unknown sequence type: {sequence_type}")

                sequences.append({
                    'filename': apk_info['filename'],
                    'label': apk_info['label'],
                    'family': apk_info.get('family'),
                    'sequence': sequence
                })

            except Exception as e:
                print(f"✗ Error extracting sequence from {apk_info['filename']}: {e}")

        # Export to JSON
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sequences, f, indent=2)

        print(f"✓ Exported {len(sequences)} sequences to {output_path}")
        return {'sequences': output_path, 'count': len(sequences)}

    def _extract_api_sequence(self, apk_path: str) -> List[str]:
        """Extract API call sequence from APK"""
        from androguard.misc import AnalyzeAPK

        _, _, dx = AnalyzeAPK(apk_path)
        api_calls = []

        for method in dx.get_methods():
            method_name = f"{method.class_name}.{method.name}"
            api_calls.append(method_name)

        return api_calls[:1000]  # Limit to 1000 calls

    def _extract_opcode_sequence(self, apk_path: str) -> List[str]:
        """Extract opcode sequence from APK"""
        from androguard.misc import AnalyzeAPK

        _, _, dx = AnalyzeAPK(apk_path)
        opcodes = []

        for method in dx.get_methods():
            if method.is_external():
                continue

            for instruction in method.get_instructions():
                opcodes.append(instruction.get_name())

        return opcodes[:5000]  # Limit to 5000 opcodes

    def _extract_permission_sequence(self, apk_path: str) -> List[str]:
        """Extract permission sequence from APK"""
        from androguard.core.bytecodes.apk import APK

        apk = APK(apk_path)
        permissions = apk.get_permissions()

        return [p.split('.')[-1] for p in permissions]

    def get_export_statistics(self) -> Dict:
        """Get statistics about cached features"""
        if not self.db_path.exists():
            return {
                'total_samples': 0,
                'total_features': 0,
                'cache_size_mb': 0
            }

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Get sample count
        cursor.execute("SELECT COUNT(*) FROM features")
        total_samples = cursor.fetchone()[0]

        # Get feature count
        cursor.execute("PRAGMA table_info(features)")
        total_features = len(cursor.fetchall()) - 2  # Exclude filename and extraction_date

        conn.close()

        # Get cache size
        cache_size_mb = self.db_path.stat().st_size / (1024 * 1024)

        return {
            'total_samples': total_samples,
            'total_features': total_features,
            'cache_size_mb': cache_size_mb
        }
