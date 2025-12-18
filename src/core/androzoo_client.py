"""
AndroZoo API Client - Query APK metadata from AndroZoo database
"""
import hashlib
import csv
import gzip
import requests
from pathlib import Path
from typing import Dict, Optional, List
import pandas as pd
from datetime import datetime, timedelta


class AndroZooClient:
    """Client for querying AndroZoo APK metadata database"""

    API_BASE_URL = "https://androzoo.uni.lu/api"
    CSV_URL = "https://androzoo.uni.lu/lists/latest.csv.gz"

    def __init__(self, api_key: str, cache_dir: str = 'workspace/cache'):
        """
        Initialize AndroZoo client

        Args:
            api_key: AndroZoo API key
            cache_dir: Directory to cache CSV database
        """
        self.api_key = api_key
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.csv_cache_path = self.cache_dir / 'androzoo_latest.csv.gz'
        self.csv_index_path = self.cache_dir / 'androzoo_index.pkl'
        self.metadata_df = None

    def calculate_sha256(self, file_path: str) -> str:
        """
        Calculate SHA-256 hash of a file

        Args:
            file_path: Path to file

        Returns:
            SHA-256 hash as hex string
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest().upper()

    def download_csv_database(self, force_update: bool = False) -> bool:
        """
        Download AndroZoo CSV database (large file ~2.7GB compressed)

        Args:
            force_update: Force re-download even if cache exists

        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if cache exists and is recent (< 7 days old)
            if self.csv_cache_path.exists() and not force_update:
                age_days = (datetime.now() - datetime.fromtimestamp(
                    self.csv_cache_path.stat().st_mtime)).days
                if age_days < 7:
                    print(f"✓ Using cached CSV database ({age_days} days old)")
                    return True

            print("⚠ Downloading AndroZoo CSV database (~2.7GB compressed)...")
            print("  This may take several minutes depending on your connection...")

            # Download with progress
            response = requests.get(self.CSV_URL, stream=True)
            response.raise_for_status()

            total_size = int(response.headers.get('content-length', 0))
            block_size = 8192
            downloaded = 0

            with open(self.csv_cache_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=block_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            print(f"\r  Progress: {progress:.1f}%", end='', flush=True)

            print("\n✓ CSV database downloaded successfully")
            return True

        except Exception as e:
            print(f"✗ Error downloading CSV database: {e}")
            return False

    def load_csv_database(self, sample_size: Optional[int] = None) -> bool:
        """
        Load CSV database into memory (or build index)

        Args:
            sample_size: If specified, load only first N rows for testing

        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.csv_cache_path.exists():
                print("✗ CSV cache not found. Run download_csv_database() first.")
                return False

            print("⚠ Loading AndroZoo database into memory...")

            # CSV columns based on AndroZoo documentation
            columns = ['sha256', 'sha1', 'md5', 'dex_date', 'apk_size',
                      'dex_size', 'pkg_name', 'vercode', 'vt_detection',
                      'vt_scan_date', 'markets']

            # Load CSV (with optional sampling for testing)
            if sample_size:
                # Load only first N rows for testing
                self.metadata_df = pd.read_csv(
                    self.csv_cache_path,
                    compression='gzip',
                    names=columns,
                    nrows=sample_size,
                    on_bad_lines='skip'  # Skip malformed rows (like snaggamea)
                )
                print(f"✓ Loaded {len(self.metadata_df)} sample records")
            else:
                # Load full database
                self.metadata_df = pd.read_csv(
                    self.csv_cache_path,
                    compression='gzip',
                    names=columns,
                    on_bad_lines='skip'
                )
                print(f"✓ Loaded {len(self.metadata_df)} APK records")

            # Create SHA256 index for fast lookup
            self.metadata_df.set_index('sha256', inplace=True)

            return True

        except Exception as e:
            print(f"✗ Error loading CSV database: {e}")
            return False

    def query_by_hash(self, sha256_hash: str) -> Optional[Dict]:
        """
        Query APK metadata by SHA256 hash

        Args:
            sha256_hash: SHA256 hash of APK (case-insensitive)

        Returns:
            Dictionary with APK metadata, or None if not found
        """
        try:
            if self.metadata_df is None:
                print("✗ Database not loaded. Run load_csv_database() first.")
                return None

            # Normalize hash to uppercase
            sha256_hash = sha256_hash.upper()

            # Query dataframe
            if sha256_hash in self.metadata_df.index:
                record = self.metadata_df.loc[sha256_hash]

                # Convert to dictionary
                metadata = {
                    'sha256': sha256_hash,
                    'sha1': record.get('sha1', 'N/A'),
                    'md5': record.get('md5', 'N/A'),
                    'dex_date': record.get('dex_date', 'N/A'),
                    'apk_size': int(record.get('apk_size', 0)),
                    'dex_size': int(record.get('dex_size', 0)),
                    'pkg_name': record.get('pkg_name', 'N/A'),
                    'vercode': record.get('vercode', 'N/A'),
                    'vt_detection': int(record.get('vt_detection', 0)),
                    'vt_scan_date': record.get('vt_scan_date', 'N/A'),
                    'markets': record.get('markets', 'N/A')
                }

                return metadata
            else:
                return None

        except Exception as e:
            print(f"✗ Error querying hash: {e}")
            return None

    def query_apk_file(self, apk_path: str) -> Optional[Dict]:
        """
        Calculate hash and query metadata for an APK file

        Args:
            apk_path: Path to APK file

        Returns:
            Dictionary with APK metadata, or None if not found
        """
        try:
            # Calculate SHA256
            sha256_hash = self.calculate_sha256(apk_path)

            # Query database
            return self.query_by_hash(sha256_hash)

        except Exception as e:
            print(f"✗ Error querying APK file: {e}")
            return None

    def suggest_label(self, metadata: Dict, vt_threshold: int = 5) -> Dict:
        """
        Suggest label based on VirusTotal detection count

        Args:
            metadata: APK metadata dictionary
            vt_threshold: VT detection threshold for malware classification

        Returns:
            Dictionary with label suggestion and confidence
        """
        vt_detection = metadata.get('vt_detection', 0)

        if vt_detection >= vt_threshold:
            label = 'MALWARE'
            confidence = min(100, (vt_detection / 70) * 100)  # Max 70 VT engines
        elif vt_detection > 0:
            label = 'SUSPICIOUS'
            confidence = 50
        else:
            label = 'BENIGN'
            confidence = 80

        return {
            'suggested_label': label,
            'confidence': round(confidence, 1),
            'vt_detections': vt_detection,
            'reasoning': f"{vt_detection} VirusTotal engine(s) flagged this APK"
        }

    def batch_query(self, apk_files: List[str], vt_threshold: int = 5) -> List[Dict]:
        """
        Query multiple APK files and get label suggestions

        Args:
            apk_files: List of APK file paths
            vt_threshold: VT detection threshold

        Returns:
            List of results with metadata and label suggestions
        """
        results = []

        print(f"⚠ Querying {len(apk_files)} APKs from AndroZoo database...")

        for i, apk_path in enumerate(apk_files, 1):
            try:
                # Calculate hash
                sha256_hash = self.calculate_sha256(apk_path)

                # Query metadata
                metadata = self.query_by_hash(sha256_hash)

                if metadata:
                    # Get label suggestion
                    suggestion = self.suggest_label(metadata, vt_threshold)

                    result = {
                        'file_path': apk_path,
                        'file_name': Path(apk_path).name,
                        'sha256': sha256_hash,
                        'found': True,
                        'metadata': metadata,
                        'suggestion': suggestion
                    }
                else:
                    result = {
                        'file_path': apk_path,
                        'file_name': Path(apk_path).name,
                        'sha256': sha256_hash,
                        'found': False,
                        'metadata': None,
                        'suggestion': None
                    }

                results.append(result)

                if i % 100 == 0:
                    print(f"  Progress: {i}/{len(apk_files)} APKs processed")

            except Exception as e:
                print(f"✗ Error processing {Path(apk_path).name}: {e}")
                continue

        found_count = sum(1 for r in results if r['found'])
        print(f"✓ Found {found_count}/{len(apk_files)} APKs in AndroZoo database")

        return results

    def get_stats(self) -> Dict:
        """
        Get statistics about loaded database

        Returns:
            Dictionary with database statistics
        """
        if self.metadata_df is None:
            return {'loaded': False}

        stats = {
            'loaded': True,
            'total_apks': len(self.metadata_df),
            'cache_age_days': (datetime.now() - datetime.fromtimestamp(
                self.csv_cache_path.stat().st_mtime)).days if self.csv_cache_path.exists() else None,
            'cache_size_mb': self.csv_cache_path.stat().st_size / (1024 * 1024) if self.csv_cache_path.exists() else 0
        }

        return stats


# Example usage
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python androzoo_client.py <api_key> <apk_path>")
        sys.exit(1)

    api_key = sys.argv[1]
    apk_path = sys.argv[2]

    # Create client
    client = AndroZooClient(api_key)

    # Download and load database (use sample_size for testing)
    if not client.csv_cache_path.exists():
        print("Downloading CSV database...")
        client.download_csv_database()

    print("Loading database...")
    client.load_csv_database(sample_size=10000)  # Load only first 10k for testing

    # Query APK
    print(f"\nQuerying APK: {apk_path}")
    metadata = client.query_apk_file(apk_path)

    if metadata:
        print(f"\n✓ Found in AndroZoo:")
        print(f"  Package: {metadata['pkg_name']}")
        print(f"  VT Detection: {metadata['vt_detection']}")
        print(f"  Markets: {metadata['markets']}")

        # Get label suggestion
        suggestion = client.suggest_label(metadata)
        print(f"\n✓ Label Suggestion:")
        print(f"  Label: {suggestion['suggested_label']}")
        print(f"  Confidence: {suggestion['confidence']}%")
        print(f"  Reasoning: {suggestion['reasoning']}")
    else:
        print("✗ APK not found in AndroZoo database")
