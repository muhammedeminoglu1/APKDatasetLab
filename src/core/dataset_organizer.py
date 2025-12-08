"""
Dataset Organizer - Organize APKs by classification and family
"""
import shutil
from pathlib import Path
from typing import Dict, List
import json


class DatasetOrganizer:
    """Organize APKs into structured folders"""

    def __init__(self, output_root: str):
        """
        Initialize dataset organizer

        Args:
            output_root: Root directory for organized dataset
        """
        self.output_root = Path(output_root)
        self.stats = {
            'benign': 0,
            'malware': {},
            'suspicious': 0,
            'unknown': 0
        }

    def create_folder_structure(self):
        """Create organized folder structure"""
        self.output_root.mkdir(parents=True, exist_ok=True)

        # Create main categories
        (self.output_root / "benign").mkdir(exist_ok=True)
        (self.output_root / "malware").mkdir(exist_ok=True)
        (self.output_root / "suspicious").mkdir(exist_ok=True)
        (self.output_root / "unknown").mkdir(exist_ok=True)

    def create_malware_family_folder(self, family: str) -> Path:
        """
        Create folder for specific malware family

        Args:
            family: Malware family name

        Returns:
            Path to family folder
        """
        family_path = self.output_root / "malware" / family
        family_path.mkdir(parents=True, exist_ok=True)
        return family_path

    def organize_apk(self, apk_path: str, label: str, family: str = "unknown") -> Path:
        """
        Copy APK to appropriate folder based on classification

        Args:
            apk_path: Source APK path
            label: Classification label (BENIGN/MALWARE/SUSPICIOUS/UNKNOWN)
            family: Malware family (for MALWARE label)

        Returns:
            Destination path
        """
        apk_path = Path(apk_path)
        filename = apk_path.name

        # Determine destination
        if label == "BENIGN":
            dest_folder = self.output_root / "benign"
            self.stats['benign'] += 1
        elif label == "MALWARE":
            dest_folder = self.create_malware_family_folder(family)
            self.stats['malware'][family] = self.stats['malware'].get(family, 0) + 1
        elif label == "SUSPICIOUS":
            dest_folder = self.output_root / "suspicious"
            self.stats['suspicious'] += 1
        else:
            dest_folder = self.output_root / "unknown"
            self.stats['unknown'] += 1

        # Copy file
        dest_path = dest_folder / filename

        # Handle duplicates
        counter = 1
        while dest_path.exists():
            dest_path = dest_folder / f"{apk_path.stem}_{counter}{apk_path.suffix}"
            counter += 1

        shutil.copy2(apk_path, dest_path)
        return dest_path

    def save_metadata(self, apk_metadata: List[Dict]):
        """
        Save metadata JSON file

        Args:
            apk_metadata: List of APK metadata dictionaries
        """
        metadata_path = self.output_root / "dataset_metadata.json"

        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump({
                'statistics': self.stats,
                'total_files': len(apk_metadata),
                'files': apk_metadata
            }, f, indent=2)

    def generate_report(self) -> str:
        """
        Generate organization report

        Returns:
            Report text
        """
        total = (self.stats['benign'] +
                sum(self.stats['malware'].values()) +
                self.stats['suspicious'] +
                self.stats['unknown'])

        report = "Dataset Organization Report\n"
        report += "=" * 50 + "\n\n"
        report += f"Total APKs: {total}\n\n"

        report += f"Benign: {self.stats['benign']} "
        report += f"({self.stats['benign']/total*100:.1f}%)\n"

        malware_total = sum(self.stats['malware'].values())
        report += f"Malware: {malware_total} "
        report += f"({malware_total/total*100:.1f}%)\n"

        if self.stats['malware']:
            report += "\n  Families:\n"
            for family, count in sorted(self.stats['malware'].items(),
                                       key=lambda x: x[1], reverse=True):
                report += f"    - {family}: {count}\n"

        if self.stats['suspicious'] > 0:
            report += f"\nSuspicious: {self.stats['suspicious']} "
            report += f"({self.stats['suspicious']/total*100:.1f}%)\n"

        if self.stats['unknown'] > 0:
            report += f"Unknown: {self.stats['unknown']} "
            report += f"({self.stats['unknown']/total*100:.1f}%)\n"

        return report

    def get_statistics(self) -> Dict:
        """Get organization statistics"""
        return self.stats.copy()
