"""
Workspace management for APK organization
"""
from pathlib import Path
import shutil
from typing import Dict, List, Tuple
import json


class WorkspaceManager:
    """Manages APK organization in workspace"""

    def __init__(self, workspace_path='workspace'):
        self.workspace = Path(workspace_path)
        self.imported = self.workspace / 'imported'
        self.organized = self.workspace / 'organized'
        self.cache = self.workspace / 'cache'

        self.create_structure()

    def create_structure(self):
        """Create workspace directory structure"""
        # Main folders
        self.imported.mkdir(parents=True, exist_ok=True)
        self.organized.mkdir(parents=True, exist_ok=True)
        self.cache.mkdir(parents=True, exist_ok=True)

        # Organized subfolders
        (self.organized / 'malware').mkdir(exist_ok=True)
        (self.organized / 'benign' / 'verified').mkdir(parents=True, exist_ok=True)
        (self.organized / 'unlabeled').mkdir(exist_ok=True)

    def import_apk(self, apk_path: str) -> Path:
        """
        Import APK to workspace/imported/

        Args:
            apk_path: Source APK path

        Returns:
            Destination path in workspace
        """
        apk_path = Path(apk_path)
        dest = self.imported / apk_path.name

        # Avoid duplicates
        if dest.exists():
            # Add counter suffix
            counter = 1
            while dest.exists():
                stem = apk_path.stem
                suffix = apk_path.suffix
                dest = self.imported / f"{stem}_{counter}{suffix}"
                counter += 1

        shutil.copy2(apk_path, dest)
        return dest

    def organize_apk(self, apk_name: str, label: str, family: str = None) -> Path:
        """
        Move APK from imported to organized

        Args:
            apk_name: APK filename
            label: MALWARE, BENIGN, or UNLABELED
            family: Malware family (for MALWARE label)

        Returns:
            New path in organized folder
        """
        src = self.imported / apk_name

        if not src.exists():
            raise FileNotFoundError(f"APK not found in imported: {apk_name}")

        # Determine destination
        if label == 'MALWARE':
            if family and family != 'unknown':
                dest_dir = self.organized / 'malware' / family
            else:
                dest_dir = self.organized / 'malware' / 'unknown'
        elif label == 'BENIGN':
            dest_dir = self.organized / 'benign' / 'verified'
        else:  # UNLABELED
            dest_dir = self.organized / 'unlabeled'

        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / apk_name

        # Move file
        shutil.move(str(src), str(dest))
        return dest

    def get_apk_label(self, apk_name: str) -> Tuple[str, str]:
        """
        Get label and family of an APK based on its location

        Args:
            apk_name: APK filename

        Returns:
            (label, family) tuple
        """
        # Check in organized/malware/*
        malware_dir = self.organized / 'malware'
        if malware_dir.exists():
            for family_dir in malware_dir.iterdir():
                if family_dir.is_dir():
                    if (family_dir / apk_name).exists():
                        return ('MALWARE', family_dir.name)

        # Check in organized/benign
        benign_path = self.organized / 'benign' / 'verified' / apk_name
        if benign_path.exists():
            return ('BENIGN', None)

        # Check in organized/unlabeled
        unlabeled_path = self.organized / 'unlabeled' / apk_name
        if unlabeled_path.exists():
            return ('UNLABELED', None)

        # Check in imported (not yet organized)
        imported_path = self.imported / apk_name
        if imported_path.exists():
            return ('UNLABELED', None)

        return ('UNKNOWN', None)

    def get_organized_stats(self) -> Dict:
        """
        Get organization statistics

        Returns:
            Dictionary with counts
        """
        stats = {
            'imported': 0,
            'malware': 0,
            'benign': 0,
            'unlabeled': 0,
            'families': {}
        }

        # Count imported
        if self.imported.exists():
            stats['imported'] = len(list(self.imported.glob('*.apk')))

        # Count malware by family
        malware_dir = self.organized / 'malware'
        if malware_dir.exists():
            for family_dir in malware_dir.iterdir():
                if family_dir.is_dir():
                    count = len(list(family_dir.glob('*.apk')))
                    if count > 0:
                        stats['malware'] += count
                        stats['families'][family_dir.name] = count

        # Count benign
        benign_dir = self.organized / 'benign'
        if benign_dir.exists():
            stats['benign'] = len(list(benign_dir.rglob('*.apk')))

        # Count unlabeled
        unlabeled_dir = self.organized / 'unlabeled'
        if unlabeled_dir.exists():
            stats['unlabeled'] = len(list(unlabeled_dir.glob('*.apk')))

        return stats

    def get_all_apks(self) -> List[Dict]:
        """
        Get list of all APKs with their labels

        Returns:
            List of dicts with APK info
        """
        apks = []

        # Scan all locations
        locations = [
            (self.imported, 'UNLABELED', None),
            (self.organized / 'benign', 'BENIGN', None),
            (self.organized / 'unlabeled', 'UNLABELED', None),
        ]

        for location, label, family in locations:
            if location.exists():
                for apk_file in location.rglob('*.apk'):
                    apks.append({
                        'filename': apk_file.name,
                        'path': str(apk_file),
                        'label': label,
                        'family': family,
                        'size_mb': apk_file.stat().st_size / (1024 * 1024)
                    })

        # Scan malware families
        malware_dir = self.organized / 'malware'
        if malware_dir.exists():
            for family_dir in malware_dir.iterdir():
                if family_dir.is_dir():
                    for apk_file in family_dir.glob('*.apk'):
                        apks.append({
                            'filename': apk_file.name,
                            'path': str(apk_file),
                            'label': 'MALWARE',
                            'family': family_dir.name,
                            'size_mb': apk_file.stat().st_size / (1024 * 1024)
                        })

        return apks

    def save_state(self):
        """Save workspace state to JSON"""
        state = {
            'stats': self.get_organized_stats(),
            'apks': self.get_all_apks()
        }

        state_file = self.cache / 'workspace_state.json'
        with open(state_file, 'w') as f:
            json.dump(state, f, indent=2)
