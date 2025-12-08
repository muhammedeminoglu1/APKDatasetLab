"""
VirusTotal Scanner - Scan APKs and get malware family information
"""
import requests
import time
import hashlib
from typing import Dict, Optional, Tuple
from pathlib import Path
import json


class VirusTotalScanner:
    """VirusTotal API integration with rate limiting"""

    API_BASE_URL = "https://www.virustotal.com/api/v3"

    # Free tier rate limits
    REQUESTS_PER_MINUTE = 4
    DELAY_BETWEEN_REQUESTS = 60 / REQUESTS_PER_MINUTE  # 15 seconds

    def __init__(self, api_key: str):
        """
        Initialize VirusTotal scanner

        Args:
            api_key: VirusTotal API key
        """
        self.api_key = api_key
        self.headers = {
            "x-apikey": api_key
        }
        self.last_request_time = 0
        self.request_count = 0

    def _wait_for_rate_limit(self):
        """Wait if necessary to respect rate limits"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time

        if time_since_last_request < self.DELAY_BETWEEN_REQUESTS:
            wait_time = self.DELAY_BETWEEN_REQUESTS - time_since_last_request
            print(f"Rate limit: Waiting {wait_time:.1f} seconds...")
            time.sleep(wait_time)

        self.last_request_time = time.time()
        self.request_count += 1

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def scan_file(self, file_path: str) -> Optional[Dict]:
        """
        Scan file with VirusTotal

        Args:
            file_path: Path to APK file

        Returns:
            Scan results dictionary or None if error
        """
        self._wait_for_rate_limit()

        try:
            # First, check if file already scanned by hash
            file_hash = self.calculate_file_hash(file_path)
            existing_report = self.get_file_report(file_hash)

            if existing_report:
                print(f"File already scanned, retrieving existing report...")
                return existing_report

            # Upload file for scanning
            print(f"Uploading file to VirusTotal...")
            url = f"{self.API_BASE_URL}/files"

            with open(file_path, 'rb') as f:
                files = {"file": (Path(file_path).name, f)}
                response = requests.post(url, headers=self.headers, files=files)

            if response.status_code == 200:
                result = response.json()
                analysis_id = result['data']['id']

                # Wait for analysis to complete
                print(f"Waiting for analysis to complete...")
                time.sleep(30)  # Wait before checking results

                return self.get_analysis_results(analysis_id)
            else:
                print(f"Upload failed: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            print(f"Error scanning file: {e}")
            return None

    def get_file_report(self, file_hash: str) -> Optional[Dict]:
        """
        Get existing file report by hash

        Args:
            file_hash: SHA-256 hash of file

        Returns:
            Report dictionary or None if not found
        """
        self._wait_for_rate_limit()

        try:
            url = f"{self.API_BASE_URL}/files/{file_hash}"
            response = requests.get(url, headers=self.headers)

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                print(f"Error getting report: {response.status_code}")
                return None

        except Exception as e:
            print(f"Error getting file report: {e}")
            return None

    def get_analysis_results(self, analysis_id: str) -> Optional[Dict]:
        """
        Get analysis results by ID

        Args:
            analysis_id: Analysis ID from upload

        Returns:
            Analysis results or None
        """
        self._wait_for_rate_limit()

        try:
            url = f"{self.API_BASE_URL}/analyses/{analysis_id}"
            response = requests.get(url, headers=self.headers)

            if response.status_code == 200:
                return response.json()
            else:
                print(f"Error getting analysis: {response.status_code}")
                return None

        except Exception as e:
            print(f"Error getting analysis results: {e}")
            return None

    def parse_scan_results(self, scan_data: Dict) -> Tuple[str, str, int, int]:
        """
        Parse scan results to extract classification info

        Args:
            scan_data: Raw scan data from VirusTotal

        Returns:
            Tuple of (label, family, detections, total_engines)
        """
        try:
            if not scan_data or 'data' not in scan_data:
                return "UNKNOWN", "unknown", 0, 0

            attributes = scan_data['data']['attributes']
            stats = attributes.get('last_analysis_stats', {})

            malicious = stats.get('malicious', 0)
            total = sum(stats.values())

            # Determine label
            if malicious > 3:  # If more than 3 engines detect as malicious
                label = "MALWARE"
            elif malicious == 0:
                label = "BENIGN"
            else:
                label = "SUSPICIOUS"

            # Extract malware family
            family = "unknown"
            results = attributes.get('last_analysis_results', {})

            # Collect suggested threat labels
            suggested_labels = []
            for engine, result in results.items():
                if result.get('category') == 'malicious':
                    detected_name = result.get('result', '')
                    if detected_name:
                        suggested_labels.append(detected_name)

            # Try to extract family from most common detection
            if suggested_labels:
                # Simple heuristic: take the most common family name
                family = self._extract_family_name(suggested_labels)

            return label, family, malicious, total

        except Exception as e:
            print(f"Error parsing scan results: {e}")
            return "UNKNOWN", "unknown", 0, 0

    def _extract_family_name(self, detection_names: list) -> str:
        """
        Extract malware family from detection names

        Args:
            detection_names: List of detection names from different engines

        Returns:
            Extracted family name
        """
        # Common malware families
        families = [
            'trojan', 'adware', 'ransomware', 'spyware', 'backdoor',
            'banker', 'dropper', 'downloader', 'rootkit', 'worm',
            'fakeinst', 'smsreg', 'agent', 'generic', 'suspicious'
        ]

        # Count occurrences
        family_counts = {}
        for name in detection_names:
            name_lower = name.lower()
            for family in families:
                if family in name_lower:
                    family_counts[family] = family_counts.get(family, 0) + 1

        # Return most common family
        if family_counts:
            return max(family_counts.items(), key=lambda x: x[1])[0]

        return "unknown"

    def get_request_count(self) -> int:
        """Get number of requests made in current session"""
        return self.request_count

    def estimate_time_remaining(self, files_remaining: int) -> float:
        """
        Estimate time to scan remaining files

        Args:
            files_remaining: Number of files left to scan

        Returns:
            Estimated time in seconds
        """
        return files_remaining * self.DELAY_BETWEEN_REQUESTS
