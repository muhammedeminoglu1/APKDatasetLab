"""
Bytecode to Image Converter - Convert APK bytecode to images for CNN
"""
import numpy as np
from PIL import Image
from pathlib import Path
from typing import Tuple
import struct


class BytecodeToImage:
    """Convert APK bytecode to grayscale/RGB images for CNN training"""

    def __init__(self, image_size: int = 224, mode: str = 'L'):
        """
        Initialize converter

        Args:
            image_size: Output image size (width = height)
            mode: Image mode ('L' for grayscale, 'RGB' for color)
        """
        self.image_size = image_size
        self.mode = mode

    def convert_apk_to_image(self, apk_path: str, output_path: str = None) -> Image.Image:
        """
        Convert APK to image

        Args:
            apk_path: Path to APK file
            output_path: Output image path (optional)

        Returns:
            PIL Image object
        """
        try:
            # Extract bytecode from APK
            bytecode = self._extract_bytecode(apk_path)

            # Convert to image
            image = self._bytecode_to_image(bytecode)

            # Save if output path provided
            if output_path:
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                image.save(output_path)
                print(f"✓ Converted {Path(apk_path).name} to image: {output_path}")

            return image

        except Exception as e:
            print(f"✗ Error converting {apk_path} to image: {e}")
            raise

    def _extract_bytecode(self, apk_path: str) -> bytes:
        """
        Extract DEX bytecode from APK

        Args:
            apk_path: Path to APK file

        Returns:
            Bytecode as bytes
        """
        from androguard.core.bytecodes.apk import APK

        # Get DEX files from APK
        apk = APK(apk_path)
        
        try:
            dex_files = apk.get_all_dex()
            
            # Combine all DEX bytecode
            all_bytecode = b''
            
            # Handle different return formats from get_all_dex()
            if dex_files:
                # Try to iterate - format varies by androguard version
                try:
                    for item in dex_files:
                        # Newer versions return (name, data) tuples
                        if isinstance(item, tuple) and len(item) == 2:
                            dex_name, dex_data = item
                            all_bytecode += dex_data
                        # Some versions return just bytes
                        elif isinstance(item, bytes):
                            all_bytecode += item
                        # Some versions return dict-like objects
                        else:
                            all_bytecode += bytes(item)
                except TypeError:
                    # If not iterable, treat as single bytes object
                    if isinstance(dex_files, bytes):
                        all_bytecode = dex_files
            
            # If no DEX found, use raw APK bytes
            if not all_bytecode:
                with open(apk_path, 'rb') as f:
                    all_bytecode = f.read()
                    
        except Exception as e:
            # Fallback: use raw APK bytes
            with open(apk_path, 'rb') as f:
                all_bytecode = f.read()

        return all_bytecode

    def _bytecode_to_image(self, bytecode: bytes) -> Image.Image:
        """
        Convert bytecode to image

        Args:
            bytecode: Raw bytecode

        Returns:
            PIL Image object
        """
        # Calculate required pixels
        total_pixels = self.image_size * self.image_size

        if self.mode == 'RGB':
            # Each pixel needs 3 bytes (R, G, B)
            required_bytes = total_pixels * 3
        else:
            # Grayscale: 1 byte per pixel
            required_bytes = total_pixels

        # Convert bytecode to numpy array
        byte_array = np.frombuffer(bytecode[:required_bytes], dtype=np.uint8)

        # Pad if necessary
        if len(byte_array) < required_bytes:
            byte_array = np.pad(byte_array, (0, required_bytes - len(byte_array)),
                               mode='constant', constant_values=0)

        # Reshape to image dimensions
        if self.mode == 'RGB':
            # Reshape to (height, width, 3)
            img_array = byte_array.reshape((self.image_size, self.image_size, 3))
        else:
            # Reshape to (height, width)
            img_array = byte_array.reshape((self.image_size, self.image_size))

        # Create PIL Image
        image = Image.fromarray(img_array, mode=self.mode)

        return image

    def convert_apk_to_rgb_channels(self, apk_path: str, output_path: str = None) -> Image.Image:
        """
        Convert APK to RGB image where each channel represents different data:
        - Red Channel: Raw APK bytes
        - Green Channel: DEX bytecode
        - Blue Channel: AndroidManifest.xml content

        Args:
            apk_path: Path to APK file
            output_path: Output image path (optional)

        Returns:
            PIL Image object (RGB mode)
        """
        try:
            from androguard.core.bytecodes.apk import APK
            import zipfile

            # Calculate bytes needed per channel
            bytes_per_channel = self.image_size * self.image_size

            # Extract Red Channel: Raw APK bytes
            with open(apk_path, 'rb') as f:
                apk_bytes = f.read(bytes_per_channel)
            
            red_channel = np.frombuffer(apk_bytes, dtype=np.uint8)
            if len(red_channel) < bytes_per_channel:
                red_channel = np.pad(red_channel, (0, bytes_per_channel - len(red_channel)),
                                   mode='constant', constant_values=0)
            else:
                red_channel = red_channel[:bytes_per_channel]

            # Extract Green Channel: DEX bytecode
            dex_bytecode = self._extract_bytecode(apk_path)
            green_channel = np.frombuffer(dex_bytecode[:bytes_per_channel], dtype=np.uint8)
            if len(green_channel) < bytes_per_channel:
                green_channel = np.pad(green_channel, (0, bytes_per_channel - len(green_channel)),
                                     mode='constant', constant_values=0)
            else:
                green_channel = green_channel[:bytes_per_channel]

            # Extract Blue Channel: AndroidManifest.xml
            try:
                apk = APK(apk_path)
                manifest_bytes = apk.get_android_manifest_xml().encode('utf-8')
            except:
                # If manifest extraction fails, try zip extraction
                try:
                    with zipfile.ZipFile(apk_path, 'r') as zf:
                        manifest_bytes = zf.read('AndroidManifest.xml')
                except:
                    # If all else fails, use zeros
                    manifest_bytes = b''

            blue_channel = np.frombuffer(manifest_bytes[:bytes_per_channel], dtype=np.uint8)
            if len(blue_channel) < bytes_per_channel:
                blue_channel = np.pad(blue_channel, (0, bytes_per_channel - len(blue_channel)),
                                    mode='constant', constant_values=0)
            else:
                blue_channel = blue_channel[:bytes_per_channel]

            # Reshape each channel to image dimensions
            red_channel = red_channel.reshape((self.image_size, self.image_size))
            green_channel = green_channel.reshape((self.image_size, self.image_size))
            blue_channel = blue_channel.reshape((self.image_size, self.image_size))

            # Stack channels to create RGB image
            rgb_array = np.stack([red_channel, green_channel, blue_channel], axis=2)

            # Create PIL Image
            image = Image.fromarray(rgb_array, mode='RGB')

            # Save if output path provided
            if output_path:
                output_path = Path(output_path)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                image.save(output_path)
                print(f"✓ Converted {Path(apk_path).name} to RGB image: {output_path}")

            return image

        except Exception as e:
            print(f"✗ Error converting {apk_path} to RGB image: {e}")
            raise

    def convert_bytecode_to_texture(self, apk_path: str, output_path: str = None,
                                   method: str = 'markov') -> Image.Image:
        """
        Convert bytecode using texture-based methods (Markov, GIST, etc.)

        Args:
            apk_path: Path to APK file
            output_path: Output image path
            method: Conversion method ('markov', 'histogram', 'entropy')

        Returns:
            PIL Image object
        """
        bytecode = self._extract_bytecode(apk_path)

        if method == 'markov':
            image = self._markov_image(bytecode)
        elif method == 'histogram':
            image = self._histogram_image(bytecode)
        elif method == 'entropy':
            image = self._entropy_image(bytecode)
        else:
            raise ValueError(f"Unknown method: {method}")

        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            image.save(output_path)

        return image

    def _markov_image(self, bytecode: bytes) -> Image.Image:
        """
        Create Markov transition matrix image

        Each pixel (i, j) represents the transition probability from byte i to byte j
        """
        # Create 256x256 transition matrix
        matrix = np.zeros((256, 256), dtype=np.uint32)

        # Count transitions
        for i in range(len(bytecode) - 1):
            curr_byte = bytecode[i]
            next_byte = bytecode[i + 1]
            matrix[curr_byte, next_byte] += 1

        # Normalize to 0-255 range
        if matrix.max() > 0:
            matrix = (matrix / matrix.max() * 255).astype(np.uint8)
        else:
            matrix = matrix.astype(np.uint8)

        # Create image
        image = Image.fromarray(matrix, mode='L')

        # Resize to target size
        if self.image_size != 256:
            image = image.resize((self.image_size, self.image_size), Image.LANCZOS)

        return image

    def _histogram_image(self, bytecode: bytes) -> Image.Image:
        """
        Create histogram-based visualization
        """
        # Calculate byte value histogram
        hist, _ = np.histogram(np.frombuffer(bytecode, dtype=np.uint8),
                              bins=256, range=(0, 256))

        # Normalize
        hist = (hist / hist.max() * 255).astype(np.uint8) if hist.max() > 0 else hist.astype(np.uint8)

        # Create 2D image from histogram
        # Tile the histogram to create square image
        tiles_per_row = self.image_size // 256
        if tiles_per_row == 0:
            tiles_per_row = 1

        # Repeat histogram to fill image
        img_array = np.tile(hist, (self.image_size, tiles_per_row))[:, :self.image_size]

        image = Image.fromarray(img_array, mode='L')
        return image

    def _entropy_image(self, bytecode: bytes) -> Image.Image:
        """
        Create entropy-based visualization using sliding window
        """
        window_size = 256
        stride = window_size // 2

        # Calculate entropy for sliding windows
        entropies = []
        for i in range(0, len(bytecode) - window_size, stride):
            window = bytecode[i:i + window_size]
            entropy = self._calculate_entropy(window)
            entropies.append(entropy)

        # Convert to image
        total_pixels = self.image_size * self.image_size
        entropies = np.array(entropies)

        # Pad or truncate
        if len(entropies) < total_pixels:
            entropies = np.pad(entropies, (0, total_pixels - len(entropies)),
                             mode='constant', constant_values=0)
        else:
            entropies = entropies[:total_pixels]

        # Normalize to 0-255
        if entropies.max() > 0:
            entropies = (entropies / entropies.max() * 255).astype(np.uint8)
        else:
            entropies = entropies.astype(np.uint8)

        # Reshape to image
        img_array = entropies.reshape((self.image_size, self.image_size))

        image = Image.fromarray(img_array, mode='L')
        return image

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte sequence"""
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)

        # Calculate entropy
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))

        return entropy

    def batch_convert(self, apk_dir: str, output_dir: str, method: str = 'raw') -> int:
        """
        Batch convert APKs to images

        Args:
            apk_dir: Directory containing APK files
            output_dir: Output directory for images
            method: Conversion method ('raw', 'markov', 'histogram', 'entropy')

        Returns:
            Number of successfully converted APKs
        """
        apk_dir = Path(apk_dir)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        apk_files = list(apk_dir.rglob('*.apk'))
        converted_count = 0

        for apk_file in apk_files:
            try:
                # Create output path
                output_path = output_dir / f"{apk_file.stem}.png"

                # Convert
                if method == 'raw':
                    self.convert_apk_to_image(str(apk_file), str(output_path))
                else:
                    self.convert_bytecode_to_texture(str(apk_file), str(output_path), method=method)

                converted_count += 1

            except Exception as e:
                print(f"✗ Error converting {apk_file.name}: {e}")

        print(f"✓ Batch conversion complete: {converted_count}/{len(apk_files)} APKs")
        return converted_count


if __name__ == "__main__":
    # Example usage
    import sys

    if len(sys.argv) < 3:
        print("Usage: python bytecode_to_image.py <apk_path> <output_path> [method] [size]")
        print("Methods: raw, markov, histogram, entropy")
        sys.exit(1)

    apk_path = sys.argv[1]
    output_path = sys.argv[2]
    method = sys.argv[3] if len(sys.argv) > 3 else 'raw'
    size = int(sys.argv[4]) if len(sys.argv) > 4 else 224

    converter = BytecodeToImage(image_size=size)

    if method == 'raw':
        converter.convert_apk_to_image(apk_path, output_path)
    else:
        converter.convert_bytecode_to_texture(apk_path, output_path, method=method)

    print(f"✓ Conversion complete: {output_path}")
