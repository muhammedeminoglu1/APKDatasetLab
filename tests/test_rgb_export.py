"""
Test script for RGB channel image export feature

This script tests the new convert_apk_to_rgb_channels method
"""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from core.bytecode_to_image import BytecodeToImage
from PIL import Image
import numpy as np


def test_rgb_conversion(apk_path: str, output_dir: str = './test_output'):
    """
    Test RGB channel conversion
    
    Args:
        apk_path: Path to test APK file
        output_dir: Output directory for test images
    """
    print("=" * 60)
    print("RGB Channel Image Export Test")
    print("=" * 60)
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Test with 224x224 image
    print("\n1. Testing with 224x224 image...")
    converter = BytecodeToImage(image_size=224)
    
    output_path = output_dir / "test_rgb_224.png"
    
    try:
        image = converter.convert_apk_to_rgb_channels(apk_path, str(output_path))
        print(f"   ✓ Image created: {output_path}")
        print(f"   ✓ Image mode: {image.mode}")
        print(f"   ✓ Image size: {image.size}")
        
        # Verify it's RGB
        assert image.mode == 'RGB', "Image should be RGB mode"
        assert image.size == (224, 224), "Image should be 224x224"
        
        # Analyze channels
        img_array = np.array(image)
        r_channel = img_array[:, :, 0]
        g_channel = img_array[:, :, 1]
        b_channel = img_array[:, :, 2]
        
        print(f"\n2. Channel Analysis:")
        print(f"   Red Channel (APK bytes):")
        print(f"     - Mean: {r_channel.mean():.2f}")
        print(f"     - Std: {r_channel.std():.2f}")
        print(f"     - Min: {r_channel.min()}, Max: {r_channel.max()}")
        
        print(f"   Green Channel (DEX bytecode):")
        print(f"     - Mean: {g_channel.mean():.2f}")
        print(f"     - Std: {g_channel.std():.2f}")
        print(f"     - Min: {g_channel.min()}, Max: {g_channel.max()}")
        
        print(f"   Blue Channel (Manifest):")
        print(f"     - Mean: {b_channel.mean():.2f}")
        print(f"     - Std: {b_channel.std():.2f}")
        print(f"     - Min: {b_channel.min()}, Max: {b_channel.max()}")
        
        # Check that channels are different
        r_vs_g = np.sum(r_channel != g_channel)
        r_vs_b = np.sum(r_channel != b_channel)
        g_vs_b = np.sum(g_channel != b_channel)
        
        print(f"\n3. Channel Difference Check:")
        print(f"   Red vs Green different pixels: {r_vs_g} / {224*224}")
        print(f"   Red vs Blue different pixels: {r_vs_b} / {224*224}")
        print(f"   Green vs Blue different pixels: {g_vs_b} / {224*224}")
        
        if r_vs_g > 0 and r_vs_b > 0 and g_vs_b > 0:
            print(f"   ✓ All channels contain different data")
        else:
            print(f"   ⚠ Warning: Some channels may contain identical data")
        
        print("\n" + "=" * 60)
        print("✓ TEST PASSED")
        print("=" * 60)
        
        return True
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_rgb_export.py <path_to_apk_file>")
        print("\nExample:")
        print("  python test_rgb_export.py workspace/malware/sample.apk")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    
    if not Path(apk_path).exists():
        print(f"Error: APK file not found: {apk_path}")
        sys.exit(1)
    
    success = test_rgb_conversion(apk_path)
    sys.exit(0 if success else 1)
