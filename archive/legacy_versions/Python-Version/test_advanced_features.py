"""
Advanced Features Test Suite
Tests ML Detection, TPM Integration, and Memory Dump
"""

import os
import sys
import tempfile
import logging

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def test_ml_detection():
    """Test ML detection layer"""
    print("\n" + "="*70)
    print("TEST 1: ML/AI DETECTION LAYER")
    print("="*70)
    
    try:
        from ml_detector import MLRansomwareDetector, FeatureExtractor
        import numpy as np
        
        # Test feature extraction
        print("\n[1/3] Testing Feature Extraction...")
        extractor = FeatureExtractor()
        
        test_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
        test_file.write(b"Test content for feature extraction")
        test_file.close()
        
        features = extractor.extract_all_features(file_path=test_file.name)
        os.unlink(test_file.name)
        
        assert len(features) == len(extractor.feature_names)
        print(f"  ✓ Extracted {len(features)} features successfully")
        
        # Test detector
        print("\n[2/3] Testing ML Detector...")
        detector = MLRansomwareDetector()
        
        # Test with synthetic data
        from train_ml_model import DatasetGenerator
        generator = DatasetGenerator()
        
        print("\n[3/3] Testing Model Training...")
        samples, labels = generator.generate_dataset(100, 100)
        
        success = detector.train(samples, labels)
        assert success, "Training failed"
        print("  ✓ Model trained successfully")
        
        # Test prediction
        is_malware, confidence = detector.predict(
            behavior_data={'files_modified': 150, 'crypto_api_calls': 80}
        )
        print(f"  ✓ Prediction: Ransomware={is_malware}, Confidence={confidence:.1%}")
        
        print("\n✅ ML DETECTION LAYER: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ ML DETECTION LAYER: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_tpm_integration():
    """Test TPM integration"""
    print("\n" + "="*70)
    print("TEST 2: TPM INTEGRATION")
    print("="*70)
    
    try:
        from tpm_integration import TPMManager, TPMKeyManager
        
        print("\n[1/4] Initializing TPM...")
        tpm = TPMManager()
        
        if not tpm.is_available():
            print("  ⚠ TPM not available, using software fallback")
        else:
            print(f"  ✓ TPM initialized: {tpm.get_tpm_version()}")
        
        # Test sealing
        print("\n[2/4] Testing Data Sealing...")
        test_data = b"Sensitive encryption key data"
        sealed = tpm.seal_data(test_data, pcr_selection=[0])
        
        assert sealed is not None
        print(f"  ✓ Data sealed ({len(sealed)} bytes)")
        
        # Test unsealing
        print("\n[3/4] Testing Data Unsealing...")
        unsealed = tpm.unseal_data(sealed)
        
        assert unsealed == test_data
        print("  ✓ Data unsealed successfully")
        
        # Test key manager
        print("\n[4/4] Testing Key Manager...")
        key_mgr = TPMKeyManager(tpm)
        
        test_key = os.urandom(32)
        success = key_mgr.store_encryption_key(test_key, "test_key")
        assert success
        print("  ✓ Key stored in TPM")
        
        retrieved = key_mgr.retrieve_encryption_key("test_key")
        assert retrieved == test_key
        print("  ✓ Key retrieved successfully")
        
        tpm.cleanup()
        
        print("\n✅ TPM INTEGRATION: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ TPM INTEGRATION: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_memory_dump():
    """Test full memory dump"""
    print("\n" + "="*70)
    print("TEST 3: FULL MEMORY DUMP")
    print("="*70)
    
    try:
        from memory_dump import MemoryDumper
        
        print("\n[1/4] Initializing Memory Dumper...")
        dumper = MemoryDumper()
        print("  ✓ Dumper initialized")
        
        # Test with current process
        current_pid = os.getpid()
        
        # Test region enumeration
        print(f"\n[2/4] Enumerating Memory Regions (PID {current_pid})...")
        regions = dumper.enumerate_memory_regions(current_pid)
        
        assert len(regions) > 0
        print(f"  ✓ Found {len(regions)} memory regions")
        
        # Test mini dump
        print(f"\n[3/4] Creating Mini Dump (PID {current_pid})...")
        dump_path = dumper.create_minidump(current_pid, dump_type='mini')
        
        assert dump_path is not None
        assert os.path.exists(dump_path)
        
        file_size = os.path.getsize(dump_path) / 1024
        print(f"  ✓ Dump created: {file_size:.1f} KB")
        
        # Test analysis
        print("\n[4/4] Analyzing Dump...")
        analysis = dumper.analyze_dump(dump_path)
        
        assert 'file_size' in analysis
        print(f"  ✓ Analysis complete: {len(analysis['strings_found'])} strings found")
        
        print("\n✅ FULL MEMORY DUMP: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ FULL MEMORY DUMP: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def test_integration():
    """Test integration of all features"""
    print("\n" + "="*70)
    print("TEST 4: SYSTEM INTEGRATION")
    print("="*70)
    
    try:
        print("\n[1/3] Testing Main System Import...")
        from main import AntiRansomwareManager
        print("  ✓ Main system imported")
        
        print("\n[2/3] Testing Config Loading...")
        manager = AntiRansomwareManager(config_path='config.yaml')
        
        # Check config has advanced features
        assert 'advanced' in manager.config
        print("  ✓ Configuration loaded with advanced features")
        
        print("\n[3/3] Testing Component Availability...")
        
        # Check ML
        try:
            from ml_detector import MLRansomwareDetector
            print("  ✓ ML Detector available")
        except:
            print("  ⚠ ML Detector not available")
        
        # Check TPM
        try:
            from tpm_integration import TPMManager
            print("  ✓ TPM Integration available")
        except:
            print("  ⚠ TPM Integration not available")
        
        # Check Memory Dump
        try:
            from memory_dump import MemoryDumper
            print("  ✓ Memory Dumper available")
        except:
            print("  ⚠ Memory Dumper not available")
        
        print("\n✅ SYSTEM INTEGRATION: PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ SYSTEM INTEGRATION: FAILED - {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run all tests"""
    print("\n" + "#"*70)
    print("# ADVANCED FEATURES TEST SUITE")
    print("#"*70)
    
    results = {
        'ML Detection': test_ml_detection(),
        'TPM Integration': test_tpm_integration(),
        'Memory Dump': test_memory_dump(),
        'System Integration': test_integration()
    }
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    
    for test_name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name:25s} {status}")
    
    total = len(results)
    passed = sum(results.values())
    
    print("\n" + "="*70)
    print(f"TOTAL: {passed}/{total} tests passed ({passed/total*100:.0f}%)")
    print("="*70)
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED! Advanced features are fully operational.")
        return 0
    else:
        print(f"\n⚠ {total-passed} test(s) failed. Please review errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
