#!/usr/bin/env python3
"""
PacketMaster Test Suite
Validates installation and basic functionality
"""

import os
import sys
import subprocess
import tempfile

def test_imports():
    """Test that all required modules can be imported"""
    print("🔍 Testing imports...")

    try:
        from packetmaster import PacketMaster
        print("✅ PacketMaster import successful")
    except ImportError as e:
        print(f"❌ PacketMaster import failed: {e}")
        return False

    try:
        import scapy
        print("✅ Scapy available")
    except ImportError:
        print("⚠️ Scapy not available - limited functionality")

    try:
        import sklearn
        print("✅ Scikit-learn available")
    except ImportError:
        print("⚠️ Scikit-learn not available - ML features disabled")

    return True

def test_basic_functionality():
    """Test basic PacketMaster functionality"""
    print("\n🔬 Testing basic functionality...")

    # Create a simple test PCAP using scapy (if available)
    try:
        from scapy.all import IP, TCP, Ether, wrpcap

        # Create a simple test packet
        packet = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=12345, dport=80)

        # Save to temporary file
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as tmp:
            tmp_pcap = tmp.name

        wrpcap(tmp_pcap, [packet])

        # Test PacketMaster analysis
        from packetmaster import PacketMaster
        analyzer = PacketMaster(tmp_pcap, {'enable_ml': False})
        analyzer.run_full_analysis()

        print("✅ Basic analysis successful")

        # Cleanup
        os.unlink(tmp_pcap)
        return True

    except Exception as e:
        print(f"❌ Basic functionality test failed: {e}")
        return False

def test_dashboard():
    """Test that dashboard can start (but don't keep it running)"""
    print("\n🌐 Testing dashboard startup...")

    try:
        # Just test import, don't actually start the server
        from dashboard import app
        print("✅ Dashboard import successful")
        return True
    except ImportError as e:
        print(f"❌ Dashboard import failed: {e}")
        return False

def test_automation():
    """Test automation module"""
    print("\n⚡ Testing automation module...")

    try:
        from automation import PacketMasterAutomation
        automation = PacketMasterAutomation()
        print("✅ Automation module loaded")
        return True
    except Exception as e:
        print(f"❌ Automation test failed: {e}")
        return False

def main():
    print("🚀 PacketMaster Test Suite")
    print("=" * 40)

    tests = [
        ("Imports", test_imports),
        ("Basic Functionality", test_basic_functionality),
        ("Dashboard", test_dashboard),
        ("Automation", test_automation)
    ]

    passed = 0
    total = len(tests)

    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                print(f"❌ {test_name} failed")
        except Exception as e:
            print(f"❌ {test_name} failed with exception: {e}")

    print("\n" + "=" * 40)
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! PacketMaster is ready to use.")
        return 0
    else:
        print("⚠️ Some tests failed. Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())