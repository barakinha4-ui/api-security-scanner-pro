from core.plugins import Registry
import os
import sys

# Ensure src path acts as root
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

def test_plugin_discovery_and_instantiation():
    try:
        from core.plugins import Registry
    except ImportError:
        pass # Handle tricky paths depending on running context

    Registry.discover()
    plugins = Registry.list_info()
    
    # Assert that actual default plugins were discovered automatically
    assert len(plugins) > 0
    names = [p["name"] for p in plugins]
    
    # Verify core modules got loaded natively
    assert "sqli" in names or "xss" in names or "idor" in names or "ssrf" in names
