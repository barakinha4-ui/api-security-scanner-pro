import pytest
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from cli import build_parser

def test_cli_parser_defaults_and_arguments():
    parser = build_parser()
    
    # Test valid parsing for custom arguments
    args = parser.parse_args(["--target", "https://api.vulnerable.com", "--scan", "quick", "--threads", "100"])
    
    assert args.target == "https://api.vulnerable.com"
    assert args.scan == "quick"
    assert args.threads == 100
    
def test_cli_parser_missing_required():
    parser = build_parser()
    
    # target is required logic (usually exits, we test if it throws SystemExit)
    with pytest.raises(SystemExit):
        parser.parse_args(["--scan", "full"])
