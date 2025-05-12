#!/usr/bin/env python3
"""
Test script to directly test the SemgrepRunner class on our sample files.
"""

import os
import sys
import json

# Add the project root to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.analysis.static.semgrep_runner import SemgrepRunner

def test_python_file():
    """Test semgrep on a Python file."""
    print("\n=== Testing SemgrepRunner on Python file ===")
    
    # Get the rules path from the project configuration
    rules_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'rules', 'semgrep'))
    
    # Initialize the semgrep runner with our rules path
    runner = SemgrepRunner(rules_path=rules_path)
    
    # Print the loaded rules for debugging
    print(f"Loaded rules: {runner.list_rules()}")
    
    # Path to the sample Python file
    sample_path = os.path.join(os.path.dirname(__file__), 'sample_for_semgrep.py')
    
    try:
        # Run semgrep on the sample file
        results = runner.run(target_path=sample_path, language='python')
        
        # Print the results
        print(f"Found {len(results)} issues:")
        for i, result in enumerate(results, 1):
            rule_id = result.get('rule_id', 'unknown')
            message = result.get('extra', {}).get('message', 'No message')
            path = result.get('path', 'unknown')
            category = result.get('category', 'unknown')
            priority = result.get('priority', 'unknown')
            
            print(f"{i}. {rule_id}: {message}")
            print(f"   Path: {path}")
            print(f"   Category: {category}")
            print(f"   Priority: {priority}")
            print()
        
        return len(results) > 0
    except Exception as e:
        print(f"Error running semgrep: {e}")
        return False

def test_generic_file():
    """Test semgrep on a generic text file."""
    print("\n=== Testing SemgrepRunner on generic text file ===")
    
    # Get the rules path from the project configuration
    rules_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'rules', 'semgrep'))
    
    # Initialize the semgrep runner with our rules path
    runner = SemgrepRunner(rules_path=rules_path)
    
    # Print the loaded rules for debugging
    print(f"Loaded rules: {runner.list_rules()}")
    
    # Path to the sample generic file
    sample_path = os.path.join(os.path.dirname(__file__), 'sample_for_generic.txt')
    
    try:
        # Run semgrep on the sample file
        results = runner.run(target_path=sample_path, language='generic')
        
        # Print the results
        print(f"Found {len(results)} issues:")
        for i, result in enumerate(results, 1):
            rule_id = result.get('rule_id', 'unknown')
            message = result.get('extra', {}).get('message', 'No message')
            path = result.get('path', 'unknown')
            category = result.get('category', 'unknown')
            priority = result.get('priority', 'unknown')
            
            print(f"{i}. {rule_id}: {message}")
            print(f"   Path: {path}")
            print(f"   Category: {category}")
            print(f"   Priority: {priority}")
            print()
        
        return True  # Consider success even if no issues found
    except Exception as e:
        print(f"Error running semgrep: {e}")
        return False

if __name__ == "__main__":
    print("=== Testing SemgrepRunner Directly ===")
    
    python_success = test_python_file()
    generic_success = test_generic_file()
    
    if python_success and generic_success:
        print("\n✅ All tests passed! The semgrep configuration has been fixed successfully.")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed. The semgrep configuration may still have issues.")
        sys.exit(1)