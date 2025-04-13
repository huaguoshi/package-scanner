#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Third-Party Package Supply Chain Attack Detection Tool

Main CLI entry point
"""

import os
import sys
import re
import json
import yaml
import argparse
import datetime
import logging
import importlib.util
from typing import Dict, List, Any, Optional

# Check if required modules are installed
required_modules = ['yaml']
for module in required_modules:
    if importlib.util.find_spec(module) is None:
        print(f"Error: Required module '{module}' is not installed.")
        print("Please install the required dependencies with: pip install -r requirements.txt")
        sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('package-scanner')

# Import local modules
from scanner import Scanner
from engine import RuleEngine
from node_parser import NodeParser
from reporter import Reporter

def analyze_javascript_code(file_path: str, engine: RuleEngine) -> List[Dict]:
    """
    Analyze JavaScript file for malicious patterns
    
    Args:
        file_path: Path to JavaScript file
        engine: Rule engine instance
        
    Returns:
        List of detected issues
    """
    try:
        parser = NodeParser()
        ast_data = parser.parse_file(file_path)
        
        matches = []
        for rule in engine.rules:
            if rule.get('language') == 'javascript' and 'match' in rule:
                rule_matches = engine.match_ast_rule(rule, ast_data)
                matches.extend(rule_matches)
                
        return matches
    except Exception as e:
        logger.error(f"Failed to analyze JavaScript code: {file_path}, error: {e}")
        return []

def scan_for_suspicious_patterns(file_path: str, language: str, engine: RuleEngine) -> List[Dict]:
    """
    Scan file for suspicious patterns using pattern-based rules
    
    Args:
        file_path: Path to file
        language: Programming language of the file
        engine: Rule engine instance
        
    Returns:
        List of detected issues
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        matches = []
        for rule in engine.rules:
            if rule.get('language') == language and 'pattern' in rule:
                rule_matches = engine.match_pattern_rule(rule, file_path, content)
                matches.extend(rule_matches)
                
        return matches
    except Exception as e:
        logger.error(f"Failed to scan file: {file_path}, error: {e}")
        return []

def analyze_package_json(file_path: str) -> Dict:
    """
    Analyze package.json file for suspicious dependencies and scripts
    
    Args:
        file_path: Path to package.json file
        
    Returns:
        Dictionary with analysis results
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        result = {
            'dependencies': {},
            'scripts': {},
            'suspicious_items': []
        }
        
        # Collect dependencies
        for dep_type in ['dependencies', 'devDependencies']:
            if dep_type in data:
                for pkg, version in data[dep_type].items():
                    result['dependencies'][pkg] = {
                        'version': version,
                        'type': dep_type
                    }
                    
        # Check scripts, especially install scripts
        if 'scripts' in data:
            for name, script in data['scripts'].items():
                result['scripts'][name] = script
                
                # Flag suspicious install scripts
                if name in ['preinstall', 'postinstall', 'install']:
                    suspicious_patterns = ['curl', 'wget', 'http', 'https', '|', '>', 'eval']
                    if any(pattern in script for pattern in suspicious_patterns):
                        result['suspicious_items'].append({
                            'type': 'suspicious_script',
                            'name': name,
                            'script': script,
                            'reason': 'Contains potentially dangerous commands'
                        })
                    
        return result
    except Exception as e:
        logger.error(f"Failed to analyze package.json: {e}")
        return {}

def analyze_requirements_txt(file_path: str) -> Dict:
    """
    Analyze requirements.txt file for suspicious dependencies
    
    Args:
        file_path: Path to requirements.txt file
        
    Returns:
        Dictionary with analysis results
    """
    try:
        result = {'dependencies': {}}
        
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                # Parse dependency format: package==version or package>=version
                parts = re.split(r'==|>=|<=|>|<|~=|!=', line)
                if len(parts) >= 1:
                    package = parts[0].strip()
                    version = line[len(package):].strip()
                    result['dependencies'][package] = {
                        'version': version or 'latest'
                    }
                    
        return result
    except Exception as e:
        logger.error(f"Failed to analyze requirements.txt: {e}")
        return {}

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Third-Party Package Supply Chain Attack Detection Tool')
    parser.add_argument('target', help='Target directory or package path')
    parser.add_argument('--output', '-o', help='Report output format (json, text)', default='text')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--skip-dts', '-s', action='store_true', help='Skip TypeScript definition files (.d.ts)')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger('package-scanner').setLevel(logging.DEBUG)
    
    start_time = datetime.datetime.now()
    print(f"Starting scan: {args.target}\n")
    
    # Step 1: Scan directory
    scanner = Scanner(args.target, skip_dts=args.skip_dts)
    files = scanner.scan()
    package_managers = scanner.detect_package_manager()
    # 添加检查以防止None错误
    if package_managers is None:
        package_managers = []  # 如果返回None，就使用空列表

    # Step 2: Load rule engine
    engine = RuleEngine()
    engine.load_rules()
    
    # Step 3: Analyze files
    reporter = Reporter()
    
    for file_path, language in files:
        print(f"Analyzing file: {os.path.basename(file_path)} ({language})")
        
        # Select analysis method based on file type
        if language == 'javascript':
            matches = analyze_javascript_code(file_path, engine)
        else:
            # Use pattern matching for other languages
            matches = scan_for_suspicious_patterns(file_path, language, engine)
            
        if matches:
            reporter.add_result(file_path, matches)
    
    # Step 4: Analyze package manager files
    if 'npm' in package_managers:
        package_json_path = os.path.join(args.target, 'package.json')
        if os.path.exists(package_json_path):
            pkg_data = analyze_package_json(package_json_path)
            
            if 'suspicious_items' in pkg_data and pkg_data['suspicious_items']:
                reporter.add_result(package_json_path, [
                    {
                        'rule': item['type'],
                        'description': f"Suspicious {item['name']} script",
                        'severity': 'high',
                        'location': {'file': package_json_path},
                        'details': item['script']
                    }
                    for item in pkg_data['suspicious_items']
                ])
    
    if 'pip' in package_managers:
        req_txt_path = os.path.join(args.target, 'requirements.txt')
        if os.path.exists(req_txt_path):
            # Currently, we don't have specific checks for requirements.txt
            # This can be expanded in the future
            pass
    
    # Step 5: Output report
    reporter.print_results()
    
    if reporter.results:
        reporter.save_report(format_type=args.output)
    
    end_time = datetime.datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print(f"\nScan completed, time taken: {duration:.2f} seconds")


if __name__ == "__main__":
    main()