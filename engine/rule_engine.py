#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rule engine implementation
"""

import os
import re
import json
import yaml
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger('package-scanner.engine')

class RuleEngine:
    """Rule engine, responsible for loading and executing detection rules"""
    
    def __init__(self):
        """Initialize rule engine"""
        self.rules = []
        self.rule_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules')
        os.makedirs(self.rule_dir, exist_ok=True)
        
    def load_rules(self, language: Optional[str] = None) -> None:
        """
        Load rules from rule files
        
        Args:
            language: Optional language filter
        """
        rule_files = []
        
        for file in os.listdir(self.rule_dir):
            if file.endswith(('.yaml', '.yml', '.json')):
                rule_files.append(os.path.join(self.rule_dir, file))
                
        if not rule_files:
            logger.warning("No rule files found. Please create rules in the 'rules' directory")
            return
            
        self.rules = []
        for rule_file in rule_files:
            try:
                with open(rule_file, 'r') as f:
                    if rule_file.endswith(('.yaml', '.yml')):
                        rules = yaml.safe_load(f)
                    else:
                        rules = json.load(f)
                    
                    if isinstance(rules, list):
                        for rule in rules:
                            if language is None or rule.get('language') == language:
                                self.rules.append(rule)
                    elif isinstance(rules, dict):
                        if language is None or rules.get('language') == language:
                            self.rules.append(rules)
            except Exception as e:
                logger.error(f"Failed to load rule file: {rule_file}, error: {e}")
                
        logger.info(f"Loaded {len(self.rules)} rules")
        
    def match_ast_rule(self, rule: Dict, ast_data: Dict) -> List[Dict]:
        """
        Match AST-based rules against parsed data
        
        Args:
            rule: Rule definition dictionary
            ast_data: AST data from parser
            
        Returns:
            List of match results
        """
        matches = []
        
        match_criteria = rule.get('match', {})
        rule_type = match_criteria.get('type')
        
        # Handle different types of AST rules
        if rule_type == 'CallExpression':
            callee_pattern = match_criteria.get('callee_pattern', '')
            args_contains = match_criteria.get('args_contains', '')
            headers_contains = match_criteria.get('headers_contains', '')
            
            for call in ast_data.get('calls', []):
                if callee_pattern and not any(pattern in call.get('name', '') 
                                             for pattern in callee_pattern.split('|')):
                    continue
                    
                # Check arguments
                args_match = False
                if not args_contains:
                    args_match = True
                else:
                    for arg in call.get('args', []):
                        arg_value = str(arg.get('value', ''))
                        if any(pattern in arg_value for pattern in args_contains.split('|')):
                            args_match = True
                            break
                            
                if not args_match:
                    continue
                    
                # Check headers for sensitive info
                if headers_contains:
                    headers_match = False
                    for arg in call.get('args', []):
                        arg_value = str(arg.get('value', ''))
                        if any(pattern in arg_value for pattern in headers_contains.split('|')):
                            headers_match = True
                            break
                            
                    if not headers_match:
                        continue
                        
                matches.append({
                    'rule': rule.get('rule_name'),
                    'description': rule.get('description'),
                    'severity': rule.get('severity', 'medium'),
                    'location': call.get('location'),
                    'details': call
                })
                
        elif rule_type == 'eval':
            args_not_literal = match_criteria.get('args_not_literal', False)
            
            for eval_call in ast_data.get('evals', []):
                if args_not_literal:
                    # Check for non-literal arguments
                    for arg in eval_call.get('args', []):
                        if not arg.startswith('"') and not arg.startswith("'"):
                            matches.append({
                                'rule': rule.get('rule_name'),
                                'description': rule.get('description'),
                                'severity': rule.get('severity', 'high'),
                                'location': eval_call.get('location'),
                                'details': eval_call
                            })
                            break
                else:
                    matches.append({
                        'rule': rule.get('rule_name'),
                        'description': rule.get('description'),
                        'severity': rule.get('severity', 'high'),
                        'location': eval_call.get('location'),
                        'details': eval_call
                    })
                    
        elif rule_type == 'dynamic_require':
            for req in ast_data.get('dynamicRequires', []):
                matches.append({
                    'rule': rule.get('rule_name'),
                    'description': rule.get('description'),
                    'severity': rule.get('severity', 'medium'),
                    'location': req.get('location'),
                    'details': req
                })
                
        elif rule_type in ('string_concat', 'setTimeout_with_string', 'setInterval_with_string', 'environment_detection'):
            suspicious_items = []
            min_occurrences = match_criteria.get('min_occurrences', 1)
            
            for item in ast_data.get('suspiciousFunctions', []):
                if (rule_type == 'string_concat' and item.get('type') == 'string_concat') or \
                   (rule_type in ('setTimeout_with_string', 'setInterval_with_string') and 
                    item.get('type') in rule_type.split('|')) or \
                   (rule_type == 'environment_detection' and item.get('type') == 'environment_detection'):
                    suspicious_items.append(item)
                    
            if len(suspicious_items) >= min_occurrences:
                matches.append({
                    'rule': rule.get('rule_name'),
                    'description': rule.get('description'),
                    'severity': rule.get('severity', 'medium'),
                    'location': suspicious_items[0].get('location'),
                    'details': f"Found {len(suspicious_items)} occurrences"
                })
                
        return matches
        
    def match_pattern_rule(self, rule: Dict, file_path: str, file_content: str) -> List[Dict]:
        """
        Match pattern-based rules against file content
        
        Args:
            rule: Rule definition dictionary
            file_path: Path to the file
            file_content: Content of the file
            
        Returns:
            List of match results
        """
        matches = []
        
        pattern = rule.get('pattern')
        if not pattern:
            return []
            
        for i, line in enumerate(file_content.splitlines(), 1):
            if re.search(pattern, line):
                matches.append({
                    'rule': rule.get('rule_name'),
                    'description': rule.get('description'),
                    'severity': rule.get('severity', 'medium'),
                    'location': {'line': i, 'file': file_path},
                    'details': line.strip()
                })
                
        return matches