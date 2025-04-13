#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reporter implementation
"""

import os
import json
import datetime
import logging
from typing import Dict, List, Any, Optional

try:
    from colorama import init, Fore, Style
    init()
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False
    
logger = logging.getLogger('package-scanner.reporter')

class Reporter:
    """Results reporter, responsible for outputting detection results"""
    
    def __init__(self, output_dir: str = None):
        """
        Initialize reporter
        
        Args:
            output_dir: Optional directory for report output
        """
        self.results = []
        self.output_dir = output_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), 'report')
        os.makedirs(self.output_dir, exist_ok=True)
        
    def add_result(self, file_path: str, matches: List[Dict]) -> None:
        """
        Add detection result
        
        Args:
            file_path: Path to the file
            matches: List of rule matches for the file
        """
        if matches:
            self.results.append({
                'file': file_path,
                'matches': matches
            })
            
    def print_results(self) -> None:
        """Print detection results to console"""
        if not self.results:
            logger.info("No suspicious code detected")
            return
            
        print("\n=== Detection Results ===\n")
        
        total_issues = sum(len(result['matches']) for result in self.results)
        print(f"Found {total_issues} suspicious issues:\n")
        
        if COLOR_ENABLED:
            severity_colors = {
                'high': Fore.RED,
                'medium': Fore.YELLOW,
                'low': Fore.BLUE,
                'info': Fore.GREEN
            }
            reset_color = Style.RESET_ALL
        else:
            severity_colors = {
                'high': '',
                'medium': '',
                'low': '',
                'info': ''
            }
            reset_color = ''
        
        for result in self.results:
            file_path = result['file']
            for match in result['matches']:
                severity = match.get('severity', 'medium')
                color = severity_colors.get(severity.lower(), '')
                
                location = match.get('location', {})
                if isinstance(location, dict):
                    if 'line' in location:
                        line_info = f":{location.get('line', '')}:{location.get('column', '')}"
                    else:
                        line_info = ""
                else:
                    line_info = ""
                
                print(f"{color}[{severity.upper()}]{reset_color} {match.get('rule')}")
                print(f"File: {file_path}{line_info}")
                print(f"Description: {match.get('description')}")
                
                details = match.get('details')
                if isinstance(details, str) and details:
                    print(f"Details: {details}")
                    
                print("")
                
    def save_report(self, format_type: str = 'json') -> Optional[str]:
        """
        Save detection report to file
        
        Args:
            format_type: Report format ('json' or 'text')
            
        Returns:
            Path to the report file or None if no issues found
        """
        if not self.results:
            return None
            
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if format_type == 'json':
            report_path = os.path.join(self.output_dir, f'report_{timestamp}.json')
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, ensure_ascii=False, indent=2)
        elif format_type == 'text':
            report_path = os.path.join(self.output_dir, f'report_{timestamp}.txt')
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("=== Detection Results ===\n\n")
                
                total_issues = sum(len(result['matches']) for result in self.results)
                f.write(f"Found {total_issues} suspicious issues:\n\n")
                
                for result in self.results:
                    file_path = result['file']
                    for match in result['matches']:
                        severity = match.get('severity', 'medium')
                        
                        location = match.get('location', {})
                        if isinstance(location, dict):
                            if 'line' in location:
                                line_info = f":{location.get('line', '')}:{location.get('column', '')}"
                            else:
                                line_info = ""
                        else:
                            line_info = ""
                        
                        f.write(f"[{severity.upper()}] {match.get('rule')}\n")
                        f.write(f"File: {file_path}{line_info}\n")
                        f.write(f"Description: {match.get('description')}\n")
                        
                        details = match.get('details')
                        if isinstance(details, str) and details:
                            f.write(f"Details: {details}\n")
                            
                        f.write("\n")
                        
        logger.info(f"Report saved to: {report_path}")
        return report_path