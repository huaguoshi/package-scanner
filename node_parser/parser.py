#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Node.js parser implementation
"""

import os
import sys
import json
import logging
import subprocess
from typing import Dict, Any

logger = logging.getLogger('package-scanner.node-parser')

class NodeParser:
    """Node.js AST parser for JavaScript files"""
    
    def __init__(self):
        """Initialize the parser and check Node.js installation"""
        # Check if Node.js is installed
        try:
            subprocess.run(['node', '--version'], check=True, stdout=subprocess.PIPE)
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error("Node.js not detected. Please install Node.js to parse JavaScript files")
            sys.exit(1)
            
        # Create parser script if it doesn't exist
        parser_script = os.path.join(os.path.dirname(__file__), 'parse.js')
        if not os.path.exists(parser_script):
            logger.error(f"Parser script not found: {parser_script}")
            logger.error("Please ensure the parse.js file is in the node_parser directory")
            sys.exit(1)
            
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse JavaScript file using Node.js
        
        Args:
            file_path: Path to JavaScript file
            
        Returns:
            Dictionary with AST analysis results
        """
        parser_script = os.path.join(os.path.dirname(__file__), 'parse.js')
        
        try:
            result = subprocess.run(
                ['node', parser_script, file_path],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            return json.loads(result.stdout)
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to parse file: {file_path}, error: {e}")
            logger.error(f"stderr: {e.stderr if hasattr(e, 'stderr') else ''}")
            return {}
        except json.JSONDecodeError:
            logger.error(f"JSON parsing failed, parser output: {result.stdout if 'result' in locals() else 'unknown'}")
            return {}