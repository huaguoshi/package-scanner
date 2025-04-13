#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scanner module implementation
"""

import os
import logging
from typing import Dict, List, Tuple, Any

logger = logging.getLogger('package-scanner.scanner')

# Define supported language file extensions
SUPPORTED_LANGUAGES = {
    'javascript': ['.js', '.ts', '.jsx', '.tsx', '.d.ts'],  # 添加了.d.ts支持
    'python': ['.py'],
    'go': ['.go'],
    'rust': ['.rs']
}

class Scanner:
    """Directory scanner, responsible for scanning project files"""
    
    def __init__(self, target_path: str, skip_dts: bool = False):
        """
        Initialize scanner with target path
        
        Args:
            target_path: Path to scan
            skip_dts: Whether to skip TypeScript definition files (.d.ts)
        """
        self.target_path = os.path.abspath(target_path)
        self.file_list = []
        self.skip_dts = skip_dts
        
    def scan(self) -> List[Tuple[str, str]]:
        """
        Scan directory for supported files
        
        Returns:
            List of (file_path, language) tuples
        """
        logger.info(f"Starting scan: {self.target_path}")
        if not os.path.exists(self.target_path):
            logger.error(f"Target path does not exist: {self.target_path}")
            return []
            
        for root, _, files in os.walk(self.target_path):
            for file in files:
                # 跳过TypeScript定义文件(.d.ts)的选项
                if self.skip_dts and file.endswith('.d.ts'):
                    logger.debug(f"Skipping TypeScript definition file: {file}")
                    continue
                    
                file_path = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                
                for lang, extensions in SUPPORTED_LANGUAGES.items():
                    if ext in extensions:
                        self.file_list.append((file_path, lang))
                        break
                        
        logger.info(f"Scan complete, found {len(self.file_list)} files")
        return self.file_list
    
    def detect_package_manager(self) -> List[str]:
        """
        Detect package managers used in the project
        
        Returns:
            List of detected package managers
        """
        package_managers = []
        
        # Check for npm/yarn
        if os.path.exists(os.path.join(self.target_path, 'package.json')):
            package_managers.append('npm')
            
        # Check for pip
        if os.path.exists(os.path.join(self.target_path, 'requirements.txt')) or \
           os.path.exists(os.path.join(self.target_path, 'setup.py')):
            package_managers.append('pip')
            
        # Check for go modules
        if os.path.exists(os.path.join(self.target_path, 'go.mod')):
            package_managers.append('go')
            
        # Check for cargo (Rust)
        if os.path.exists(os.path.join(self.target_path, 'Cargo.toml')):
            package_managers.append('cargo')
            
        logger.info(f"Detected package managers: {', '.join(package_managers) if package_managers else 'None'}")
        return package_managers.append('npm')
            
        # Check for pip
        if os.path.exists(os.path.join(self.target_path, 'requirements.txt')) or \
           os.path.exists(os.path.join(self.target_path, 'setup.py')):
            package_managers.append('pip')
            
        # Check for go modules
        if os.path.exists(os.path.join(self.target_path, 'go.mod')):
            package_managers.append('go')
            
        # Check for cargo (Rust)
        if os.path.exists(os.path.join(self.target_path, 'Cargo.toml')):
            package_managers.append('cargo')
            
        logger.info(f"Detected package managers: {', '.join(package_managers) if package_managers else 'None'}")
        return package_managers