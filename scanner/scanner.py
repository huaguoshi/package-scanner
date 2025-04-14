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
    """目录扫描器，负责扫描项目文件"""
    
    def __init__(self, target_path: str, skip_dts: bool = False, skip_dist: bool = True):
        """
        初始化扫描器
        
        Args:
            target_path: 要扫描的路径
            skip_dts: 是否跳过TypeScript定义文件(.d.ts)
            skip_dist: 是否跳过dist目录(通常包含压缩的构建代码)
        """
        self.target_path = os.path.abspath(target_path)
        self.file_list = []
        self.skip_dts = skip_dts
        self.skip_dist = skip_dist
        
    def scan(self) -> List[Tuple[str, str]]:
        """
        扫描目录下的支持文件
        
        Returns:
            文件路径和语言类型的元组列表
        """
        logger.info(f"开始扫描: {self.target_path}")
        if not os.path.exists(self.target_path):
            logger.error(f"目标路径不存在: {self.target_path}")
            return []
            
        for root, dirs, files in os.walk(self.target_path):
            # 跳过dist目录
            if self.skip_dist:
                # 修改dirs列表来避免递归进入某些目录
                dirs[:] = [d for d in dirs if d != 'dist']
                
                # 对于node_modules内的包，也跳过min和bundle目录
                if 'node_modules' in root:
                    dirs[:] = [d for d in dirs if not (
                        d == 'min' or 
                        d == 'bundle' or 
                        d == 'bundled' or 
                        d.endswith('.min') or 
                        d.endswith('-dist')
                    )]
            
            for file in files:
                # 跳过TypeScript定义文件
                if self.skip_dts and file.endswith('.d.ts'):
                    logger.debug(f"跳过TypeScript定义文件: {file}")
                    continue
                
                # 跳过压缩和编译后的js文件
                if file.endswith('.min.js') or file.endswith('.bundle.js'):
                    logger.debug(f"跳过压缩/打包JS文件: {file}")
                    continue
                    
                file_path = os.path.join(root, file)
                ext = os.path.splitext(file)[1].lower()
                
                for lang, extensions in SUPPORTED_LANGUAGES.items():
                    if ext in extensions:
                        self.file_list.append((file_path, lang))
                        break
                        
        logger.info(f"扫描完成，共发现 {len(self.file_list)} 个文件")
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