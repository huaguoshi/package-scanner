#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描器模块实现，支持白名单和灰名单
"""

import os
import logging
from typing import Dict, List, Tuple, Any, Optional

logger = logging.getLogger('package-scanner.scanner')

# 定义支持的语言文件扩展名
SUPPORTED_LANGUAGES = {
    'javascript': ['.js', '.ts', '.jsx', '.tsx', '.d.ts'],
    'python': ['.py'],
    'go': ['.go'],
    'rust': ['.rs']
}

class Scanner:
    """目录扫描器，负责扫描项目文件"""
    
    def __init__(self, target_path: str, skip_dts: bool = False, skip_dist: bool = True,
                 whitelist_file: str = None, graylist_file: str = None,
                 skip_whitelist: bool = True, skip_graylist: bool = True):
        """
        初始化扫描器
        
        Args:
            target_path: 要扫描的路径
            skip_dts: 是否跳过TypeScript定义文件(.d.ts)
            skip_dist: 是否跳过dist目录(通常包含压缩的构建代码)
            whitelist_file: 白名单npm包列表文件路径
            graylist_file: 灰名单npm包列表文件路径
            skip_whitelist: 是否跳过白名单中的包
            skip_graylist: 是否跳过灰名单中的包
        """
        self.target_path = os.path.abspath(target_path)
        self.file_list = []
        self.skip_dts = skip_dts
        self.skip_dist = skip_dist
        self.skip_whitelist = skip_whitelist
        self.skip_graylist = skip_graylist
        self.whitelist = []
        self.graylist = []
        
        # 默认的包列表目录和文件
        package_lists_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'package_lists')
        default_whitelist = os.path.join(package_lists_dir, 'whitelist.ini')
        default_graylist = os.path.join(package_lists_dir, 'graylist.ini')
        
        # 使用提供的文件路径或默认路径
        whitelist_path = whitelist_file or default_whitelist
        graylist_path = graylist_file or default_graylist
        
        # 加载白名单
        if self.skip_whitelist and os.path.exists(whitelist_path):
            try:
                with open(whitelist_path, 'r') as f:
                    self.whitelist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logger.info(f"已加载 {len(self.whitelist)} 个白名单包")
            except Exception as e:
                logger.error(f"加载白名单文件失败: {e}")
                
        # 加载灰名单
        if self.skip_graylist and os.path.exists(graylist_path):
            try:
                with open(graylist_path, 'r') as f:
                    self.graylist = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                logger.info(f"已加载 {len(self.graylist)} 个灰名单包")
            except Exception as e:
                logger.error(f"加载灰名单文件失败: {e}")
                
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
            # 处理node_modules目录
            if 'node_modules' in root:
                # 检查当前目录是否在白名单或灰名单中
                package_name = self._get_package_name(root)
                
                if package_name:
                    # 检查是否在白名单中(完全跳过)
                    if self.skip_whitelist and package_name in self.whitelist:
                        logger.debug(f"跳过白名单包: {package_name}")
                        dirs[:] = []  # 清空dirs列表，不继续递归
                        continue
                        
                    # 检查是否在灰名单中(完全跳过)
                    if self.skip_graylist and package_name in self.graylist:
                        logger.debug(f"跳过灰名单包: {package_name}")
                        dirs[:] = []  # 清空dirs列表，不继续递归
                        continue
                
                # 跳过dist目录等
                if self.skip_dist:
                    # 从dirs中移除不需要扫描的目录
                    dirs[:] = [d for d in dirs if d not in (
                        'dist', 'min', 'bundle', 'bundled', 'build',
                        'umd', 'esm', 'cjs', 'compiled', 'vendor'
                    )]
                    
                    # 如果当前目录是这些目录，跳过
                    if any(segment in root for segment in (
                        '/dist/', '/min/', '/bundle/', '/umd/', '/esm/', '/cjs/',
                        '.min/', '.bundle/', '.compiled/', '.umd/'
                    )):
                        continue
                
            # 处理文件
            for file in files:
                # 跳过TypeScript定义文件(.d.ts)
                if self.skip_dts and file.endswith('.d.ts'):
                    logger.debug(f"跳过TypeScript定义文件: {file}")
                    continue
                
                # 跳过压缩文件
                if any(suffix in file for suffix in (
                    '.min.js', '.bundle.js', '.umd.js', '.esm.js', '.cjs.js',
                    '.compiled.js', '.prod.js', '-bundle.js', '-min.js'
                )):
                    logger.debug(f"跳过压缩/打包JS文件: {file}")
                    continue
                    
                # 检查大文件
                file_path = os.path.join(root, file)
                if file.endswith('.js') and os.path.getsize(file_path) > 50000:  # 50KB
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            first_few_lines = [f.readline() for _ in range(5)]
                        
                        # 检查是否可能是压缩文件
                        if any(len(line) > 1000 for line in first_few_lines):
                            logger.debug(f"跳过可能压缩的大文件: {file}")
                            continue
                    except:
                        pass  # 如果读取失败，继续处理该文件
                
                # 添加符合条件的文件
                ext = os.path.splitext(file)[1].lower()
                for lang, extensions in SUPPORTED_LANGUAGES.items():
                    if ext in extensions:
                        self.file_list.append((file_path, lang))
                        break
                        
        logger.info(f"扫描完成，共发现 {len(self.file_list)} 个文件")
        return self.file_list
        
    def _get_package_name(self, path: str) -> Optional[str]:
        """
        从路径中提取npm包名
        
        Args:
            path: 文件或目录路径
            
        Returns:
            包名或None
        """
        if 'node_modules' not in path:
            return None
            
        # 提取node_modules之后的部分
        parts = path.split(os.path.sep + 'node_modules' + os.path.sep)
        if len(parts) < 2:
            return None
            
        # 获取包路径的第一部分
        package_path = parts[1].split(os.path.sep)[0]
        
        # 处理@org/package格式
        if package_path.startswith('@'):
            path_parts = parts[1].split(os.path.sep)
            if len(path_parts) >= 2:
                package_path = '@' + path_parts[1]
                package_path = path_parts[0] + '/' + path_parts[1]
        
        return package_path
    
    def detect_package_manager(self) -> List[str]:
        """
        检测项目使用的包管理器
        
        Returns:
            检测到的包管理器列表
        """
        package_managers = []
        
        # 检测 npm/yarn
        if os.path.exists(os.path.join(self.target_path, 'package.json')):
            package_managers.append('npm')
            
        # 检测 pip
        if os.path.exists(os.path.join(self.target_path, 'requirements.txt')) or \
           os.path.exists(os.path.join(self.target_path, 'setup.py')):
            package_managers.append('pip')
            
        # 检测 go modules
        if os.path.exists(os.path.join(self.target_path, 'go.mod')):
            package_managers.append('go')
            
        # 检测 cargo (Rust)
        if os.path.exists(os.path.join(self.target_path, 'Cargo.toml')):
            package_managers.append('cargo')
            
        logger.info(f"检测到的包管理器: {', '.join(package_managers) if package_managers else '无'}")
        return package_managers
