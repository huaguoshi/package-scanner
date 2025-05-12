#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描器模块实现，支持白名单和灰名单，以及pnpm包管理器
增强版：处理嵌套node_modules结构中的包依赖，更好地应用白名单和灰名单规则
优化版：提高扫描效率，减少不必要的计算
rust扫描：需先执行
mkdir -p deps
CARGO_HOME=$(pwd)/.cargo cargo vendor deps
把三方包下载到本地并解压后才能扫描
"""

import os
import logging
import re
from typing import Dict, List, Tuple, Any, Optional, Set, FrozenSet

logger = logging.getLogger('package-scanner.scanner')

# 定义支持的语言文件扩展名 - 使用集合提高查找效率
SUPPORTED_LANGUAGES = {
    'javascript': frozenset(['.js', '.ts', '.jsx', '.tsx', '.d.ts']),
    'python': frozenset(['.py']),
    'go': frozenset(['.go']),
    'rust': frozenset(['.rs'])
}

# 预编译的正则表达式 - 提高匹配效率
NODE_MODULES_PATTERN = re.compile(r'[\\/]node_modules[\\/]')
DIST_DIR_PATTERN = re.compile(r'[\\/](dist|min|bundle|bundled|build|umd|esm|cjs|compiled|vendor)[\\/]')
SKIP_FILE_PATTERN = re.compile(r'(\.min\.js|\.bundle\.js|\.umd\.js|\.esm\.js|\.cjs\.js|\.compiled\.js|\.prod\.js|-bundle\.js|-min\.js)$')
RUST_DEP_PATTERN = re.compile(r'[\\/]deps[\\/]([\w-]+)(?:-\d+\.\d+\.\d+)?[\\/]')

class Scanner:
    """目录扫描器，负责扫描项目文件，优化版"""
    
    def __init__(self, target_path: str, skip_dts: bool = False, skip_dist: bool = True,
                 whitelist_file: str = None, graylist_file: str = None, 
                 rust_whitelist_file: str = None, go_whitelist_file: str = None,
                 skip_whitelist: bool = True, skip_graylist: bool = True,
                 skip_rust_whitelist: bool = True, skip_go_whitelist: bool = True):
        """
        初始化扫描器
        
        Args:
            target_path: 要扫描的路径
            skip_dts: 是否跳过TypeScript定义文件(.d.ts)
            skip_dist: 是否跳过dist目录(通常包含压缩的构建代码)
            whitelist_file: 白名单npm包列表文件路径
            graylist_file: 灰名单npm包列表文件路径
            rust_whitelist_file: Rust白名单包列表文件路径
            go_whitelist_file: Go白名单包列表文件路径
            skip_whitelist: 是否跳过白名单中的包
            skip_graylist: 是否跳过灰名单中的包
            skip_rust_whitelist: 是否跳过Rust白名单中的包
            skip_go_whitelist: 是否跳过Go白名单中的包
        """
        self.target_path = os.path.abspath(target_path)
        self.file_list = []
        self.skip_dts = skip_dts
        self.skip_dist = skip_dist
        self.skip_whitelist = skip_whitelist
        self.skip_graylist = skip_graylist
        self.skip_rust_whitelist = skip_rust_whitelist
        self.skip_go_whitelist = skip_go_whitelist
        
        # 使用集合提高查找效率
        self.whitelist = set()
        self.graylist = set()
        self.rust_whitelist = set()
        self.go_whitelist = set()
        
        # 包链缓存 - 避免重复计算同一路径的包链
        self._package_chain_cache = {}
        self._rust_package_cache = {}
        self._go_package_cache = {}
        
        # 跳过的目录集合 - 提高查找效率
        self.skip_dirs = frozenset([
            'dist', 'min', 'bundle', 'bundled', 'build',
            'umd', 'esm', 'cjs', 'compiled', 'vendor'
        ])
        
        # 默认的包列表目录和文件
        package_lists_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'package_lists')
        default_whitelist = os.path.join(package_lists_dir, 'whitelist.ini')
        default_graylist = os.path.join(package_lists_dir, 'graylist.ini')
        default_rust_whitelist = os.path.join(package_lists_dir, 'rust_whitelist.ini')
        default_go_whitelist = os.path.join(package_lists_dir, 'go_whitelist.ini')
        
        # 使用提供的文件路径或默认路径
        whitelist_path = whitelist_file or default_whitelist
        graylist_path = graylist_file or default_graylist
        rust_whitelist_path = rust_whitelist_file or default_rust_whitelist
        go_whitelist_path = go_whitelist_file or default_go_whitelist
        
        # 加载白名单
        self._load_list_file(whitelist_path, self.whitelist, "白名单", self.skip_whitelist)
        
        # 加载灰名单
        self._load_list_file(graylist_path, self.graylist, "灰名单", self.skip_graylist)
        
        # 加载Rust白名单
        self._load_list_file(rust_whitelist_path, self.rust_whitelist, "Rust白名单", self.skip_rust_whitelist)
        
        # 加载Go白名单
        self._load_list_file(go_whitelist_path, self.go_whitelist, "Go白名单", self.skip_go_whitelist)
    
    def _load_list_file(self, file_path: str, target_set: set, list_name: str, should_load: bool) -> None:
        """加载列表文件到集合中"""
        if not should_load or not os.path.exists(file_path):
            return
            
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        target_set.add(line)
            logger.info(f"已加载 {len(target_set)} 个{list_name}包")
        except Exception as e:
            logger.error(f"加载{list_name}文件失败: {e}")
                
    def scan(self) -> List[Tuple[str, str]]:
        """
        扫描目录下的支持文件，特别增强对Go文件的处理
        
        Returns:
            文件路径和语言类型的元组列表
        """
        logger.info(f"开始扫描: {self.target_path}")
        if not os.path.exists(self.target_path):
            logger.error(f"目标路径不存在: {self.target_path}")
            return []
            
        # 添加调试统计
        count_all_files = 0
        count_go_files = 0
        dirs_processed = 0
        
        # 创建一个语言扩展名映射表，避免循环查找
        ext_to_lang = {}
        for lang, extensions in SUPPORTED_LANGUAGES.items():
            for ext in extensions:
                ext_to_lang[ext] = lang
                
        for root, dirs, files in os.walk(self.target_path):
            dirs_processed += 1
            
            # 目录级别统计
            count_all_files += len(files)
            go_files_count = len([f for f in files if f.endswith('.go')])
            count_go_files += go_files_count
            
            # 检查是否在node_modules目录中
            is_node_modules = bool(NODE_MODULES_PATTERN.search(root))
            
            # 检查是否在Rust deps目录中
            is_rust_deps = '/deps/' in root.replace('\\', '/') or '\\deps\\' in root
                
            # 检查是否在Go vendor目录中
            is_go_vendor = '/vendor/' in root.replace('\\', '/') or '\\vendor\\' in root
            
            if is_node_modules:
                # 处理Node.js包依赖
                package_chain = self._get_package_chain_cached(root)
                
                if package_chain:
                    # 检查依赖链中是否有白名单包
                    if self.skip_whitelist and package_chain & self.whitelist:
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"跳过白名单包依赖链: {' -> '.join(package_chain)}")
                        dirs.clear()  # 清空dirs列表，不继续递归
                        continue
                        
                    # 检查依赖链中是否有灰名单包
                    if self.skip_graylist and package_chain & self.graylist:
                        if logger.isEnabledFor(logging.DEBUG):
                            logger.debug(f"跳过灰名单包依赖链: {' -> '.join(package_chain)}")
                        dirs.clear()  # 清空dirs列表，不继续递归
                        continue
            
            elif is_rust_deps and self.skip_rust_whitelist and self.rust_whitelist:
                # 处理Rust依赖包
                rust_package = self._get_rust_package_name(root)
                if rust_package and rust_package in self.rust_whitelist:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"跳过Rust白名单包: {rust_package}")
                    dirs.clear()  # 清空dirs列表，不继续递归
                    continue
            
            elif is_go_vendor and self.skip_go_whitelist and self.go_whitelist:
                # 处理Go依赖包
                go_package = self._get_go_package_name(root)
                if go_package and go_package in self.go_whitelist:
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"跳过Go白名单包: {go_package}")
                    dirs.clear()  # 清空dirs列表，不继续递归
                    continue
                
            # 跳过dist目录等 - 但不影响.go文件的扫描
            is_scanning_go_directory = any(f.endswith('.go') for f in files)
            
            if self.skip_dist and not is_scanning_go_directory:
                # 只对非Go文件目录应用skip_dist规则
                # 原地过滤dirs列表
                i = 0
                while i < len(dirs):
                    if dirs[i] in self.skip_dirs:
                        dirs.pop(i)
                    else:
                        i += 1
                
                # 检查当前目录是否应该跳过
                if DIST_DIR_PATTERN.search(root):
                    continue
            
            # 批量处理文件
            for file in files:
                # 获取文件扩展名
                _, ext = os.path.splitext(file)
                ext = ext.lower()
                
                # 特殊处理Go文件 - 不跳过任何.go文件
                if ext == '.go':
                    file_path = os.path.join(root, file)
                    self.file_list.append((file_path, 'go'))
                    continue
                
                # 对于非Go文件，保持原有的处理逻辑
                # 跳过TypeScript定义文件
                if self.skip_dts and file.endswith('.d.ts'):
                    continue
                    
                # 跳过压缩文件
                if SKIP_FILE_PATTERN.search(file):
                    continue
                    
                # 对JavaScript文件检查是否是压缩文件
                if ext == '.js' and os.path.getsize(os.path.join(root, file)) > 50000:  # 50KB
                    try:
                        with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                            first_line = f.readline()
                            if len(first_line) > 1000:
                                continue
                    except Exception:
                        pass  # 如果读取失败，继续处理该文件
                
                # 使用映射表快速查找语言类型
                if ext in ext_to_lang:
                    file_path = os.path.join(root, file)
                    self.file_list.append((file_path, ext_to_lang[ext]))
        
        # 添加额外统计信息        
        logger.info(f"扫描完成，共发现 {len(self.file_list)} 个文件")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"目录统计: 处理了 {dirs_processed} 个目录, 发现 {count_all_files} 个文件, 其中 {count_go_files} 个Go文件")
        
        return self.file_list
       
    def _get_package_chain_cached(self, path: str) -> FrozenSet[str]:
        """
        从缓存中获取包链，如果缓存中不存在则计算并存入缓存
        
        Args:
            path: 文件或目录路径
            
        Returns:
            包名的不可变集合
        """
        if path in self._package_chain_cache:
            return self._package_chain_cache[path]
            
        # 计算包链并转换为不可变集合
        packages = frozenset(self._compute_package_chain(path))
        self._package_chain_cache[path] = packages
        return packages
        
    def _compute_package_chain(self, path: str) -> List[str]:
        """
        从路径中计算npm包的依赖链，支持嵌套的node_modules结构
        同时支持标准node_modules和pnpm结构
        
        Args:
            path: 文件或目录路径
            
        Returns:
            包名链列表
        """
        # 快速检查 - 优化常见情况
        if 'node_modules' not in path:
            return []
            
        packages = []
        
        # 使用正则表达式优化路径分割处理
        pnpm_pattern = re.compile(r'[\\/]\.pnpm[\\/]')
        is_pnpm = bool(pnpm_pattern.search(path))
        
        if is_pnpm:
            # PNPM结构处理 - 优化实现
            path_parts = re.split(r'[\\/]', path)  # 跨平台路径分割
            try:
                pnpm_index = path_parts.index('.pnpm')
                
                # 处理PNPM主包
                if pnpm_index + 1 < len(path_parts):
                    package_info = path_parts[pnpm_index + 1]
                    
                    # 使用更高效的方式处理@org/package格式
                    if package_info.startswith('@'):
                        # 处理@org/package@version格式
                        at_splits = package_info.split('@', 2)  # 最多分割2次
                        if len(at_splits) >= 3:
                            package_part = '@' + at_splits[1]
                            if package_part:
                                packages.append(package_part)
                    else:
                        # 普通包名处理
                        version_split = package_info.split('@', 1)  # 最多分割1次
                        package_part = version_split[0]
                        if package_part:
                            packages.append(package_part)
                
                # 优化查找嵌套node_modules
                node_modules_indices = [i for i, part in enumerate(path_parts) 
                                       if part == 'node_modules' and i > pnpm_index]
                
                for idx in node_modules_indices:
                    if idx + 1 < len(path_parts):
                        pkg = path_parts[idx + 1]
                        # 检查并处理@org/package格式
                        if pkg.startswith('@') and idx + 2 < len(path_parts):
                            pkg = f"{pkg}/{path_parts[idx + 2]}"
                        
                        # 避免重复添加
                        if pkg and pkg not in packages:
                            packages.append(pkg)
            
            except (ValueError, IndexError) as e:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"解析PNPM路径时出错: {e}")
        else:
            # 标准node_modules结构 - 优化实现
            # 使用正则表达式分割 - 处理不同操作系统的路径分隔符
            parts = re.split(r'[\\/]node_modules[\\/]', path)
            
            if len(parts) < 2:
                return []
                
            for i in range(1, len(parts)):
                # 每个部分的第一个目录是包名
                package_path = parts[i].split(os.sep, 1)[0] if os.sep in parts[i] else parts[i]
                
                # 优化处理@org/package格式
                if package_path.startswith('@'):
                    try:
                        # 直接获取@org/package格式
                        org_parts = parts[i].split(os.sep, 2)
                        if len(org_parts) >= 2:
                            package_path = f"{org_parts[0]}/{org_parts[1]}"
                    except IndexError:
                        pass  # 保持原始包名
                
                # 只添加有效的不重复包名
                if package_path and package_path not in packages:
                    packages.append(package_path)
        
        return packages
    
    def _get_rust_package_name(self, path: str) -> Optional[str]:
        """
        从路径中提取Rust包名，支持带版本号的格式
        
        Args:
            path: 文件或目录路径
            
        Returns:
            Rust包名或None
        """
        # 使用缓存
        if path in self._rust_package_cache:
            return self._rust_package_cache[path]
        
        # 使用正则表达式提取包名，忽略版本号
        match = RUST_DEP_PATTERN.search(path.replace('\\', '/'))
        if match:
            package_name = match.group(1)
            self._rust_package_cache[path] = package_name
            return package_name
        
        # 尝试直接提取包名（对于没有版本号的情况）
        parts = path.replace('\\', '/').split('/deps/')
        if len(parts) > 1:
            package_dir = parts[1].split('/', 1)[0]
            # 移除可能的版本号
            package_name = re.sub(r'-\d+\.\d+\.\d+.*$', '', package_dir)
            self._rust_package_cache[path] = package_name
            return package_name
        
        self._rust_package_cache[path] = None
        return None
        
    def _get_go_package_name(self, path: str) -> Optional[str]:
        """
        从路径中提取Go包名，针对vendor目录下的包
        
        Args:
            path: 文件或目录路径
            
        Returns:
            Go包名或None
        """
        # 使用缓存
        if path in self._go_package_cache:
            return self._go_package_cache[path]
        
        # 将路径转换为统一格式
        normalized_path = path.replace('\\', '/')
        
        # 检查是否在vendor目录中
        if '/vendor/' not in normalized_path:
            self._go_package_cache[path] = None
            return None
        
        # 提取vendor后面的路径部分
        parts = normalized_path.split('/vendor/')
        if len(parts) < 2:
            self._go_package_cache[path] = None
            return None
        
        # 获取vendor后面的包路径
        package_path = parts[1]
        
        # 移除可能的文件名和多余部分
        if '/' in package_path:
            # 假设路径格式为 github.com/user/repo/...
            # 我们需要考虑不同深度的包路径
            path_parts = package_path.split('/')
            
            # 处理不同深度的包路径
            # 例如 github.com/user/repo 或 golang.org/x/crypto
            if path_parts[0] == 'github.com' and len(path_parts) >= 3:
                # github.com/user/repo 格式
                package_name = '/'.join(path_parts[:3])
            elif path_parts[0] in ('golang.org', 'gopkg.in') and len(path_parts) >= 2:
                # golang.org/x/crypto 或 gopkg.in/yaml.v2 格式
                package_name = '/'.join(path_parts[:3] if len(path_parts) >= 3 else path_parts[:2])
            elif path_parts[0] in ('k8s.io', 'sigs.k8s.io') and len(path_parts) >= 2:
                # k8s.io/client-go 或 sigs.k8s.io/yaml 格式
                package_name = '/'.join(path_parts[:2])
            else:
                # 其他域名，尝试使用前两部分
                package_name = '/'.join(path_parts[:2] if len(path_parts) >= 2 else path_parts)
        else:
            # 没有子路径，直接使用
            package_name = package_path
        
        self._go_package_cache[path] = package_name
        return package_name

    def detect_package_manager(self) -> List[str]:
        """
        检测项目使用的包管理器 - 优化版，减少I/O操作
        
        Returns:
            检测到的包管理器列表
        """
        package_managers = []
        
        # 定义需要检查的文件和对应的包管理器
        package_manager_files = [
            ('package.json', 'npm'),
            ('pnpm-lock.yaml', 'pnpm'),
            ('yarn.lock', 'yarn'),
            ('go.mod', 'go'),
            ('Cargo.toml', 'cargo')
        ]
        
        # 一次性检查多个文件 - 减少重复调用os.path.join
        target_dir = self.target_path
        for filename, manager in package_manager_files:
            if os.path.exists(os.path.join(target_dir, filename)):
                package_managers.append(manager)
        
        # 单独处理pip（可能有多个文件满足条件）
        if (os.path.exists(os.path.join(target_dir, 'requirements.txt')) or 
            os.path.exists(os.path.join(target_dir, 'setup.py'))):
            package_managers.append('pip')
            
        if package_managers:
            logger.info(f"检测到的包管理器: {', '.join(package_managers)}")
        else:
            logger.info(f"未检测到包管理器")
        
        return package_managers