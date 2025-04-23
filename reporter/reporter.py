#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
增强的 Reporter 实现，支持上下文行显示和按风险级别分类报告
"""

import os
import json
import datetime
import logging
from typing import Dict, List, Any, Optional, Tuple

try:
    from colorama import init, Fore, Style
    init()
    COLOR_ENABLED = True
except ImportError:
    COLOR_ENABLED = False
    
logger = logging.getLogger('package-scanner.reporter')

class Reporter:
    """增强的结果报告器，负责格式化和输出检测结果"""
    
    def __init__(self, output_dir: str = None, context_lines: int = 2, max_context_chars: int = 300):
        """
        初始化报告器
        
        Args:
            output_dir: 报告输出目录
            context_lines: 显示的上下文行数（每侧）
        """
        self.results = []
        self.output_dir = output_dir or os.path.join(os.path.dirname(os.path.dirname(__file__)), 'report')
        os.makedirs(self.output_dir, exist_ok=True)
        self.context_lines = context_lines
        self.max_context_chars = max_context_chars
        self.file_contents_cache = {}  # 缓存文件内容以提高性能
        
    def add_result(self, file_path: str, matches: List[Dict]) -> None:
        """
        添加检测结果
        
        Args:
            file_path: 文件路径
            matches: 规则匹配列表
        """
        if matches:
            self.results.append({
                'file': file_path,
                'matches': matches
            })
    
    def _get_file_lines(self, file_path: str) -> List[str]:
        """
        获取文件内容的行列表
        
        Args:
            file_path: 文件路径
            
        Returns:
            文件内容行列表
        """
        if file_path in self.file_contents_cache:
            return self.file_contents_cache[file_path]
            
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                self.file_contents_cache[file_path] = lines
                return lines
        except Exception as e:
            logger.error(f"无法读取文件内容: {file_path}, 错误: {e}")
            return []
    
    def _get_context_lines(self, file_path: str, line_number: int) -> Tuple[List[str], int, int]:
        """
        获取指定行周围的上下文行
        
        Args:
            file_path: 文件路径
            line_number: 行号
            
        Returns:
            (上下文行列表, 起始行号, 结束行号)
        """
        lines = self._get_file_lines(file_path)
        if not lines:
            return [], 0, 0
            
        # 行号从1开始，但列表索引从0开始
        line_idx = line_number - 1
        if line_idx < 0 or line_idx >= len(lines):
            return [], 0, 0
            
        # 计算上下文范围
        start_idx = max(0, line_idx - self.context_lines)
        end_idx = min(len(lines) - 1, line_idx + self.context_lines)
        
        # 返回上下文行，和实际的起始和结束行号（从1开始）
        return lines[start_idx:end_idx+1], start_idx + 1, end_idx + 1
    
    def _group_results_by_severity(self) -> Dict[str, List[Dict]]:
        """
        按严重性分组结果
        
        Returns:
            分组后的结果字典
        """
        grouped = {
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        for result in self.results:
            file_path = result['file']
            for match in result['matches']:
                severity = match.get('severity', 'medium').lower()
                if severity not in grouped:
                    severity = 'medium'  # 默认为中等风险
                    
                # 创建新的条目，便于按风险分类
                entry = {
                    'file': file_path,
                    'match': match
                }
                grouped[severity].append(entry)
                
        return grouped
    
    def get_results_by_severity(self, severity: str) -> List[Dict]:
        """
        获取指定严重性级别的结果
        
        Args:
            severity: 严重性级别
            
        Returns:
            该严重性级别的结果列表
        """
        grouped = self._group_results_by_severity()
        return grouped.get(severity.lower(), [])
            
    def print_results(self, filter_severity: Optional[str] = None) -> None:
        """
        打印检测结果到控制台
        
        Args:
            filter_severity: 可选的过滤器，只显示指定严重性的结果
        """
        if not self.results:
            logger.info("未发现可疑代码")
            return
            
        # 按严重性分组
        grouped_results = self._group_results_by_severity()
        
        # 如果指定了过滤器，只打印特定严重性的结果
        severities = [filter_severity.lower()] if filter_severity else ['high', 'medium', 'low', 'info']
        
        # 设置颜色
        if COLOR_ENABLED:
            severity_colors = {
                'high': Fore.RED,
                'medium': Fore.YELLOW,
                'low': Fore.BLUE,
                'info': Fore.GREEN
            }
            reset_color = Style.RESET_ALL
            highlight_color = Fore.CYAN
        else:
            severity_colors = {
                'high': '',
                'medium': '',
                'low': '',
                'info': ''
            }
            reset_color = ''
            highlight_color = ''
        
        # 计算总数
        total_issues = sum(len(grouped_results[sev]) for sev in severities if sev in grouped_results)
        
        # 打印标题
        print("\n=== 检测结果 ===\n")
        print(f"发现 {total_issues} 个可疑问题\n")
        
        # 分别打印每个严重性级别的结果
        for severity in severities:
            if severity not in grouped_results or not grouped_results[severity]:
                continue
                
            issues = grouped_results[severity]
            color = severity_colors.get(severity, '')
            
            print(f"\n{color}[{severity.upper()} 级别问题] 共 {len(issues)} 个{reset_color}\n")
            print("-" * 80)
            
            for issue in issues:
                file_path = issue['file']
                match = issue['match']
                
                # 获取规则和描述
                rule = match.get('rule', '未知规则')
                description = match.get('description', '无描述')
                
                # 获取位置信息
                location = match.get('location', {})
                if isinstance(location, dict) and 'line' in location:
                    line_number = location.get('line', 0)
                    column = location.get('column', '')
                    line_info = f":{line_number}:{column}" if column else f":{line_number}"
                    
                    # 获取上下文行
                    context_lines, start_line, end_line = self._get_context_lines(file_path, line_number)
                    has_context = bool(context_lines)
                else:
                    line_info = ""
                    has_context = False
                
                # 打印问题信息
                print(f"{color}[{severity.upper()}]{reset_color} {rule}")
                print(f"文件: {file_path}{line_info}")
                print(f"描述: {description}")
                
                # 打印详细信息
                details = match.get('details')
                if isinstance(details, str) and details:
                    print(f"详情: {details}")
                
                # 打印上下文行
                if has_context:
                    print("\n代码上下文:")
                    total_chars = 0
                    truncated = False
                    
                    for i, line in enumerate(context_lines, start_line):
                        line_text = line.rstrip('\n')
                        # 如果添加这行会超出字符限制，则截断
                        if total_chars + len(line_text) > self.max_context_chars:
                            truncated = True
                            if i == line_number:  # 如果是当前匹配行，必须显示
                                print(f"{color}> {i:4d}|{reset_color} {highlight_color}{line_text[:self.max_context_chars-total_chars]}...{reset_color}")
                            break
                            
                        if i == line_number:  # 当前行
                            print(f"{color}> {i:4d}|{reset_color} {highlight_color}{line_text}{reset_color}")
                        else:  # 上下文行
                            print(f"  {i:4d}| {line_text}")
                            
                        total_chars += len(line_text)
                        
                    if truncated:
                        print(f"... (超出字符限制 {self.max_context_chars})")
                            
                print("-" * 80)
                
    def save_report(self, format_type: str = 'json', filter_severity: Optional[str] = None) -> str:
        """
        保存检测报告到文件
        
        Args:
            format_type: 报告格式（json 或 text）
            filter_severity: 可选的过滤器，只保存指定严重性的结果
            
        Returns:
            报告文件路径
        """
        if not self.results:
            return None
            
        # 按严重性分组
        grouped_results = self._group_results_by_severity()
        
        # 如果指定了过滤器，只保存特定严重性的结果
        severities = [filter_severity.lower()] if filter_severity else ['high', 'medium', 'low', 'info']
        filtered_results = []
        for severity in severities:
            if severity in grouped_results:
                filtered_results.extend(grouped_results[severity])
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        severity_suffix = f"_{filter_severity}" if filter_severity else ""
        
        if format_type == 'json':
            report_path = os.path.join(self.output_dir, f'report{severity_suffix}_{timestamp}.json')
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(filtered_results, f, ensure_ascii=False, indent=2)
        elif format_type == 'text':
            report_path = os.path.join(self.output_dir, f'report{severity_suffix}_{timestamp}.txt')
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("=== 检测结果 ===\n\n")
                
                total_issues = len(filtered_results)
                f.write(f"发现 {total_issues} 个可疑问题:\n\n")
                
                for issue in filtered_results:
                    file_path = issue['file']
                    match = issue['match']
                    severity = match.get('severity', 'medium').lower()
                    
                    rule = match.get('rule', '未知规则')
                    description = match.get('description', '无描述')
                    
                    # 获取位置信息
                    location = match.get('location', {})
                    if isinstance(location, dict) and 'line' in location:
                        line_number = location.get('line', 0)
                        column = location.get('column', '')
                        line_info = f":{line_number}:{column}" if column else f":{line_number}"
                        
                        # 获取上下文行
                        context_lines, start_line, end_line = self._get_context_lines(file_path, line_number)
                        has_context = bool(context_lines)
                    else:
                        line_info = ""
                        has_context = False
                    
                    # 写入问题信息
                    f.write(f"[{severity.upper()}] {rule}\n")
                    f.write(f"文件: {file_path}{line_info}\n")
                    f.write(f"描述: {description}\n")
                    
                    # 写入详细信息
                    details = match.get('details')
                    if isinstance(details, str) and details:
                        f.write(f"详情: {details}\n")
                    
                    # 写入上下文行
                    if has_context:
                        f.write("\n代码上下文:\n")
                        total_chars = 0
                        truncated = False
                        
                        for i, line in enumerate(context_lines, start_line):
                            line_text = line.rstrip('\n')
                            
                            # 检查字符限制
                            if total_chars + len(line_text) > self.max_context_chars:
                                truncated = True
                                if i == line_number:  # 如果是当前匹配行，必须显示
                                    f.write(f"> {i:4d}| {line_text[:self.max_context_chars-total_chars]}...\n")
                                break
                                
                            if i == line_number:  # 当前行
                                f.write(f"> {i:4d}| {line_text}\n")
                            else:  # 上下文行
                                f.write(f"  {i:4d}| {line_text}\n")
                                
                            total_chars += len(line_text)
                            
                        if truncated:
                            f.write(f"... (超出字符限制 {self.max_context_chars})\n")
                    
                    f.write("\n" + "-" * 80 + "\n\n")
                    
        logger.info(f"报告已保存到: {report_path}")
        return report_path
        
    def print_by_severity(self, severity: str) -> None:
        """
        打印特定严重性级别的结果
        
        Args:
            severity: 严重性级别（high, medium, low, info）
        """
        self.print_results(filter_severity=severity)
        
    def save_by_severity(self, severity: str, format_type: str = 'text') -> str:
        """
        保存特定严重性级别的结果
        
        Args:
            severity: 严重性级别（high, medium, low, info）
            format_type: 报告格式（json 或 text）
            
        Returns:
            报告文件路径
        """
        return self.save_report(format_type=format_type, filter_severity=severity)