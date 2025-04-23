#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
更新后的规则引擎，支持更多功能，并优化了对混淆代码的检测
"""

import os
import re
import json
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple, Pattern, Set

logger = logging.getLogger('package-scanner.engine')

class RuleEngine:
    """规则引擎，负责加载和执行检测规则"""
    
    def __init__(self):
        """初始化规则引擎"""
        self.rules = []
        self.rule_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'rules')
        # 创建规则目录（如果不存在）
        os.makedirs(self.rule_dir, exist_ok=True)
        # 缓存已编译的正则表达式
        self.regex_cache = {}
        # 记录已处理的行范围，用于避免重复检测相同行上的混淆代码
        self.processed_line_ranges = {}
        
    def _compile_regex(self, pattern: str) -> Pattern:
        """
        编译正则表达式并缓存结果
        
        Args:
            pattern: 正则表达式模式
            
        Returns:
            编译后的正则表达式
        """
        if pattern not in self.regex_cache:
            try:
                self.regex_cache[pattern] = re.compile(pattern, re.MULTILINE)
            except re.error as e:
                logger.error(f"正则表达式编译失败: {pattern}, 错误: {e}")
                # 返回一个永远不会匹配的正则表达式
                self.regex_cache[pattern] = re.compile(r'^\b$')
                
        return self.regex_cache[pattern]
        
    def load_rules(self, language: Optional[str] = None) -> None:
        """
        加载规则文件
        
        Args:
            language: 可选的语言过滤器
        """
        rule_files = []
        
        for file in os.listdir(self.rule_dir):
            if file.endswith(('.yaml', '.yml', '.json')):
                rule_files.append(os.path.join(self.rule_dir, file))
                
        if not rule_files:
            logger.warning("未找到规则文件。请在 'rules' 目录中创建规则文件")
            return
            
        self.rules = []
        for rule_file in rule_files:
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
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
                logger.error(f"加载规则文件失败: {rule_file}, 错误: {e}")
                
        logger.info(f"已加载 {len(self.rules)} 条规则")
        
    def load_rules_by_severity(self, severity: str) -> None:
        """
        按严重性加载规则
        
        Args:
            severity: 规则严重性级别
        """
        rule_files = []
        
        # 找到特定严重性规则文件
        severity_files = [f for f in os.listdir(self.rule_dir) 
                          if f.startswith(severity.lower()) and f.endswith(('.yaml', '.yml', '.json'))]
        
        if severity_files:
            # 如果找到特定严重性规则文件，只加载这些文件
            for file in severity_files:
                rule_files.append(os.path.join(self.rule_dir, file))
        else:
            # 否则，加载所有规则并根据严重性过滤
            for file in os.listdir(self.rule_dir):
                if file.endswith(('.yaml', '.yml', '.json')):
                    rule_files.append(os.path.join(self.rule_dir, file))
        
        if not rule_files:
            logger.warning(f"未找到{severity}级别的规则文件。")
            return
            
        self.rules = []
        for rule_file in rule_files:
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    if rule_file.endswith(('.yaml', '.yml')):
                        rules = yaml.safe_load(f)
                    else:
                        rules = json.load(f)
                    
                    if isinstance(rules, list):
                        for rule in rules:
                            # 如果存在特定严重性规则文件，直接加载所有规则
                            if severity_files:
                                self.rules.append(rule)
                            # 否则根据严重性过滤
                            elif rule.get('severity', '').lower() == severity.lower():
                                self.rules.append(rule)
                    elif isinstance(rules, dict):
                        if severity_files or rules.get('severity', '').lower() == severity.lower():
                            self.rules.append(rules)
            except Exception as e:
                logger.error(f"加载规则文件失败: {rule_file}, 错误: {e}")
                
        logger.info(f"已加载 {len(self.rules)} 条{severity}级别的规则")
        
    def match_ast_rule(self, rule: Dict, ast_data: Dict) -> List[Dict]:
        """
        匹配基于AST的规则
        
        Args:
            rule: 规则定义
            ast_data: AST数据
            
        Returns:
            匹配结果列表
        """
        matches = []
        
        match_criteria = rule.get('match', {})
        rule_type = match_criteria.get('type')
        
        # 处理不同类型的AST规则
        if rule_type == 'CallExpression':
            callee_pattern = match_criteria.get('callee_pattern', '')
            args_contains = match_criteria.get('args_contains', '')
            headers_contains = match_criteria.get('headers_contains', '')
            
            for call in ast_data.get('calls', []):
                if callee_pattern and not any(pattern in call.get('name', '') 
                                             for pattern in callee_pattern.split('|')):
                    continue
                    
                # 检查参数
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
                    
                # 检查header是否包含敏感信息
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
                    # 检查是否有非字面量参数
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
        
    def match_pattern_rule(self, rule: Dict, file_path: str, file_content: str, context_lines: int = 2) -> List[Dict]:
        """
        匹配基于模式的规则
        
        Args:
            rule: 规则定义
            file_path: 文件路径
            file_content: 文件内容
            context_lines: 上下文行数
            
        Returns:
            匹配结果列表
        """
        matches = []
        
        pattern = rule.get('pattern')
        if not pattern:
            return []
        
        # 检查文件名是否匹配
        file_pattern = rule.get('file_pattern')
        if file_pattern and not re.search(file_pattern, file_path):
            return []
            
        # 规则是否针对混淆代码
        is_obfuscation_rule = 'obfuscated' in rule.get('rule_name', '').lower() or 'obfuscation' in rule.get('description', '').lower()

        # 初始化文件的处理行范围
        if file_path not in self.processed_line_ranges:
            self.processed_line_ranges[file_path] = set()
            
        # 编译正则表达式
        regex = self._compile_regex(pattern)
        
        # 检查是否有负向模式
        negative_pattern = rule.get('negative_pattern')
        negative_regex = None
        if negative_pattern:
            negative_regex = self._compile_regex(negative_pattern)
            
        # 获取规则的最小出现次数
        min_occurrences = rule.get('min_occurrences', 1)
        
        # 查找所有匹配
        all_matches = list(regex.finditer(file_content))
        
        # 如果匹配数小于最小出现次数，则返回空
        if len(all_matches) < min_occurrences:
            return []
            
        # 计算文件的行偏移量，用于定位行号
        line_offsets = [0]
        for i, char in enumerate(file_content):
            if char == '\n':
                line_offsets.append(i + 1)
                
        # 处理每个匹配
        for match in all_matches:
            # 如果有负向模式，则检查匹配是否符合负向模式
            if negative_regex and negative_regex.match(match.group(0)):
                continue
                
            # 获取匹配文本
            match_text = match.group(0)
            
            # 计算行号和列号
            start_pos = match.start()
            line_idx = 0
            while line_idx < len(line_offsets) and line_offsets[line_idx] <= start_pos:
                line_idx += 1
            line_idx -= 1
            line_number = line_idx + 1
            column = start_pos - line_offsets[line_idx] + 1
            
            # 对于混淆代码规则，如果当前行已经被处理过，跳过
            if is_obfuscation_rule:
                # 检查这个匹配位置是否在已处理的行范围内
                if self._in_processed_range(file_path, line_number):
                    continue
                    
                # 添加当前行到已处理的行范围
                self._add_processed_range(file_path, line_number, line_offsets, start_pos)
            
            # 获取上下文行
            context = self._get_context_lines(file_content, line_offsets, line_idx, context_lines)
            
            # 添加匹配结果
            matches.append({
                'rule': rule.get('rule_name'),
                'description': rule.get('description'),
                'severity': rule.get('severity', 'medium'),
                'location': {'line': line_number, 'column': column, 'file': file_path},
                'details': f"{match_text[:100]}{'...' if len(match_text) > 100 else ''}",
                'context': context
            })
                
        return matches
    
    def _in_processed_range(self, file_path: str, line_number: int) -> bool:
        """
        检查行号是否在已处理的范围内
        
        Args:
            file_path: 文件路径
            line_number: 行号
            
        Returns:
            是否在已处理范围内
        """
        return line_number in self.processed_line_ranges.get(file_path, set())
    
    def _add_processed_range(self, file_path: str, line_number: int, line_offsets: List[int], match_pos: int) -> None:
        """
        添加已处理的行范围
        
        Args:
            file_path: 文件路径
            line_number: 匹配的行号
            line_offsets: 行偏移量列表
            match_pos: 匹配位置
        """
        if file_path not in self.processed_line_ranges:
            self.processed_line_ranges[file_path] = set()
            
        # 添加当前行
        self.processed_line_ranges[file_path].add(line_number)
        
        # 尝试获取长行的内容以决定是否需要跳过更多行
        if line_number - 1 < len(line_offsets) - 1:  # 确保不是最后一行
            current_line_start = line_offsets[line_number - 1]
            next_line_start = line_offsets[line_number] if line_number < len(line_offsets) else -1
            
            # 如果有下一行且当前行特别长(例如超过300个字符)
            if next_line_start != -1 and next_line_start - current_line_start > 300:
                # 找到与当前行相同缩进级别的下一行
                next_non_continuation_line = self._find_next_non_continuation_line(line_number, line_offsets)
                
                # 将所有连续的行添加到已处理范围
                for l in range(line_number, next_non_continuation_line + 1):
                    self.processed_line_ranges[file_path].add(l)
    
    def _find_next_non_continuation_line(self, current_line: int, line_offsets: List[int]) -> int:
        """
        找到不是当前行延续的下一行
        
        Args:
            current_line: 当前行号
            line_offsets: 行偏移量列表
            
        Returns:
            下一个非延续行的行号
        """
        # 简单实现：对于混淆代码，通常是一个很长的行，我们可以返回当前行+10作为保守估计
        return min(current_line + 10, len(line_offsets))
        
    def _get_context_lines(self, content: str, line_offsets: List[int], line_idx: int, context_lines: int) -> Dict:
        """
        获取匹配行的上下文
        
        Args:
            content: 文件内容
            line_offsets: 行偏移量列表
            line_idx: 当前行索引
            context_lines: 上下文行数
            
        Returns:
            上下文信息字典
        """
        start_idx = max(0, line_idx - context_lines)
        end_idx = min(len(line_offsets) - 1, line_idx + context_lines)
        
        context_content = []
        for i in range(start_idx, end_idx + 1):
            if i == len(line_offsets) - 1:
                line = content[line_offsets[i]:]
            else:
                line = content[line_offsets[i]:line_offsets[i+1]]
                
            if line.endswith('\n'):
                line = line[:-1]
                
            context_content.append({
                'line_number': i + 1,
                'content': line,
                'is_match': i == line_idx
            })
            
        return {
            'lines': context_content,
            'start_line': start_idx + 1,
            'end_line': end_idx + 1,
            'match_line': line_idx + 1
        }