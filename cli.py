#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
更新后的CLI主入口，支持所有新功能
"""

import os
import sys
import argparse
import datetime
import logging
import importlib.util
from typing import Dict, List, Any, Optional

# 检查所需模块是否安装
required_modules = ['yaml']
for module in required_modules:
    if importlib.util.find_spec(module) is None:
        print(f"错误: 所需模块 '{module}' 未安装")
        print("请使用以下命令安装依赖: pip install -r requirements.txt")
        sys.exit(1)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('package-scanner')

# 导入本地模块
from scanner import Scanner
from engine import RuleEngine
from node_parser import NodeParser
from reporter import Reporter

def analyze_javascript_code(file_path: str, engine: RuleEngine) -> List[Dict]:
    """
    分析JavaScript文件中的恶意模式
    
    Args:
        file_path: JavaScript文件路径
        engine: 规则引擎实例
        
    Returns:
        检测到的问题列表
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
        logger.error(f"分析JavaScript代码失败: {file_path}, 错误: {e}")
        return []

def scan_for_patterns(file_path: str, language: str, engine: RuleEngine) -> List[Dict]:
    """
    使用模式匹配扫描文件
    
    Args:
        file_path: 文件路径
        language: 编程语言
        engine: 规则引擎实例
        
    Returns:
        检测到的问题列表
    """
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        matches = []
        for rule in engine.rules:
            if rule.get('language') == language and 'pattern' in rule:
                # 获取上下文行数设置
                context_lines = rule.get('context_lines', 2)
                rule_matches = engine.match_pattern_rule(rule, file_path, content, context_lines)
                matches.extend(rule_matches)
                
        return matches
    except Exception as e:
        logger.error(f"扫描文件失败: {file_path}, 错误: {e}")
        return []

def analyze_package_json(file_path: str) -> Dict:
    """
    分析package.json文件中的可疑依赖和脚本
    
    Args:
        file_path: package.json文件路径
        
    Returns:
        分析结果字典
    """
    import json
    import re
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        result = {
            'dependencies': {},
            'scripts': {},
            'suspicious_items': []
        }
        
        # 收集依赖
        for dep_type in ['dependencies', 'devDependencies']:
            if dep_type in data:
                for pkg, version in data[dep_type].items():
                    result['dependencies'][pkg] = {
                        'version': version,
                        'type': dep_type
                    }
                    
        # 检查脚本，特别是安装脚本
        if 'scripts' in data:
            for name, script in data['scripts'].items():
                result['scripts'][name] = script
                
                # 标记可疑的安装脚本
                if name in ['preinstall', 'postinstall', 'install']:
                    suspicious_patterns = ['curl', 'wget', 'http', 'https', '|', '>', 'eval']
                    if any(pattern in script for pattern in suspicious_patterns):
                        result['suspicious_items'].append({
                            'type': 'suspicious_script',
                            'name': name,
                            'script': script,
                            'reason': '包含潜在危险的命令'
                        })
                    
        return result
    except Exception as e:
        logger.error(f"分析package.json失败: {e}")
        return {}

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='第三方包供应链攻击检测工具')
    parser.add_argument('target', help='目标目录或包路径')
    parser.add_argument('--output', '-o', help='报告输出格式 (json, text)', default='text')
    parser.add_argument('--verbose', '-v', action='store_true', help='输出详细日志')
    parser.add_argument('--skip-dts', '-s', action='store_true', help='跳过TypeScript定义文件(.d.ts)')
    parser.add_argument('--rules-dir', '-r', help='规则目录路径')
    parser.add_argument('--context-lines', '-c', type=int, default=2, help='显示的上下文行数')
    parser.add_argument('--severity', '-S', choices=['high', 'medium', 'low', 'all'], default='all', 
                      help='只报告指定严重性的问题')
    parser.add_argument('--obfuscation-only', '-O', action='store_true', help='只检测代码混淆')
    parser.add_argument('--skip-dist', '-D', action='store_true', default=True,
                    help='跳过dist目录和压缩文件(默认开启)')
    parser.add_argument('--include-dist', '-I', action='store_false', dest='skip_dist',
                    help='包含dist目录和压缩文件')
    parser.add_argument('--max-context', '-M', type=int, default=300, 
                    help='代码上下文最大字符数 (默认: 300)')

    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logging.getLogger('package-scanner').setLevel(logging.DEBUG)
    
    start_time = datetime.datetime.now()
    print(f"开始扫描: {args.target}\n")
    
    # 如果只检测混淆，使用专门的混淆检测器
    if args.obfuscation_only:
        try:
            from obfuscation_detector import ObfuscationDetector
            detector = ObfuscationDetector(context_lines=args.context_lines)
            
            if os.path.isfile(args.target):
                results = detector.scan_file(args.target)
            else:
                results = detector.scan_directory(args.target, recursive=True)
                
            detector.print_results(results)
            
            if args.output:
                output_file = f"obfuscation_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{args.output}"
                if args.output == 'json':
                    detector.save_results(results, output_file)
                else:
                    detector.generate_report(results, output_file)
            
            end_time = datetime.datetime.now()
            duration = (end_time - start_time).total_seconds()
            print(f"\n混淆检测完成，用时: {duration:.2f} 秒")
            return
        except ImportError:
            logger.warning("混淆检测器模块不可用，回退到标准扫描")
    
    # 标准扫描流程
    # 步骤1: 扫描目录
    scanner = Scanner(args.target, skip_dts=args.skip_dts, skip_dist=args.skip_dist)

    files = scanner.scan()
    package_managers = scanner.detect_package_manager() or []
    
    # 步骤2: 加载规则引擎
    engine = RuleEngine()
    
    # 如果指定了规则目录，使用指定目录
    if args.rules_dir and os.path.isdir(args.rules_dir):
        engine.rule_dir = args.rules_dir
        
    # 根据严重性级别加载规则
    if args.severity != 'all':
        # 只加载指定严重性的规则
        engine.load_rules_by_severity(args.severity)
    else:
        # 加载所有规则
        engine.load_rules()
    
    # 步骤3: 初始化报告器
    reporter = Reporter(context_lines=args.context_lines, max_context_chars=args.max_context)
    
    # 步骤4: 分析文件
    for file_path, language in files:
        print(f"分析文件: {os.path.basename(file_path)} ({language})")
        
        # 基于文件类型选择分析方法
        if language == 'javascript':
            matches = analyze_javascript_code(file_path, engine)
            # 同时使用模式匹配进行补充
            pattern_matches = scan_for_patterns(file_path, language, engine)
            matches.extend(pattern_matches)
        else:
            # 对其他语言使用模式匹配
            matches = scan_for_patterns(file_path, language, engine)
            
        if matches:
            reporter.add_result(file_path, matches)
    
    # 步骤5: 分析包管理器文件
    if 'npm' in package_managers:
        package_json_path = os.path.join(args.target, 'package.json')
        if os.path.exists(package_json_path):
            pkg_data = analyze_package_json(package_json_path)
            
            if 'suspicious_items' in pkg_data and pkg_data['suspicious_items']:
                reporter.add_result(package_json_path, [
                    {
                        'rule': item['type'],
                        'description': f"可疑的 {item['name']} 脚本",
                        'severity': 'high',
                        'location': {'file': package_json_path},
                        'details': item['script']
                    }
                    for item in pkg_data['suspicious_items']
                ])
    
    # 步骤6: 根据严重性筛选并输出报告
    if args.severity != 'all':
        reporter.print_by_severity(args.severity)
        if reporter.results:
            reporter.save_by_severity(args.severity, format_type=args.output)
    else:
        reporter.print_results()
        if reporter.results:
            reporter.save_report(format_type=args.output)
    
    end_time = datetime.datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print(f"\n扫描完成，用时: {duration:.2f} 秒")


if __name__ == "__main__":
    main()