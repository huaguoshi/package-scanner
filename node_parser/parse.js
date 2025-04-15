// node_parser/parse.js
// JavaScript and TypeScript代码AST解析工具

const fs = require('fs');
const path = require('path');

// 检查是否安装了acorn依赖
try {
    require.resolve('acorn');
    require.resolve('acorn-walk');
} catch (e) {
    console.error('请先安装依赖: npm install acorn acorn-walk');
    console.error('运行命令: npm install acorn acorn-walk');
    process.exit(1);
}

const acorn = require('acorn');
const walk = require('acorn-walk');

// 获取命令行参数中的文件路径
const filePath = process.argv[2];
if (!filePath) {
    console.error('请提供要解析的文件路径');
    process.exit(1);
}

// 读取文件内容
let source;
try {
    source = fs.readFileSync(filePath, 'utf8');
} catch (e) {
    console.error(`读取文件失败: ${e.message}`);
    process.exit(1);
}

// 检测文件类型
const isTypeScript = filePath.endsWith('.ts') || filePath.endsWith('.tsx') || filePath.endsWith('.d.ts');

// 尝试加载TypeScript解析器
let tsParser = null;
if (isTypeScript) {
    try {
        // 尝试多种可能的导入方式
        try {
            tsParser = require('@typescript-eslint/parser');
        } catch (e) {
            try {
                const parser = require('@typescript-eslint/parser');
                tsParser = parser.parse || parser;
            } catch (e) {
                console.warn('TypeScript文件检测到，但@typescript-eslint/parser导入失败');
            }
        }
    } catch (e) {
        console.warn('TypeScript文件检测到，但@typescript-eslint/parser模块不可用');
    }
}

// 针对.d.ts文件的简单预处理函数
function preprocessDtsFile(source) {
    return source
        // 移除export和import语句
        .replace(/export\s+(type|interface|enum|const enum|declare|namespace|abstract class|class|function)\s+/g, '$1 ')
        .replace(/import\s+.*?from\s+['"].*?['"];?/g, '')
        .replace(/import\s+{.*?}\s+from\s+['"].*?['"];?/g, '')
        // 移除类型注解
        .replace(/:\s*[A-Za-z0-9_<>\[\]|&(),\s.]+(?=[,);=])/g, '')
        // 移除泛型
        .replace(/<[^>]+>/g, '')
        // 移除接口定义
        .replace(/interface\s+\w+(\s+extends\s+[^{]+)?\s*{[^}]*}/g, '')
        // 移除类型别名
        .replace(/type\s+\w+\s*=\s*[^;]+;/g, '')
        // 移除命名空间
        .replace(/namespace\s+\w+\s*{[^}]*}/g, '')
        // 移除修饰符
        .replace(/(@[a-zA-Z]+\([^)]*\)\s*|readonly\s+|public\s+|private\s+|protected\s+|abstract\s+|static\s+)/g, '')
        // 移除declare语句
        .replace(/declare\s+(namespace|module|global|type|interface|class|enum|const)\s+/g, '$1 ')
        // 处理枚举
        .replace(/enum\s+(\w+)\s*{[^}]*}/g, 'const $1 = {}')
        // 处理可选参数
        .replace(/\?:/g, ':')
        // 处理剩余参数
        .replace(/\.\.\.(\w+):/g, '...$1')
        // 处理对象文字类型
        .replace(/{\s*\[key:\s*\w+\]:\s*\w+;\s*}/g, '{}')
        // 简化声明合并
        .replace(/export\s+as\s+namespace\s+\w+;?/g, '')
        // 移除空导出
        .replace(/export\s*{};?/g, '')
        // 替换模块声明语法
        .replace(/declare\s+module\s+['"].*?['"] \{([\s\S]*?)\}/g, (match, p1) => {
            return p1.replace(/export\s+/g, '');
        });
}

try {
    let ast;
    let preprocessed = false;
    
    if (isTypeScript) {
        // TypeScript文件处理
        if (tsParser) {
            try {
                // 尝试使用TypeScript解析器
                ast = tsParser.parse(source, {
                    ecmaVersion: 2020,
                    sourceType: 'module',
                    ecmaFeatures: {
                        jsx: true
                    },
                    loc: true,
                    range: true,
                    tokens: true,
                    comment: true,
                    eslintVisitorKeys: true,
                    eslintScopeManager: true
                });
            } catch (e) {
                console.warn(`使用TypeScript解析器失败，尝试预处理: ${e.message}`);
                // 如果使用TypeScript解析器失败，尝试预处理
                source = preprocessDtsFile(source);
                preprocessed = true;
                
                // 尝试使用acorn解析预处理后的代码
                try {
                    ast = acorn.parse(source, {
                        ecmaVersion: 2020,
                        sourceType: 'module',
                        locations: true,
                        allowReserved: true,
                        allowReturnOutsideFunction: true,
                        allowImportExportEverywhere: true
                    });
                } catch (innerError) {
                    console.error(`预处理后使用acorn解析失败: ${innerError.message}`);
                    // 创建一个空的AST，允许继续处理
                    ast = {
                        type: 'Program',
                        body: [],
                        sourceType: 'module'
                    };
                }
            }
        } else {
            // 如果没有TypeScript解析器，使用预处理+acorn
            source = preprocessDtsFile(source);
            preprocessed = true;
            
            try {
                ast = acorn.parse(source, {
                    ecmaVersion: 2020,
                    sourceType: 'module',
                    locations: true,
                    allowReserved: true,
                    allowReturnOutsideFunction: true,
                    allowImportExportEverywhere: true
                });
            } catch (e) {
                console.error(`预处理后使用acorn解析TypeScript失败: ${e.message}`);
                // 创建一个空的AST，允许继续处理
                ast = {
                    type: 'Program',
                    body: [],
                    sourceType: 'module'
                };
            }
        }
    } else {
        // 标准JavaScript文件处理
        try {
            ast = acorn.parse(source, {
                ecmaVersion: 2020,
                sourceType: 'module',
                locations: true
            });
        } catch (e) {
            console.error(`解析JavaScript失败: ${e.message}`);
            ast = {
                type: 'Program',
                body: [],
                sourceType: 'module'
            };
        }
    }
    
    // 确保ast不是null或undefined
    if (!ast) {
        console.warn("无法生成AST，使用空AST");
        ast = {
            type: 'Program',
            body: [],
            sourceType: 'module'
        };
    }
    
    // 收集分析结果
    const result = {
        filePath,
        isTypeScript,
        preprocessed,
        calls: [],              // 函数调用
        evals: [],              // eval调用
        dynamicRequires: [],    // 动态require
        suspiciousFunctions: [], // 可疑函数使用
        stringManipulations: [], // 字符串操作
        networkRequests: [],     // 网络请求
        environmentProbes: [],   // 环境探测
        fileOperations: []       // 文件操作
    };
    
    try {
        // 遍历AST查找可疑的调用
        walk.recursive(ast, {}, {
            // 分析函数调用
            CallExpression(node, state, c) {
                try {
                    // 处理callee节点
                    if (node.callee) {
                        c(node.callee, state);
                    }
                    
                    // 处理arguments
                    if (node.arguments && Array.isArray(node.arguments)) {
                        node.arguments.forEach(arg => {
                            if (arg) c(arg, state);
                        });
                    }
                    
                    // 记录函数调用信息
                    if (node.callee && node.callee.type === 'Identifier') {
                        const name = node.callee.name;
                        const args = node.arguments && Array.isArray(node.arguments) ? 
                            node.arguments.map(arg => {
                                if (!arg) return { type: 'unknown', value: 'undefined' };
                                return {
                                    type: arg.type,
                                    value: arg.type === 'Literal' ? arg.value : 
                                          (arg.start !== undefined && arg.end !== undefined) ? 
                                          source.substring(arg.start, arg.end) : 'unknown'
                                };
                            }) : [];
                        
                        result.calls.push({
                            name,
                            location: node.loc,
                            args
                        });
                        
                        // 检测eval调用
                        if (name === 'eval') {
                            result.evals.push({
                                type: 'eval',
                                location: node.loc,
                                args: args.map(arg => arg.value)
                            });
                        }
                        
                        // 检测Function构造函数
                        else if (name === 'Function') {
                            result.suspiciousFunctions.push({
                                type: 'Function_constructor',
                                location: node.loc,
                                args: args.map(arg => arg.value)
                            });
                        }
                        
                        // 检测setTimeout/setInterval字符串执行
                        else if (name === 'setTimeout' || name === 'setInterval') {
                            if (node.arguments && node.arguments.length > 0 && 
                                ((node.arguments[0].type === 'Literal' && typeof node.arguments[0].value === 'string') ||
                                 (node.arguments[0].type === 'BinaryExpression' && node.arguments[0].left && node.arguments[0].right && 
                                  ((node.arguments[0].left.type === 'Literal' && typeof node.arguments[0].left.value === 'string') ||
                                   (node.arguments[0].right.type === 'Literal' && typeof node.arguments[0].right.value === 'string'))))) {
                                result.suspiciousFunctions.push({
                                    type: `${name}_with_string`,
                                    location: node.loc,
                                    code: args[0].value
                                });
                            }
                        }
                        
                        // 检测require调用
                        else if (name === 'require') {
                            // 检测动态require - 不是字符串直接量
                            if (node.arguments && node.arguments.length > 0 && node.arguments[0].type !== 'Literal') {
                                result.dynamicRequires.push({
                                    type: 'dynamic_require',
                                    location: node.loc,
                                    arg: args[0].value
                                });
                            }
                        }
                        
                        // 检测网络请求
                        else if (['fetch', 'request', 'axios', 'http', 'XMLHttpRequest'].includes(name)) {
                            result.networkRequests.push({
                                type: 'network_request',
                                name,
                                location: node.loc,
                                args: args.map(arg => arg.value)
                            });
                        }
                        
                        // 检测Buffer操作和编码
                        else if (name === 'Buffer' || name === 'btoa' || name === 'atob') {
                            result.suspiciousFunctions.push({
                                type: 'encoding',
                                name,
                                location: node.loc,
                                args: args.map(arg => arg.value)
                            });
                        }
                    }
                    
                    // 检测成员表达式调用 (例如 console.log, window.eval)
                    else if (node.callee && node.callee.type === 'MemberExpression') {
                        let callee = 'unknown';
                        try {
                            if (node.callee.start !== undefined && node.callee.end !== undefined) {
                                callee = source.substring(node.callee.start, node.callee.end);
                            } else if (node.callee.object && node.callee.property) {
                                const obj = node.callee.object.type === 'Identifier' ? node.callee.object.name : 'obj';
                                const prop = node.callee.property.type === 'Identifier' ? node.callee.property.name : 'prop';
                                callee = `${obj}.${prop}`;
                            }
                        } catch (e) {
                            // 忽略错误，使用默认值
                        }
                        
                        const args = node.arguments && Array.isArray(node.arguments) ? 
                            node.arguments.map(arg => {
                                if (!arg) return { type: 'unknown', value: 'undefined' };
                                try {
                                    return {
                                        type: arg.type,
                                        value: arg.type === 'Literal' ? arg.value : 
                                              (arg.start !== undefined && arg.end !== undefined) ? 
                                              source.substring(arg.start, arg.end) : 'unknown'
                                    };
                                } catch (e) {
                                    return { type: 'error', value: 'error' };
                                }
                            }) : [];
                        
                        result.calls.push({
                            name: callee,
                            location: node.loc,
                            args
                        });
                        
                        // 检测对象属性上的eval
                        if (node.callee.property && node.callee.property.type === 'Identifier' && 
                            node.callee.property.name === 'eval' && node.callee.object) {
                            let objectName = 'unknown';
                            try {
                                if (node.callee.object.start !== undefined && node.callee.object.end !== undefined) {
                                    objectName = source.substring(node.callee.object.start, node.callee.object.end);
                                } else if (node.callee.object.type === 'Identifier') {
                                    objectName = node.callee.object.name;
                                }
                            } catch (e) {
                                // 忽略错误，使用默认值
                            }
                            
                            result.evals.push({
                                type: 'method_eval',
                                location: node.loc,
                                object: objectName,
                                args: args.map(arg => arg.value)
                            });
                        }
                        
                        try {
                            // 检测网络请求方法
                            const networkMethods = ['fetch', 'get', 'post', 'put', 'delete', 'request', 'send'];
                            if (node.callee.property && node.callee.property.type === 'Identifier' && 
                                networkMethods.includes(node.callee.property.name)) {
                                result.networkRequests.push({
                                    type: 'network_method',
                                    name: callee,
                                    location: node.loc,
                                    args: args.map(arg => arg.value)
                                });
                            }
                            
                            // 检测文件系统操作
                            const fileSystemMethods = ['readFile', 'writeFile', 'appendFile', 'unlink', 'mkdir', 'rmdir'];
                            if (node.callee.property && node.callee.property.type === 'Identifier' && 
                                fileSystemMethods.includes(node.callee.property.name)) {
                                result.fileOperations.push({
                                    type: 'file_operation',
                                    name: callee,
                                    location: node.loc,
                                    args: args.map(arg => arg.value)
                                });
                            }
                        } catch (e) {
                            // 忽略错误
                        }
                    }
                } catch (e) {
                    console.warn(`分析CallExpression时出错: ${e.message}`);
                }
            },
            
            // 检测字符串混淆和拼接
            BinaryExpression(node, state, c) {
                try {
                    if (node.left) c(node.left, state);
                    if (node.right) c(node.right, state);
                    
                    if (node.operator === '+' && 
                        ((node.left && node.left.type === 'Literal' && typeof node.left.value === 'string') ||
                         (node.right && node.right.type === 'Literal' && typeof node.right.value === 'string'))) {
                        // 只记录长字符串拼接
                        const leftStr = (node.left && node.left.type === 'Literal') ? node.left.value : '';
                        const rightStr = (node.right && node.right.type === 'Literal') ? node.right.value : '';
                        if (leftStr.length > 3 || rightStr.length > 3) {
                            let expression = 'unknown';
                            try {
                                if (node.start !== undefined && node.end !== undefined) {
                                    expression = source.substring(node.start, node.end);
                                }
                            } catch (e) {
                                // 忽略错误，使用默认值
                            }
                            
                            result.stringManipulations.push({
                                type: 'string_concat',
                                location: node.loc,
                                expression
                            });
                        }
                    }
                } catch (e) {
                    console.warn(`分析BinaryExpression时出错: ${e.message}`);
                }
            },
            
            // 检测环境探测
            MemberExpression(node, state, c) {
                try {
                    if (node.object) c(node.object, state);
                    if (node.property) c(node.property, state);
                    
                    const obj = (node.object && node.object.type === 'Identifier') ? node.object.name : '';
                    const prop = (node.property && node.property.type === 'Identifier') ? node.property.name : '';
                    
                    // 系统环境信息收集
                    const environmentObjects = ['process', 'navigator', 'window', 'document', 'global', 'os'];
                    const environmentProps = ['env', 'platform', 'arch', 'version', 'userAgent', 'location', 'cookie', 'hostname'];
                    
                    if (environmentObjects.includes(obj) && environmentProps.includes(prop)) {
                        result.environmentProbes.push({
                            type: 'environment_detection',
                            name: `${obj}.${prop}`,
                            location: node.loc
                        });
                    }
                } catch (e) {
                    console.warn(`分析MemberExpression时出错: ${e.message}`);
                }
            },
            
            // 检测变量声明中的可疑模式
            VariableDeclaration(node, state, c) {
                try {
                    if (node.declarations && Array.isArray(node.declarations)) {
                        node.declarations.forEach(decl => {
                            if (decl) c(decl, state);
                            
                            // 检测短变量名和混淆变量
                            if (decl && decl.id && decl.id.type === 'Identifier') {
                                const name = decl.id.name;
                                if (/^(_[0-9a-f]{4,}|[a-z]{1,2}[0-9]{1,2})$/.test(name) && decl.init) {
                                    // 检测字符数组初始化
                                    if (decl.init.type === 'ArrayExpression' && 
                                        decl.init.elements && decl.init.elements.length > 3 && 
                                        decl.init.elements.every(el => el && el.type === 'Literal' && typeof el.value === 'string')) {
                                        result.suspiciousFunctions.push({
                                            type: 'obfuscated_string_array',
                                            location: node.loc,
                                            name,
                                            values: decl.init.elements.map(el => el.value)
                                        });
                                    }
                                }
                            }
                        });
                    }
                } catch (e) {
                    console.warn(`分析VariableDeclaration时出错: ${e.message}`);
                }
            }
        });
    } catch (e) {
        console.warn(`AST遍历时出错: ${e.message}`);
        // 记录错误，但继续返回已收集的结果
        result.error = e.message;
    }
    
    // 输出分析结果
    console.log(JSON.stringify(result, null, 2));
} catch (e) {
    console.error(`解析文件失败: ${e.message}`);
    process.exit(1);
}