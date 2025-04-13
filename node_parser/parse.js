// node_parser/parse.js
// JavaScript代码AST解析工具

const fs = require('fs');
const path = require('path');

// 检查是否安装了acorn
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

// 使用acorn解析AST
try {
    const ast = acorn.parse(source, {
        ecmaVersion: 2020,
        sourceType: 'module',
        locations: true
    });
    
    // 收集分析结果
    const result = {
        filePath,
        calls: [],              // 函数调用
        evals: [],              // eval调用
        dynamicRequires: [],    // 动态require
        suspiciousFunctions: [], // 可疑函数使用
        stringManipulations: [], // 字符串操作
        networkRequests: [],     // 网络请求
        environmentProbes: [],   // 环境探测
        fileOperations: []       // 文件操作
    };
    
    // 遍历AST查找可疑的调用
    walk.recursive(ast, {}, {
        // 分析函数调用
        CallExpression(node, state, c) {
            // 处理callee节点
            c(node.callee, state);
            
            // 处理arguments
            node.arguments.forEach(arg => c(arg, state));
            
            // 记录函数调用信息
            if (node.callee.type === 'Identifier') {
                const name = node.callee.name;
                const args = node.arguments.map(arg => {
                    return {
                        type: arg.type,
                        value: arg.type === 'Literal' ? arg.value : source.substring(arg.start, arg.end)
                    };
                });
                
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
                    if (node.arguments.length > 0 && 
                        ((node.arguments[0].type === 'Literal' && typeof node.arguments[0].value === 'string') ||
                         (node.arguments[0].type === 'BinaryExpression' && 
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
                    if (node.arguments.length > 0 && node.arguments[0].type !== 'Literal') {
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
            else if (node.callee.type === 'MemberExpression') {
                const callee = source.substring(node.callee.start, node.callee.end);
                const args = node.arguments.map(arg => {
                    return {
                        type: arg.type,
                        value: arg.type === 'Literal' ? arg.value : source.substring(arg.start, arg.end)
                    };
                });
                
                result.calls.push({
                    name: callee,
                    location: node.loc,
                    args
                });
                
                // 检测对象属性上的eval
                if (node.callee.property.type === 'Identifier' && node.callee.property.name === 'eval') {
                    result.evals.push({
                        type: 'method_eval',
                        location: node.loc,
                        object: source.substring(node.callee.object.start, node.callee.object.end),
                        args: args.map(arg => arg.value)
                    });
                }
                
                // 检测网络请求方法
                const networkMethods = ['fetch', 'get', 'post', 'put', 'delete', 'request', 'send'];
                if (node.callee.property.type === 'Identifier' && networkMethods.includes(node.callee.property.name)) {
                    result.networkRequests.push({
                        type: 'network_method',
                        name: callee,
                        location: node.loc,
                        args: args.map(arg => arg.value)
                    });
                }
                
                // 检测文件系统操作
                const fileSystemMethods = ['readFile', 'writeFile', 'appendFile', 'unlink', 'mkdir', 'rmdir'];
                if (node.callee.property.type === 'Identifier' && fileSystemMethods.includes(node.callee.property.name)) {
                    result.fileOperations.push({
                        type: 'file_operation',
                        name: callee,
                        location: node.loc,
                        args: args.map(arg => arg.value)
                    });
                }
            }
        },
        
        // 检测字符串混淆和拼接
        BinaryExpression(node, state, c) {
            c(node.left, state);
            c(node.right, state);
            
            if (node.operator === '+' && 
                ((node.left.type === 'Literal' && typeof node.left.value === 'string') ||
                 (node.right.type === 'Literal' && typeof node.right.value === 'string'))) {
                // 只记录长字符串拼接
                const leftStr = node.left.type === 'Literal' ? node.left.value : '';
                const rightStr = node.right.type === 'Literal' ? node.right.value : '';
                if (leftStr.length > 3 || rightStr.length > 3) {
                    result.stringManipulations.push({
                        type: 'string_concat',
                        location: node.loc,
                        expression: source.substring(node.start, node.end)
                    });
                }
            }
        },
        
        // 检测环境探测
        MemberExpression(node, state, c) {
            c(node.object, state);
            c(node.property, state);
            
            const obj = node.object.type === 'Identifier' ? node.object.name : '';
            const prop = node.property.type === 'Identifier' ? node.property.name : '';
            
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
        },
        
        // 检测变量声明中的可疑模式
        VariableDeclaration(node, state, c) {
            node.declarations.forEach(decl => {
                c(decl, state);
                
                // 检测短变量名和混淆变量
                if (decl.id.type === 'Identifier') {
                    const name = decl.id.name;
                    if (/^(_[0-9a-f]{4,}|[a-z]{1,2}[0-9]{1,2})$/.test(name) && decl.init) {
                        // 检测字符数组初始化
                        if (decl.init.type === 'ArrayExpression' && 
                            decl.init.elements.length > 3 && 
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
    });
    
    // 输出分析结果
    console.log(JSON.stringify(result, null, 2));
} catch (e) {
    console.error(`解析文件失败: ${e.message}`);
    process.exit(1);
}