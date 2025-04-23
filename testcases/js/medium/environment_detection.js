// 环境检测，可能用于沙箱逃逸
function checkEnvironment() {
    // 检测各种环境变量
    if (process.env.CI || process.env.JENKINS || process.env.TRAVIS) {
        return false;
    }
    
    // 检测浏览器特性
    if (navigator && navigator.userAgent.indexOf("Chrome") > -1) {
        return true;
    }
    
    // 检测容器环境
    try {
        const fs = require('fs');
        if (fs.existsSync('/.dockerenv')) {
            return false;
        }
    } catch (e) {}
    
    return true;
}