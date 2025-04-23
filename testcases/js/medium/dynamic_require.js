// 使用动态输入执行require函数
const moduleName = "config-" + process.env.NODE_ENV;
const config = require(moduleName);

// 另一个例子
const utils = require(`./utils/${userSpecifiedPath}`);