// 使用JSON.parse处理可能的恶意数据
const userInput = '{"code": "alert(document.cookie)"}';
const data = JSON.parse(userInput);
eval(data.code);