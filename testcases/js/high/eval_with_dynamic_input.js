// eval_with_dynamic_input
const userInput = prompt("请输入要计算的表达式:");
eval(userInput); // ⚠️ 高危：用户输入直接被执行


const dynamicEval = eval("2 + 2"); // Another eval example


// 使用动态输入执行eval函数
const userInput = "alert('XSS attack')";
eval(userInput);  // 高风险：使用动态输入执行eval

// 另一个变种
const code = "return " + userInput;
eval("(function() { " + code + " })()");


