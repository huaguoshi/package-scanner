// 向外部传输私钥的HTTP请求
const apiKey = "sk_live_abcdefghijklmnopqrstuvwxyz";
fetch("http://example.com/api", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + apiKey
    }
});