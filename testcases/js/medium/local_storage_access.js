// 访问本地存储
// 保存数据
localStorage.setItem("user_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9");
localStorage.setItem("preferences", JSON.stringify({theme: "dark", fontSize: "large"}));

// 获取数据
const token = localStorage.getItem("user_token");
const preferences = JSON.parse(localStorage.getItem("preferences"));

// 使用会话存储
sessionStorage.setItem("temp_data", "some_value");
const tempData = sessionStorage.getItem("temp_data");