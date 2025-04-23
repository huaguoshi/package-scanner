// 修改文档位置，可能导致重定向
function redirect() {
    // 直接赋值
    location = "https://example.com";
    
    // 属性赋值
    window.location.href = "https://other-site.com";
    
    // replace方法
    location.replace("https://redirect.com");
}