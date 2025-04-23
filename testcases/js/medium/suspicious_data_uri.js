// 使用Data URI可能隐藏恶意内容
const img = new Image();
img.src = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

// 隐藏脚本
const script = document.createElement('script');
script.src = "data:text/javascript;base64,Y29uc29sZS5sb2coJ0hlbGxvIScpOw==";
document.body.appendChild(script);