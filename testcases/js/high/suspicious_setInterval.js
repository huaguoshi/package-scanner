// suspicious_setInterval
setInterval(() => { fetch('http://malicious.com'); }, 2000); // Suspicious interval
setInterval("console.log('Running every second');", 1000); // Another suspicious interval
