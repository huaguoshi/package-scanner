Third-Party Package Supply Chain Attack Detection Tool
A static analysis tool for detecting malicious code patterns in third-party packages across multiple programming languages.

Features
Multi-language support: JavaScript/TypeScript (npm), Python (pip), Go (go modules), and Rust (crates.io)
Detects various malicious behaviors including data exfiltration, code injection, and environment detection
Customizable rule sets via YAML/JSON configuration
Comprehensive reporting in multiple formats
Quick Start
Prerequisites
Python 3.6+
Node.js 12+ (for JavaScript parsing)
Installation
Clone the repository:
bash
git clone https://github.com/yourusername/package-scanner.git
cd package-scanner
Install Python dependencies:
bash
pip install -r requirements.txt
Install Node.js parser dependencies:
bash
cd node_parser
npm install acorn acorn-walk
cd ..
Basic Usage
Scan a project or package:

bash
python cli.py ./path/to/project
For more options:

bash
python cli.py --help
Documentation
For detailed usage instructions, see the User Manual.

Project Structure
package-scanner/
├── cli.py # Main entry point script
├── scanner/ # Directory scanner
├── engine/ # Rule execution core
├── node_parser/ # Node.js AST parsing interface
├── reporter/ # Results reporting
├── rules/ # Rule definitions
├── report/ # Output reports
└── testcases/ # Example test cases
License
MIT

Acknowledgements
This project was inspired by the need to protect against supply chain attacks like the event-stream incident of 2018 and other similar cases.
