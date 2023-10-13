FortifyQL is a sophisticated security scanning tool designed to provide developers with deep insights into potential security vulnerabilities within their GraphQL API's. FortifyQL dynamically generates queries that emulate common attacks identified by the Open Web Application Security Project (OWASP). The responses are analyzed for insecure default configurations and missing security measures that may lead to Injection, Denial of Service (DOS), and Batching attacks. The data is displayed within an intuitive and user-friendly interface, making it accessible to developers of all skill levels.

Let's further explore FortifyQL's initial robust test suites. 

## Table of Contents

1. [Features](##Features)
2. [Setup](##Setup)
3. [Roadmap](##Roadmap)
4. [Contributors](##Contributors)

## Features:

• SQL Injection (Boolean, Error, and Time-based): These tests check for vulnerabilities in different types of database systems, using various injection techniques to expose weaknesses.

• Denial of Service (DoS: Circular): This test simulates a circular DoS-type attack, rendering a system unresponsive through excessive resource consumption.

• Batching (Multiple Queries and Resource Exhaustive/Nested): Batching and nesting tests aim to uncover resource exhaustion and complex operations that could harm your server.

• Verbose Error: This test identifies security misconfigurations by exposing excessive system information.

![](/src/assets/FortifyQLDemo4.gif)

## Setup:

1. Clone the FortifyQL repository locally and install required modules:

```bash
npm install
```
2. Launch FortifyQL from the command line:
-`npm run dev`: Runs frontend and backend development servers concurrently for an integrated development experience.

3. Enable introspection for GraphQL endpoint.

4. Navigate to http://localhost:5173/ to view web application

5. Input GraphQL URI into input field

6. Toggle desired tests to execute


## Roadmap
| Feature                                          | Status |
| ------------------------------------------------ | ------ |
| Dynamic Query Generation                         | ✅     |
| In-Depth Reporting                               | ✅     |
| Increase Testing Coverage                        | ⏳     |
| Expansion of Pentesting Suite                    | ⏳     |
| Introspection and URI Authentication             | ⏳     |
| Node and Rate Limit Calculator                   | ⚡️     |


- ✅ = Completed
- ⏳ = In-Progress
- ⚡️ = Backlog

## Contributors

• Rachel Power: [LinkedIn](https://www.linkedin.com/in/rachel-b-power/) | [GitHub](https://github.com/rpower15)

• Ayden Yip: [LinkedIn](https://www.linkedin.com/in/aydenyip/) | [GitHub](https://github.com/aydenyipcs)

• Megan Kabat: [LinkedIn](https://www.linkedin.com/in/megan-kabat/) | [GitHub](https://github.com/mnkabat)

• David Yoon: [LinkedIn](https://www.linkedin.com/in/davidlyoon/) | [GitHub](https://github.com/DYoonity)



