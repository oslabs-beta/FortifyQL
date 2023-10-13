FortifyQL is a sophisticated security scanning tool designed to provide developers with deep insights into potential security vulnerabilities within their GraphQL API's. FortifyQL dynamically generates queries that emulate common attacks identified by the Open Web Application Security Project (OWASP). The responses are analyzed for insecure default configurations and missing security measures that may lead to Injection, Denial of Service (DOS), and Batching attacks. The data is displayed within an intuitive and user-friendly interface, making it accessible to developers of all skill levels.

Let's further explore FortifyQL's initial robust test suites. 

• SQL Injection (Boolean, Error, and Time-based): These tests check for vulnerabilities in different types of database systems, using various injection techniques to expose weaknesses.

• Denial of Service (DoS: Circular): This test simulates a circular DoS-type attack, rendering a system unresponsive through excessive resource consumption.

• Batching (Multiple Queries and Resource Exhaustive/Nested): Batching and nesting tests aim to uncover resource exhaustion and complex operations that could harm your server.

• Verbose Error: This test identifies security misconfigurations by exposing excessive system information.

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

## Scripts 
-`npm run dev:frontend`: Initiates the Vite-powered frontend development environment.

-`npm run dev:backend`: Spins up the backend server using Nodemon and ts-node.

-`npm run dev`: Runs frontend and backend development servers concurrently for an integrated development experience.

-`npm run build:frontend`: Executes a frontend build using Vite.

-`npm run build:backend`: Compiles the backend code for production readiness.

-`npm run build`: Simultaneously builds both frontend and backend components.

-`npm run lint`: Lints TypeScript and TypeScript React files, ensuring adherence to coding standards.

-`npm run lint:fix`: Automatically corrects detectable linting discrepancies within the source.

-`npm run preview`: Provides a Vite-powered preview, offering a glance at the build output.

-`npm run format`: Standardizes the source files' appearance using Prettier.

-`npm run test`: Runs Jest tests, verifying code integrity and behavior.
