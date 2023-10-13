FortifyQL is a sophisticated security scanning tool designed to provide developers with deep insights into potential security vulnerabilities within their GraphQL API's. FortifyQL dynamically generates queries that emulate common attacks identified by the Open Web Application Security Project (OWASP). The responses are analyzed for insecure default configurations and missing security measures that may lead to Injection, Denial of Service (DOS), and Batching attacks. The data is displayed within an intuitive and user-friendly interface, making it accessible to developers of all skill levels.

Let's further explore FortifyQL's initial robust test suites. 

• SQL Injection (Boolean, Error, and Time-based): These tests check for vulnerabilities in different types of database systems, using various injection techniques to expose weaknesses.

• Denial of Service (DoS: Circular): This test simulates a circular DoS-type attack, rendering a system unresponsive through excessive resource consumption.

• Batching (Multiple Queries and Resource Exhaustive/Nested): Batching and nesting tests aim to uncover resource exhaustion and complex operations that could harm your server.

• Verbose Error: This test identifies security misconfigurations by exposing excessive system information.

# React + TypeScript + Vite

This template provides a minimal setup to get React working in Vite with HMR and some ESLint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react/README.md) uses [Babel](https://babeljs.io/) for Fast Refresh
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react-swc) uses [SWC](https://swc.rs/) for Fast Refresh

## Expanding the ESLint configuration

If you are developing a production application, we recommend updating the configuration to enable type aware lint rules:

- Configure the top-level `parserOptions` property like this:

```js
   parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    project: ['./tsconfig.json', './tsconfig.node.json'],
    tsconfigRootDir: __dirname,
   },
```

- Replace `plugin:@typescript-eslint/recommended` to `plugin:@typescript-eslint/recommended-type-checked` or `plugin:@typescript-eslint/strict-type-checked`
- Optionally add `plugin:@typescript-eslint/stylistic-type-checked`
- Install [eslint-plugin-react](https://github.com/jsx-eslint/eslint-plugin-react) and add `plugin:react/recommended` & `plugin:react/jsx-runtime` to the `extends` list
