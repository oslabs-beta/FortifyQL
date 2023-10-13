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


