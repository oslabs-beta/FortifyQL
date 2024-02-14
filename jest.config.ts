export default {
  "transform": {
    "^.+\\.(ts|tsx)$": "ts-jest",
    "^.+\\.(js|jsx)$": "babel-jest"
  },
  "testEnvironment": "jest-environment-jsdom",
  "setupFiles": ["<rootDir>/test/__mocks__/text-encoder.mock.ts"],
  "moduleNameMapper": {
    "\\.(gif|ttf|eot|svg|png)$": "<rootDir>/test/__mocks__/fileMock.js",
    "\\.(css|less|sass|scss)$": "identity-obj-proxy"
  },
  "testPathIgnorePatterns": ["<rootDir>/src/__tests__/mocks/"]
}