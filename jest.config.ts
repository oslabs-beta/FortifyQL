export default {
  testEnvironment: 'jest-environment-jsdom',
  setupFiles: ['<rootDir>/test/__mocks__/text-encoder.mock.ts'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest',
  },
  moduleNameMapper: {
    '\\.(gif|ttf|eot|svg|png)$': '<rootDir>/test/__mocks__/fileMock.js',
    '\\.(css|less|sassscss)$': 'identity-obj-proxy',
  },
};
