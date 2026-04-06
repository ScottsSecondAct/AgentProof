/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/__tests__/**/*.test.ts'],
  globals: {
    'ts-jest': {
      tsconfig: {
        // Allow rootDir to include both js/ and __tests__/ during test runs.
        rootDir: '.',
      },
    },
  },
};
