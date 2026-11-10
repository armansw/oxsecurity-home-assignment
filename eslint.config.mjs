// @ts-check
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

/**
 * The assignment forbids fs.readFile and JSON.parse on scan results.
 * We go further and forbid them across the whole backend, so compliance is enforced by CI
 * rather than promised in a README.
 */
const forbiddenMemoryApis = {
  'no-restricted-syntax': [
    'error',
    {
      selector: "CallExpression[callee.object.name='JSON'][callee.property.name='parse']",
      message: 'Forbidden: scan data must be stream-parsed (see docs/MEMORY.md).',
    },
    {
      selector: 'CallExpression[callee.property.name=/^readFile(Sync)?$/]',
      message: 'Forbidden: read files with streams (see docs/MEMORY.md).',
    },
    {
      selector: 'CallExpression[callee.name=/^readFile(Sync)?$/]',
      message: 'Forbidden: read files with streams (see docs/MEMORY.md).',
    },
  ],
  'no-restricted-imports': [
    'error',
    {
      paths: [
        { name: 'node:fs', importNames: ['readFile', 'readFileSync'], message: 'Use streams.' },
        { name: 'fs', importNames: ['readFile', 'readFileSync'], message: 'Use streams.' },
        { name: 'node:fs/promises', importNames: ['readFile'], message: 'Use streams.' },
        { name: 'fs/promises', importNames: ['readFile'], message: 'Use streams.' },
      ],
    },
  ],
};

export default tseslint.config(
  { ignores: ['dist/**', 'coverage/**', 'node_modules/**', 'web/**', 'eslint.config.mjs'] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/explicit-module-boundary-types': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
      '@typescript-eslint/no-floating-promises': 'error',
      ...forbiddenMemoryApis,
    },
  },
  {
    // Tests may build fixtures by hand, but still never JSON.parse scan output: they assert via
    // the same streaming paths (or test helpers that parse small HTTP bodies).
    files: ['test/**/*.ts', 'vitest.config.ts'],
    rules: {
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
    },
  },
);
