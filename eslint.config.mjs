import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ignores: ['node_modules/'],
  },
  js.configs.recommended,
  {
    files: ['**/*.js', '**/*.cjs'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: { ...globals.node },
    },
    rules: {
      'no-unused-vars': ['error', { args: 'none', caughtErrors: 'none' }],
    },
  },
  {
    // ACP client module, loaded by NodeBB in the browser through require.js
    files: ['static/lib/**/*.js'],
    languageOptions: {
      sourceType: 'script',
      globals: { ...globals.browser, define: 'readonly', $: 'readonly', socket: 'readonly' },
    },
  },
];
