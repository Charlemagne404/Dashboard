const js = require('@eslint/js');
const globals = require('globals');

module.exports = [js.configs.recommended, {
  files: ['**/*.js', '**/*.cjs'],
  languageOptions: { ecmaVersion: 2022, sourceType: 'commonjs', globals: { ...globals.node } },
  rules: {
    'no-unused-vars': ['error', { argsIgnorePattern: '^_', caughtErrors: 'none' }],
    'no-eval': 'error', 'no-implied-eval': 'error', 'no-new-func': 'error',
    'no-prototype-builtins': 'error',
  },
}, { ignores: ['node_modules/**'] }];
