export const SQLInputs = [
  // Boolean Based SQL Injection
  "' OR 1 = 1; --",
  "1' OR '1' = '1 /*",
  "admin' OR '1'='1'--",

  // Error Based SQL Injection
  "'",
  ';',
  '--',

  // Time-Based Blind SQL Injection
  '; SELECT SLEEP(15) --', // MySQL, MariaDB
  '; SELECT pg_sleep(15); --', // PostgreSQL
  "; IF (1=1) WAITFOR DELAY '00:00:15'--", // Another example for MySQL
];
export const sqlErrorKeywords = [
  'syntax error',
  'unexpected',
  'mysql_fetch',
  'invalid query',
];
export const batchingErrorKeywords: string[] = [
  'too many operations',
  'batch size exceeds',
  'operation limit',
  'query complexity exceeds',
  'rate limit exceeded',
  'throttle',
  'unauthorized batch request',
  'unexpected token',
  'batching not supported',
  'anonymous operation',
  'must be the only defined operation',
  'batch',
  'rate limit',
  'server error',
  'api limit exceeded',
];
export const verboseErrorKeywords: string[] = [
  'did you mean ',
  'syntax error graphql',
  'expected',
  'found',
  'is required',
  'not provided',
  'argument',
  'sub selection',
];
