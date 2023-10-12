/**
 * Prettify a JSON object by converting it to a pretty-printed JSON string
 * @param json - JSON object to be prettified
 * @returns A string containing the pretty-printed JSON representation
 */
export const prettifyJson = (json: any): string => {
  return JSON.stringify(json, null, 2);
};

//
/**
 * Pretty-prints a GraphQL query by adding line breaks and indentation
 * @param query - Input GraphQL query string to be formatted
 * @returns A string containing the pretty-printed GraphQL query
 */
export const prettyPrintGraphQL = (query: string): string => {
  const indent = '  ';
  let level = 0;
  let prettyQuery = '';

  for (let i = 0; i < query.length; i++) {
    const char = query[i];

    if (char === '{') {
      prettyQuery += `{\n${indent.repeat(++level)}`;
    } else if (char === '}') {
      prettyQuery += `\n${indent.repeat(--level)}}`;
    } else {
      prettyQuery += char;
    }
  }

  return prettyQuery;
};
