/**
 * Prettify a JSON object by converting it to a pretty-printed JSON string
 * @param json - JSON object to be prettified
 * @returns A string containing the pretty-printed JSON representation
 */
export const prettifyJson = (json: string): string => {
  return JSON.stringify(json, null, 2);
};

//
/**
 *
 * Pretty-print GraphQL batching queries by adding line breaks and indentation.
 * @param queries - An array of input GraphQL query strings to be formatted.
 * @returns A string containing the pretty-printed GraphQL queries.
 */
export const prettyPrintGraphQLBatch = (queries: string[]): string => {
  // Indentation string (two spaces)
  const indent = '  ';
  // Initialize the indentation level
  let level = 0;
  // Initialize the formatted query string
  let prettyQuery = '';
  // Function to add the current indentation
  function addIndent() {
    prettyQuery += `${indent.repeat(level)}`;
  }
  // Loop through each query in the array
  queries.forEach((query) => {
    // Loop through each character in the query
    for (let i = 0; i < query.length; i++) {
      const char = query[i];
      // When an opening curly brace is encountered, add a line break, increase the indentation level, and add the opening brace
      if (char === '{') {
        addIndent();
        prettyQuery += `{\n`;
        level++;
      }
      // When a closing curly brace is encountered, decrease the indentation level, add a line break, and then close the brace
      else if (char === '}') {
        level--;
        prettyQuery += `\n`;
        addIndent();
        prettyQuery += `}`;
      }
      // For all other characters, simply append them to the formatted query
      else {
        prettyQuery += char;
      }
    }
    // Add a separator line between queries in the batch
    prettyQuery += '\n\n';
  });
  // Remove trailing newlines
  prettyQuery = prettyQuery.trimEnd();
  // Return the formatted query
  return prettyQuery;
};

/**
 * Function to pretty-print a GraphQL query by adding line breaks and indentation.
 * @param queryId - Test ID that contains test type to determine what type of pretty print to format
 * @param query - The input GraphQL query string to be formatted.
 * @returns A string containing the pretty-printed GraphQL query.
 */

export const prettyPrintGraphQL = (
  queryId: string,
  query: string[] | string,
): string => {
  if (queryId.toLowerCase().includes('batch')) {
    return prettyPrintGraphQLBatch(query);
  }

  // Indentation string (two spaces)
  const indent = '  ';

  // Initialize the indentation level
  let level = 0;

  // Initialize the formatted query string
  let prettyQuery = '';

  // Loop through each character in the input query
  for (let i = 0; i < query.length; i++) {
    const char = query[i];

    // When an opening curly brace is encountered, add a line break and increase the indentation level
    if (char === '{') {
      prettyQuery += `{\n${indent.repeat(++level)}`;
    }
    // When a closing curly brace is encountered, add a line break and decrease the indentation level, then close the brace
    else if (char === '}') {
      prettyQuery += `\n${indent.repeat(--level)}}`;
    }
    // For all other characters, simply append them to the formatted query
    else {
      prettyQuery += char;
    }
  }

  // Return the formatted query
  return prettyQuery;
};
