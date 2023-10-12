/**
 * Prettify a JSON object by converting it to a pretty-printed JSON string
 * @param json - JSON object to be prettified
 * @returns A string containing the pretty-printed JSON representation
 */
export const prettifyJson = (json: any): string => {
  return JSON.stringify(json, null, 2);
};

/**
 * Pretty-prints a GraphQL query by adding line breaks and indentation
 * @param query - Input GraphQL query string to be formatted
 * @returns A string containing the pretty-printed GraphQL query
 */
export const prettyPrintGraphQL = (queries: string[]): string => {
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
