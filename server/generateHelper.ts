import { GraphQLType, GraphQLField, GraphQLArgs, GraphQLTypeReference, QueryResult } from './types';

export const getBaseType = (type: GraphQLTypeReference): string => {
    let curr = type;
    while (curr.ofType) {
      curr = curr.ofType;
    }
    return curr.name || '';
  };
export const getSubFields = (
    type: GraphQLType | GraphQLTypeReference,
    schemaTypes: GraphQLType[],
    depth: number = 0,
    maxDepth: number = 1,
  ): string => {
    if (!type.fields || depth > maxDepth) return '';
    return `{ ${type.fields
      .filter((field) => {
        const baseTypeName = getBaseType(field.type);
        const baseType = schemaTypes.find((t) => t.name === baseTypeName);
        return !baseType?.fields;
      })
      .map((field) => field.name)
      .join(' ')} }`;
  };
export const generateSQLQuery = (
    field: GraphQLField,
    input: string,
    QueryType: string,
    schemaTypes: GraphQLType[]
  ) => {
    const queryName = QueryType === 'queryType' ? 'query' : 'mutation';
    const args =
      field.args
        ?.filter(
          (arg) => arg.type?.kind === 'SCALAR' && arg.type?.name === 'String',
        )
        .map((arg) => `${arg.name}: "${input}"`)
        .join(', ') || '';

    const baseTypeName = field.type ? getBaseType(field.type) : '';
    const baseType = schemaTypes.find((type) => type.name === baseTypeName);
    const subFields = baseType ? getSubFields(baseType, schemaTypes) : '';

    return `${queryName} { ${field.name}(${args}) ${subFields} }`;
  };
  export const generateBatchQuery = (field: GraphQLField, QueryType: string, schemaTypes: GraphQLType[]) => {
    const queryName = QueryType === 'queryType' ? 'query' : 'mutation';

    const baseTypeName = field.type ? getBaseType(field.type) : '';
    const baseType = schemaTypes.find((type) => type.name === baseTypeName);
    const subFields = baseType ? getSubFields(baseType, schemaTypes) : '';

    return `${queryName} { ${field.name} ${subFields} }`;
  };
  export const getSubFieldsNested = (
    type: GraphQLType | GraphQLTypeReference,
    schemaTypes: GraphQLType[],
    depth: number = 0,
    maxDepth: number = 1,
  ): string => {
    // If the type has no fields or reached the maximum depth, return an empty string
    if (!type.fields || depth > maxDepth) return '';

    // Filter and concat valid subfields for the current type
    const validSubFields = type.fields
      .map((field) => {
        const baseTypeName = field.type ? getBaseType(field.type) : '';
        const baseType = schemaTypes.find((t) => t.name === baseTypeName);

        // If reached max depth, return the field name if it has no subfields,
        // otherwise, return an empty string
        if (depth === maxDepth) {
          return !baseType?.fields ? field.name : '';
        }

        // Recursively get subfields for the baseType and concat them
        const subFields = baseType
          ? getSubFieldsNested(baseType,schemaTypes, depth + 1, maxDepth)
          : '';

        return subFields ? `${field.name} ${subFields}` : '';
      })
      .filter(Boolean)
      .join(' ');

    // If there are no valid subfields, return an empty string
    if (!validSubFields) return '';

    // Return the selected subfields within curly braces as a GraphQL query string
    return `{ ${validSubFields} }`;
  };
  export const generateQueryNested = (field: GraphQLField, QueryType: string, schemaTypes: GraphQLType[]) => {
    const queryName = QueryType === 'queryType' ? 'query' : 'mutation';

    const baseTypeName = field.type ? getBaseType(field.type) : '';
    const baseType = schemaTypes.find((type) => type.name === baseTypeName);
    const subFields = baseType ? getSubFieldsNested(baseType, schemaTypes) : '';

    return `${queryName} { ${field.name} ${subFields} }`;
  };