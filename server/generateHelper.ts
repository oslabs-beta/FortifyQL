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
export const generateQuery = (
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