/**
 * ************************************
 *
 * @module  batching.ts
 * @author  MADR Productions - AY
 * @date    9-25-23
 * @description middleware for server.use('/injection') to generate and send queries to test for SQL injection and evaluate response
 *
 * ************************************
 */

import { Request, Response, NextFunction, RequestHandler } from 'express';
import { BatchingType, GraphQLType, GraphQLField, GraphQLArgs, GraphQLTypeReference, QueryResult } from './types';

//remove arguments
//2 types
//identical queries ~10
//grab sub fields without arguments
//multiple resource intensive
//grab subfields with a specified depth

export const batching: BatchingType = {
  generateQueries: async (req: Request, res: Response, next: NextFunction) => {
    console.log('Generating SQL Injection Queries...');
    // const schema: Schema = res.locals.schema.data;
    const schemaTypes: GraphQLType[] = res.locals.schema.data.__schema.types;

    const getBaseType = (type: GraphQLTypeReference): string => {
      let curr = type;
      while (curr.ofType) {
        curr = curr.ofType;
      }
      return curr.name || '';
    };

    const getSubFields = (
      type: GraphQLType | GraphQLTypeReference,
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

    const generateQuery = (field: GraphQLField, QueryType: string) => {
      const queryName = QueryType === 'queryType' ? 'query' : 'mutation';

      const baseTypeName = field.type ? getBaseType(field.type) : '';
      const baseType = schemaTypes.find((type) => type.name === baseTypeName);
      const subFields = baseType ? getSubFields(baseType) : '';

      return `${queryName} { ${field.name} ${subFields} }`;
    };

    /*
    Generates a nested GraphQL query string for selecting subfields
    of a given GraphQL type up to a specified maximum depth.
    */
    const getSubFieldsNested = (
      type: GraphQLType | GraphQLTypeReference,
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
            ? getSubFieldsNested(baseType, depth + 1, maxDepth)
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

    const generateQueryNested = (field: GraphQLField, QueryType: string) => {
      const queryName = QueryType === 'queryType' ? 'query' : 'mutation';

      const baseTypeName = field.type ? getBaseType(field.type) : '';
      const baseType = schemaTypes.find((type) => type.name === baseTypeName);
      const subFields = baseType ? getSubFieldsNested(baseType) : '';

      return `${queryName} { ${field.name} ${subFields} }`;
    };

    const arrOfQueries: (string | string[])[] = [];
    const arrOfNested: string[] = [];

    for (const typeName of ['queryType', 'mutationType']) {
      const name: string | null =
        res.locals.schema.data.__schema[typeName]?.name;
      if (!name) continue;

      const types: GraphQLType | undefined = schemaTypes.find(
        (type) => type.name === name,
      );
      if (!types?.fields) continue;

      for (const field of types.fields) {
        const singularQuery: string = generateQuery(field, typeName);
        const identicalQuery: string[] = new Array(10).fill(singularQuery);
        arrOfQueries.push(identicalQuery);
        const nestedQuery = generateQueryNested(field, typeName);
        arrOfNested.push(nestedQuery);
      }
    }
    arrOfQueries.push(arrOfNested);
    res.locals.batchingQueries = arrOfQueries;
    console.log('Generated Batching Queries...');
    return;
  },
  attack: async (req: Request, res: Response): Promise<QueryResult[]> => {
    console.log('Sending Batching Queries...');

    const results: QueryResult[] = [];
    const API: string = req.body.API;
    let ID: number = 1;

    const errorResult = {
      id: `BATCH-${ID++}`,
      status: 'Error',
      title: 'Failed Test',
      query: '',
      description: `Error occured`,
      severity: 'P1',
      testDuration: '',
      lastDetected: `${new Date().toLocaleTimeString('en-GB')} - ${new Date()
        .toLocaleDateString('en-GB')
        .split('/')
        .reverse()
        .join('-')}`,
    };

    const titles = {
      identical: 'Multiple Identical Queries',
      exhaustive: 'Resource Exhaustive and Nested',
    };

    const sendReqAndEvaluate = async (query: string): Promise<QueryResult> => {
      const queryResult: QueryResult = {
        id: `BATCH-${ID++}`,
        status: 'Pass',
        title: '',
        query: query,
        description: '',
        severity: 'P1',
        testDuration: '',
        lastDetected: '',
      };

      try {
        const sendTime = Date.now();

        const data = await fetch(API, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/graphql',
          },
          body: query,
        }).catch((err) => console.log(err));

        if (!data) {
          return errorResult;
        }

        const response = await data.json();
        const timeTaken = Date.now() - sendTime;
        queryResult.description = query;
        queryResult.testDuration = `${timeTaken} ms`;
        queryResult.lastDetected = `${new Date().toLocaleTimeString(
          'en-GB',
        )} - ${new Date()
          .toLocaleDateString('en-GB')
          .split('/')
          .reverse()
          .join('-')}`;

        //logic here
        //check if identical or exhaustive- then change title
        //check if vulnerable- change status
        //depending on vulnerability- change description
        //checks would be:
        //if data is returned
        //if certain key words in the error leak info
        //time based- they are processing the query
        if (query[0] === query[1]) {
          queryResult.title = titles.identical;
        } else {
          queryResult.title = titles.exhaustive;
        }
        //first check if data is given
        //status fail
        //check if error exist
        //make an arr of key words
        //loop through array and evaluate messages for key words
        //fail

        if (response.data) {
          queryResult.status = 'Fail';
          queryResult.description =
            'Batching enabled, Rate Limiting Not Found';
        }
        if (response.errors) {
          const batchingErrorKeywords: string[] = [
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
          if (
            response.errors.some((error: { message: string }) =>
              batchingErrorKeywords.some((keyword) =>
                error.message.toLowerCase().includes(keyword),
              ),
            )
          ) {
            queryResult.status = 'Fail';
            queryResult.description = 'Potential Exposure of Sensitive Information Through Error Message';
          }
        }
        return queryResult
      } catch (err) {
        console.log(err);
        return errorResult;
      }
    };
    const arrofQueries: string[] = res.locals.batchingQueries;

    for (const query of arrofQueries) {
      try {
        const result = await sendReqAndEvaluate(query);
        results.push(result);
      } catch (err) {
        console.log(err);
        results.push(errorResult);
      }
    }
    return results;
  },
};
