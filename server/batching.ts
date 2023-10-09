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
import {
  BatchingType,
  GraphQLType,
  GraphQLField,
  GraphQLArgs,
  GraphQLTypeReference,
  QueryResult,
} from './types';
import {
  getBaseType,
  getSubFields,
  generateBatchQuery,
  getSubFieldsNested,
  generateQueryNested,
} from './generateHelper.ts';
import { createQueryResult, createErrorResult } from './query.ts';
import { batchTitles } from './titles.ts';
import { batchingErrorKeywords } from './inputsAndKeywords.ts';

export const batching: BatchingType = {
  generateQueries: async (req: Request, res: Response) => {
    console.log('Generating Batching Queries...');
    const schemaTypes: GraphQLType[] = res.locals.schema.data.__schema.types;

    /*
    Generates a nested GraphQL query string for selecting subfields
    of a given GraphQL type up to a specified maximum depth.
    */

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
        const singularQuery: string = generateBatchQuery(
          field,
          typeName,
          schemaTypes,
        );
        const identicalQuery: string[] = new Array(10).fill(singularQuery);
        arrOfQueries.push(identicalQuery);
        const nestedQuery = generateQueryNested(field, typeName, schemaTypes);
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

    const sendReqAndEvaluate = async (query: string): Promise<QueryResult> => {
      const queryResult = createQueryResult('INJ', query, ID);
      const errorResult = createErrorResult('INJ', query, ID);
      ID++;

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
        queryResult.testDuration = `${timeTaken} ms`;

        if (query[0] === query[1]) {
          queryResult.title = batchTitles.identical;
        } else {
          queryResult.title = batchTitles.exhaustive;
        }

        if (response.data) {
          queryResult.status = 'Fail';
          queryResult.description = 'Batching enabled, Rate Limiting Not Found';
        }
        if (response.errors) {
          if (
            response.errors.some((error: { message: string }) =>
              batchingErrorKeywords.some((keyword) =>
                error.message.toLowerCase().includes(keyword),
              ),
            )
          ) {
            queryResult.status = 'Fail';
            queryResult.description =
              'Potential Exposure of Sensitive Information Through Error Message';
          }
        }
        return queryResult;
      } catch (err) {
        console.log(err);
        return errorResult;
      }
    };
    const arrofQueries: string[] = res.locals.batchingQueries;

    for (const query of arrofQueries) {
        const result = await sendReqAndEvaluate(query);
        results.push(result);
    }
    return results;
  },
};
