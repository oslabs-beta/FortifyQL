/**
 * ************************************
 *
 * @module  injection.ts
 * @author  MADR Productions - AY
 * @date    9-25-23
 * @description middleware for server.use('/injection') to generate and send queries to test for SQL injection and evaluate response
 *
 * ************************************
 */

import { Request, Response, NextFunction, RequestHandler } from 'express';
import {
  InjectionType,
  GraphQLType,
  GraphQLField,
  GraphQLArgs,
  GraphQLTypeReference,
  QueryResult,
} from './types';
import {
  getBaseType,
  getSubFields,
  generateSQLQuery,
} from './generateHelper.ts';
import { SQLInputs, sqlErrorKeywords } from './inputsAndKeywords.ts';
import { SQLtitles } from './titles.ts';
import { createQueryResult, createErrorResult } from './query.ts';

export const injection: InjectionType = {
  generateQueries: async (req: Request, res: Response) => {
    console.log('Generating SQL Injection Queries...');
    const schemaTypes: GraphQLType[] = res.locals.schema.data.__schema.types;

    const arrOfQueries: string[] = [];

    for (const typeName of ['queryType', 'mutationType']) {
      const name: string | null =
        res.locals.schema.data.__schema[typeName]?.name;
      if (!name) continue;

      const types: GraphQLType | undefined = schemaTypes.find(
        (type) => type.name === name,
      );
      if (!types?.fields) continue;

      for (const field of types.fields) {
        if (
          !field.args ||
          field.args.some(
            (arg) => arg.type?.kind == 'SCALAR' && arg.type?.name === 'String',
          )
        ) {
          for (const input of SQLInputs) {
            const query = generateSQLQuery(field, input, typeName, schemaTypes);
            arrOfQueries.push(query);
          }
        }
      }
    }
    res.locals.SQLQueries = arrOfQueries;
    console.log('Generated Injection Queries...');
    return;
  },
  attack: async (req: Request, res: Response): Promise<QueryResult[]> => {
    console.log('Sending SQL Injections...');

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

        if (query.includes('OR 1=1') || query.includes("'1'='1")) {
          queryResult.title = SQLtitles.booleanBased;
        } else if (
          query.includes("'") ||
          query.includes(';') ||
          query.includes('--')
        ) {
          queryResult.title = SQLtitles.errorBased;
        } else if (query.toLowerCase().includes('sleep')) {
          queryResult.title = SQLtitles.timeBased;
        }

        if (response.data && response.data.length > 1) {
          queryResult.status = 'Fail';
          queryResult.description =
            'Potentially Excessive/Sensitive Information Given';
        }
  
        if (
          response.errors &&
          response.errors.some((error: { message: string }) =>
            sqlErrorKeywords.some((keyword) =>
              error.message.toLowerCase().includes(keyword),
            ),
          )
        ) {
          queryResult.status = 'Fail';
          queryResult.description =
            'Potential Exposure of Sensitive Information Through Error Message';
        }
        if (timeTaken > 5000) {
          queryResult.status = 'Fail';
          queryResult.description = 'Server Response Delayed Due to Injection';
        }
        return queryResult;
      } catch (err) {
        console.log(err);
        return errorResult;
      }
    };
    const arrofQueries: string[] = res.locals.SQLQueries;

    for (const query of arrofQueries) {
      const result = await sendReqAndEvaluate(query);
      results.push(result);
    }
    return results;
  },
};
