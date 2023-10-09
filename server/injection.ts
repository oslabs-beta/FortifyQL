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
import { InjectionType, GraphQLType, GraphQLField, GraphQLArgs, GraphQLTypeReference, QueryResult } from './types';
import { getBaseType, getSubFields, generateQuery } from './generateHelper.ts';
import { SQLInputs } from './inputs.ts';

export const injection: InjectionType = {
  generateQueries: async (req: Request, res: Response, next: NextFunction) => {
    console.log('Generating SQL Injection Queries...');
    // const schema: Schema = res.locals.schema.data;
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
            const query = generateQuery(field, input, typeName, schemaTypes);
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

    const titles = {
      booleanBased: 'Boolean Based SQL Injection',
      errorBased: 'Error Based SQL Injection',
      timeBased: 'Time-Based Blind SQL Injection',
    };
    const errorResult = {
      id: `Inj-${ID++}`,
      status: 'Error',
      query: 'Request errored out',
      title: 'Failed Test',
      description: `Error occured`,
      severity: 'P1',
      testDuration: '',
      lastDetected: `${new Date().toLocaleTimeString('en-GB')} - ${new Date()
        .toLocaleDateString('en-GB')
        .split('/')
        .reverse()
        .join('-')}`,
    };
    const sendReqAndEvaluate = async (query: string): Promise<QueryResult> => {
      const queryResult: QueryResult = {
        id: `Inj-${ID++}`,
        status: 'Pass',
        query: query,
        title: '',
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
        queryResult.testDuration = `${timeTaken} ms`;
        queryResult.lastDetected = `${new Date().toLocaleTimeString(
          'en-GB',
        )} - ${new Date()
          .toLocaleDateString('en-GB')
          .split('/')
          .reverse()
          .join('-')}`;

        if (query.includes('OR 1=1') || query.includes("'1'='1")) {
          queryResult.title = titles.booleanBased;
        } else if (
          query.includes("'") ||
          query.includes(';') ||
          query.includes('--')
        ) {
          queryResult.title = titles.errorBased;
        } else if (query.toLowerCase().includes('sleep')) {
          queryResult.title = titles.timeBased;
        }

        if (response.data && response.data.length > 1) {
          queryResult.status = 'Fail';
          queryResult.description = 'Potentially Excessive/Sensitive Information Given';
        }
        const sqlErrorKeywords = [
          'syntax error',
          'unexpected',
          'mysql_fetch',
          'invalid query',
        ];
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
