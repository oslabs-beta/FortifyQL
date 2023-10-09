/**
 * ************************************
 *
 * @module  verboseError.ts
 * @author  MADR Productions - RP
 * @date    9-28-23
 * @description middleware for server.use('/error') to generate and send queries to trigger an error and evaluate response for verbosity (a security vulnerability in GraphQL APIs)
 *
 * ************************************
 */

import { Request, Response, NextFunction, RequestHandler } from 'express';
import { VerboseType, GraphQLType, GraphQLField, GraphQLArgs, GraphQLTypeReference, QueryResult } from './types';
import {
  getBaseType,
  generateBatchQuery,
  getSubFieldsNested,
  generateQueryNested,
} from './generateHelper.ts';
import { generateVerboseQuery } from './generateHelper.ts';
import { createQueryResult, createErrorResult } from './query.ts';

// move all of the following types and interfaces to a TS file
// also can some of them be removed they seem duplicative


export const verboseError: VerboseType = {
  // method for generating queries that trigger an error response by purposefully creating a typo
  generateQueries: async (req: Request, res: Response) => {
    console.log('Generating Queries for verbose...');

    // types is an array of objects retrieved from getSchema and includes all of the query, mutation, and subscription types
    const schemaTypes: GraphQLType[] = res.locals.schema.data.__schema.types;

    const arrOfQueries: string[] = [];

    // Identifies the naming convention for queryType and mutationType
    // For example, DVGA calls them "Query" and "Mutations."
    // Then look for the object with the name "Query" and check for fields.
    // Fields represent the names of the different Queries.
    // For example, the Query fields for DVGA include "pastes", "paste", "users"
    // Args are opportunities for client input to filter data or mutate data.
    for (const typeName of ['queryType', 'mutationType']) {
      const name: string | null =
        res.locals.schema.data.__schema[typeName]?.name;
      if (!name) continue;

      const types: GraphQLType | undefined = schemaTypes.find(
        (type) => type.name === name,
      );
      if (!types?.fields) continue;

      for (const field of types.fields) {
        const query = generateVerboseQuery(field, typeName, schemaTypes);
        arrOfQueries.push(query);
      }
    }
    res.locals.queries = arrOfQueries;
    console.log('Generated Verbose Queries...');
    return;
  },
  attack: async (req: Request, res: Response, _next: NextFunction) => {
    // console.log('Sending Queries...');

    const result: QueryResult[] = [];
    const API: string = req.body.API;
    let ID: number = 1;

    // Think about logic of the query result and how we define each variable, should we summarize and use accordion? The send req could be modularized.
    const sendReqAndEvaluate = async (query: string) => {
      const queryResult = createQueryResult('VE', query, ID);
      const errorResult = createErrorResult('VE', query, ID);
      ID++;
      try {

        const sendTime = Date.now(); // checks for the time to send and receive respsonse from GraphQL API

        const data = await fetch(API, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/graphql',
          },
          body: query,
        }).catch((err) => console.log(err));

        if (!data) return errorResult; 

        const response = await data.json();
        const timeTaken = Date.now() - sendTime;
        queryResult.description = query;
        queryResult.testDuration = `${timeTaken} ms`;

        // Currently, pass/fail is based on error message length, but we could also look at "Did you mean..." to see if the response includes sugggested fields
        if (response.errors) {
          response.errors[0].message.length > 50
            ? (queryResult.status = 'Fail')
            : (queryResult.status = 'Pass');
        }
        result.push(queryResult);
        // result.push(response); - This is the response from the server but it is not currently used by the client
      } catch (err) {
        console.log(err);
        return errorResult;
      }
    };
    const arrofQueries = res.locals.queries;
    for (const query of arrofQueries) {
      await sendReqAndEvaluate(query);
    }
    return result;
  },
};
