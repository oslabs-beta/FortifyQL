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

// move all of the following types and interfaces to a TS file
// also can some of them be removed they seem duplicative
type VulnerabilityType = {
  generateQueries: RequestHandler;
  attack: RequestHandler;
};

interface Schema {
  __schema: {
    types: GraphQLType[];
    queryType?: { name: string };
    mutationType?: { name: string };
  };
}
interface GraphQLType {
  name: string;
  kind: string;
  fields?: GraphQLField[];
}
interface GraphQLField {
  name: string;
  args?: GraphQLArgs[];
  type: GraphQLTypeReference;
  fields?: GraphQLField;
}
interface GraphQLArgs {
  name: string;
  type?: GraphQLTypeReference;
}
interface GraphQLTypeReference {
  kind: string;
  name?: string;
  ofType?: GraphQLTypeReference;
  fields?: GraphQLField[];
}

export const verboseError: VulnerabilityType = {
  // method for generating queries that trigger an error response by purposefully creating a typo
  generateQueries: async (req: Request, res: Response, next: NextFunction) => {
    console.log('Generating Queries for verbose...');

    // types is an array of objects retrieved from getSchema and includes all of the query, mutation, and subscription types
    const schemaTypes: GraphQLType[] = res.locals.schema.data.__schema.types;

    // function to extract field name based on query type.
    const getBaseType = (type: GraphQLTypeReference): string => {
      let curr = type;
      while (curr.ofType) {
        curr = curr.ofType;
      }
      return curr.name || '';
    };

    // function to extract the subfields which are the fields expected in the response from the GraphQL server
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
        .join('s ')} }`;
    };

    // function to build queries with queryName (i.e., query or mutation), field name, and subfields which are part of the response.
    const generateQuery = (field: GraphQLField, QueryType: string) => {
      const queryName = QueryType === 'queryType' ? 'query' : 'mutation';
      const baseTypeName = field.type ? getBaseType(field.type) : '';
      const baseType = schemaTypes.find((type) => type.name === baseTypeName);
      const subFields = baseType ? getSubFields(baseType) : '';

      return `${queryName} { ${field.name} ${subFields} }`;
    };

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
        const query = generateQuery(field, typeName);
        arrOfQueries.push(query);
      }
    }
    res.locals.queries = arrOfQueries;
    // console.log('Generated Queries...');
    // console.log(arrOfQueries);
    return next();
  },
  attack: async (req: Request, res: Response, _next: NextFunction) => {
    // console.log('Sending Queries...');

    // Move this to TS file
    interface QueryResult {
      id: string;
      status: string;
      title: string;
      description: string;
      severity: string | number;
      testDuration: string | number;
      lastDetected: string | number;
    }

    const result: QueryResult[] = [];
    const API: string = req.body.API;
    let ID: number = 1;

    // Think about logic of the query result and how we define each variable, should we summarize and use accordion? The send req could be modularized.
    const sendReqAndEvaluate = async (query: string) => {
      try {
        const queryResult: QueryResult = {
          id: `VE-${ID++}`,
          status: 'Pass',
          title: 'Verbose Error',
          description: '',
          severity: 'P1',
          testDuration: '',
          lastDetected: '',
        };

        const sendTime = Date.now(); // checks for the time to send and receive respsonse from GraphQL API

        const data = await fetch(API, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/graphql',
          },
          body: query,
        }).catch((err) => console.log(err));

        if (!data) return; // is this line necessary?

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
      }
    };
    const arrofQueries = res.locals.queries;
    for (const query of arrofQueries) {
      await sendReqAndEvaluate(query);
    }
    res.status(200).json(result);
  },
};
