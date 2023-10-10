/**
 * ************************************
 *
 * @module  bashing.ts
 * @author  MADR Productions - AY
 * @date    9-25-23
 * @description middleware for server.use('/injection') to generate and send queries to test for SQL injection and evaluate response
 *
 * ************************************
 */

import { Request, Response, NextFunction, RequestHandler } from 'express';

//remove arguments 
//2 types 
  //identical queries ~10 
    //grab sub fields without arguments
  //multiple resource intensive 
    //grab subfields with a specified depth 



type BatchingType = {
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
interface QueryResult {
  id: string;
  status: string;
  title: string;
  description: string;
  severity: string | number;
  testDuration: string | number;
  lastDetected: string | number;
}

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

    const generateQuery = (
      field: GraphQLField,
      QueryType: string,
    ) => {
      const queryName = QueryType === 'queryType' ? 'query' : 'mutation';

      const baseTypeName = field.type ? getBaseType(field.type) : '';
      const baseType = schemaTypes.find((type) => type.name === baseTypeName);
      const subFields = baseType ? getSubFields(baseType) : '';

      return `${queryName} { ${field.name} ${subFields} }`;
    };

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
          
            const query = generateQuery(field, typeName);
            arrOfQueries.push(query);
        
      }
    }
    res.locals.bashingQueries = arrOfQueries;
    console.log('Generated Queries...');
    console.log(arrOfQueries)
    return;
  },
  attack: async (req: Request, res: Response): Promise<QueryResult[]>  => {
    console.log('Sending SQL Injections...');

    const results: QueryResult[] = [];
    const API: string = req.body.API;
    let ID: number = 1;

    const errorResult = {
      id: `Inj-${ID++}`,
      status: 'Error',
      title: 'Failed Test',
      description: `Error occured`,
      severity: 'P1',
      testDuration: '',
      lastDetected: `${new Date().toLocaleTimeString('en-GB')} - ${new Date().toLocaleDateString('en-GB').split('/').reverse().join('-')}`,
    };
    const titles = {
      booleanBased: 'Boolean Based SQL Injection',
      errorBased: 'Error Based SQL Injection',
      timeBased: 'Time-Based Blind SQL Injection',
    };
    const sendReqAndEvaluate = async (query: string): Promise<QueryResult> => {
      const queryResult: QueryResult = {
        id: `Inj-${ID++}`,
        status: 'Pass',
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
        queryResult.description = query;
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
              if (response.data && response.data.length > 1)
              queryResult.status = 'Fail';
          } else if (
            query.includes("'") ||
            query.includes(';') ||
            query.includes('--')
            ) {
              const sqlErrorKeywords = [
                'syntax error',
                'unexpected',
                'mysql_fetch',
                'invalid query',
              ];
              queryResult.title = titles.errorBased;
              if (
                response.errors &&
                response.errors.some((error: { message: string }) =>
                sqlErrorKeywords.some((keyword) =>
                error.message.toLowerCase().includes(keyword),
                ),
                )
                ) {
                  queryResult.status = 'Fail';
                }
              } else if (query.toLowerCase().includes('sleep')) {
                queryResult.title = titles.timeBased;
                if (timeTaken > 5000) queryResult.status = 'Fail';
              }
              console.log(response)
              return queryResult;
            } catch (err) {
              console.log(err);
              return errorResult;
            }
          };
          const arrofQueries: string[] = res.locals.SQLQueries;

          for(const query of arrofQueries) {
            try {
              const result = await sendReqAndEvaluate(query);
              results.push(result);
            }catch(err) {
              console.log(err);
              results.push(errorResult);
            }
    }
    return results;
  },
};