/**
 * ************************************
 *
 * @module  circularQuery.ts
 * @author  MADR Productions - MK & RP
 * @date    10-05-23
 * @description searches for circular references within the object types in the schema, generates and executes circular queries when found, and returns a pass or fail depending on if the number of nested relationships exceeds the maximum allowable depth
 *
 * ************************************
 */
import { Request, Response, NextFunction, RequestHandler } from 'express';

type VulnerabilityType = {
  generateQueries: RequestHandler;
  attack: RequestHandler;
};
interface GraphQLType {
  name: string;
  kind: string;
  fields?: GraphQLField[];
}
interface GraphQLField {
  name: string;
  args?: GraphQLArgs[];
  type: GraphQLTypeReference;
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

// Helper function that searches for circular references within the schema
export const circularQuery: VulnerabilityType = {
  generateQueries: async (req: Request, res: Response, next: NextFunction) => {
    console.log('Generating circular queries...');
    // Retrieves all the operation types "Query, Mutation, Subscription" in the schema
    const schemaTypes: GraphQLType[] = res.locals.schema.data.__schema.types;
    let field_1_name: string = '';
    let field_2_name: string = '';
    let scalar_name: string = '';
    let firstObjName: string = '';
    let objTypeName: string = '';
    const queries: unknown[] = [];
    const allRelationships: unknown[] = []; // contains all circularly referenced field names along with one scalar field to end the loop

    const findCircularRelationship = (): void => {
      // Filter out objects that are query, mutation, and subscription types
      const customNameTypes = schemaTypes.filter(
        (object) =>
          object.name !== 'Query' &&
          object.name !== 'Mutations' &&
          object.name !== 'Subscription' &&
          object.kind === 'OBJECT',
      );

      console.log('CustomNameTypes: ', customNameTypes);

      // Iterate over customNameType objects to find an oject with a field that is also a customNameType object
      for (let i = 0; i < customNameTypes.length; i++) {
        const fields = customNameTypes[i].fields; // array of objects
        console.log('fields: ', fields);
        if (firstObjName === '') {
          console.log('-----------> In the first field object <-----------');
          fields?.forEach((field) => {
            if (
              field.type?.kind === 'OBJECT' ||
              field.type.ofType?.kind! === 'OBJECT'
            ) {
              firstObjName = customNameTypes[i].name; // PasteObject
              console.log('firstObjName: ', firstObjName);
              // objTypeName = field.type.ofType?.name!; // OwnerObject
              field.type.name !== null
                ? (objTypeName = field.type?.name!) // OwnerObject
                : (objTypeName = field.type.ofType?.name!);
              console.log('objTypeName: ', objTypeName);
              field_1_name = field.name; // owner
              console.log('field_1_name', field_1_name);
            }
          });
        } else if (customNameTypes[i].name === objTypeName) {
          const fields2 = customNameTypes[i].fields;
          fields2?.forEach((field) => {
            if (field.type.ofType?.kind === 'SCALAR' && scalar_name === '') {
              scalar_name = field.name;
            }
            if (
              field.type.ofType?.kind === 'OBJECT' &&
              field.type.ofType?.name === firstObjName
            ) {
              console.log('---------> In the second field object <----------');
              field_2_name = field.name;
              console.log('field_2_name', field_2_name);
              return;
            }
          });
        }
      }
      console.log('names: ', field_1_name, field_2_name, scalar_name);
      if (field_1_name !== '' && field_2_name !== '') {
        buildQuery(field_1_name, field_2_name, scalar_name);
      }
    };

    const buildQuery = (
      field_1: string,
      field_2: string,
      scalar: string,
    ): void => {
      const FIELD_REPEAT = 10;
      let query = 'query {';
      let count = 0;

      for (let i = 0; i < FIELD_REPEAT; i++) {
        count++;
        const closing_braces = '}'.repeat(FIELD_REPEAT * 2) + '}';
        const payload = `${field_2} { ${field_1} { `;
        query += payload;

        if (count === FIELD_REPEAT) {
          query += scalar + closing_braces;
        }
      }
      console.log(query);
      queries.push(query);
    };

    findCircularRelationship();

    res.locals.queries = queries;
    console.log('Queries: ', res.locals.queries);
    return;
  },
  attack: async (req: Request, res: Response, _next: NextFunction) => {
    console.log('Sending Queries...');

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

    const sendReqAndEvaluate = async (query: string) => {
      try {
        const queryResult: QueryResult = {
          id: `DoS-${ID++}`,
          status: 'Pass',
          title: 'Circular Query',
          description: '',
          severity: 'N/A',
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

        // Currently, pass/fail is based on response data but also need to look at timeout?
        if (response.data) {
          queryResult.status = 'Fail';
        }
        result.push(queryResult);
        console.log(response); // This is the response from the server but it is not currently used by the client
      } catch (err) {
        console.log(err);
      }
    };
    const arrofQueries = res.locals.queries;

    // Check to see if there are any circular references
    if (arrofQueries.length === 0) {
      result.push({
        id: `DoS-${ID++}`,
        status: 'Pass',
        title: 'Circular Query',
        description: 'No circular references found.',
        severity: 'N/A',
        testDuration: 'O ms',
        lastDetected: `${new Date().toLocaleTimeString('en-GB')} - ${new Date()
          .toLocaleDateString('en-GB')
          .split('/')
          .reverse()
          .join('-')}`,
      });
    } else {
      for (const query of arrofQueries) {
        await sendReqAndEvaluate(query);
      }
    }
    return result;
  },
};
