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
    const field_1_name: string = '';
    const field_2_name: string = '';
    const scalar_name: string = '';
    const firstObjName: string = '';
    const objTypeName: string = '';
    const queries: unknown[] = [];
    const allRelationships: unknown[] = []; // contains all circularly referenced field names along with one scalar field to end the loop

    // Check if mutationType and subscriptionType exist in the schema
    const queryTypeName = res.locals.schema.data.__schema.queryType?.name;
    const mutationTypeName = res.locals.schema.data.__schema.mutationType?.name;
    const subscriptionTypeName =
      res.locals.schema.data.__schema.subscriptionType?.name;

    const queryTypeObject = schemaTypes.filter(
      (object) => object.name === queryTypeName,
    );
    const queryTypeFields = queryTypeObject[0].fields;

    const interfaceObject = queryTypeFields?.filter(
      (object) => object.type.kind === 'INTERFACE',
    );

    let interfaceTypeName: string = '';

    if (interfaceObject?.length !== 0) {
      interfaceTypeName = interfaceObject![0].name;
    }

    // Create an array of type names to exclude
    const excludedTypeNames = [
      queryTypeName,
      mutationTypeName,
      subscriptionTypeName,
    ].filter((name) => name); // Filter out null values

    // Filter out objects that are query, mutation, and subscription types
    const customNameTypes = schemaTypes.filter(
      (object) =>
        !excludedTypeNames.includes(object.name) &&
        object.name[0] !== '_' &&
        object.kind === 'OBJECT',
    );

    const circularRefs: Set<string> = new Set();

    function addUniqueTuple(tuple: [string, string, string]): void {
      const tupleString = JSON.stringify(tuple);
      circularRefs.add(tupleString);
    }
    const findCircularRelationships = (
      nameType: any,
    ): [string, string, string][] => {
      let primFieldName: string = '';
      let secFieldName: string = '';
      let scalarName: string = '';

      const traverseFields = (
        typeName: string,
        fields: GraphQLField[] | undefined,
        visitedFields: Set<string>,
      ) => {
        if (
          visitedFields.has(typeName!) &&
          primFieldName !== '' &&
          secFieldName !== '' &&
          scalarName !== ''
        ) {
          addUniqueTuple([primFieldName, secFieldName, scalarName]);
          return circularRefs;
        }
        visitedFields.add(typeName);
        fields?.forEach((field) => {
          const fieldType = field.type.ofType || field.type;
          if (field.name === interfaceTypeName) return;

          if (fieldType?.kind === 'OBJECT') {
            const foundQueryType = queryTypeFields?.find(
              (obj) => obj.name === field.name,
            );
            if (foundQueryType !== undefined) {
              primFieldName = field.name;
            } else {
              secFieldName = field.name;
              // Find a scalar field on the second object
              const circularType = nameType.find(
                (t: any) => t.name === fieldType.name,
              );
              const scalarField = circularType?.fields.find(
                (f: GraphQLField) => f.type.kind === 'SCALAR',
              );
              if (scalarField) {
                scalarName = scalarField.name;
              }
            }
            traverseFields(
              fieldType.name!,
              nameType.find((t: any) => t.name === fieldType.name)?.fields,
              new Set<string>(visitedFields),
            );
          }
        });
      };

      customNameTypes.forEach((customType) => {
        traverseFields(customType.name, customType.fields, new Set<string>());
      });

      const uniqueTuples: [string, string, string][] = Array.from(
        circularRefs,
        (tupleString) => JSON.parse(tupleString),
      );
      return uniqueTuples;
    };

    const circularReferences = findCircularRelationships(customNameTypes);

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
        const closingBraces = '}'.repeat(FIELD_REPEAT * 2) + '}';
        const payload = `${field_1} { ${field_2} { `;
        query += payload;

        if (count === FIELD_REPEAT) {
          query += scalar + closingBraces;
        }
      }
      queries.push(query);
    };

    for (const array of circularReferences) {
      buildQuery(array[0], array[1], array[2]);
    }

    res.locals.queries = queries;
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
        if (response.errors) {
          queryResult.status = 'Pass';
        } else if (response.data) {
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
