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
    const allRelationships: string[] = []; // contains all circularly referenced field names

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
      // Iterate over the array of customNameType objects
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
                ? (objTypeName = field.type?.name!)
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
      console.log('names: ', field_1_name, field_2_name);
      // enter for loop
      // check if firstObjName is = '', if so then enter the if statement
      // if not check if customNameTypes = objTypeName if so then enter second if
      // otherwise continue to loop

      allRelationships.push(field_1_name, field_2_name);
      // return the field names to the generateQuery function
    };

    findCircularRelationship();
    const ARRAY_LENGTH = 5;
    const FIELD_REPEAT = 10;
    let query = 'query {';
    const first_field = `${field_1_name}`;
    const second_field = `${field_2_name}`;
    let count = 0;

    for (let i = 0; i < FIELD_REPEAT; i++) {
      count++;
      const closing_braces = '}'.repeat(FIELD_REPEAT * 2) + '}';
      const payload = `${second_field} { ${first_field} { `;
      query += payload;

      if (count === FIELD_REPEAT) {
        query += scalar_name + closing_braces;
      }
    }

    const queries = [];

    for (let i = 0; i < ARRAY_LENGTH; i++) {
      console.log(query);
      queries.push(query);
    }
    res.locals.queries = queries;
    return;
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
          id: `DoS-${ID++}`,
          status: 'Pass',
          title: 'Circular Query',
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

        // fetch('http://localhost:5013/graphql', {
        //   method: 'POST',
        //   headers: {
        //     'Content-Type': 'application/json',
        //   },
        //   body: JSON.stringify(res.locals.queries),
        // })
        //   .then((response) => response.json())
        //   .then((data) => {
        //     console.log(data);
        //     return data;
        //   })
        //   .catch((error) => console.error('Error:', error));

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
    for (const query of arrofQueries) {
      await sendReqAndEvaluate(query);
    }
    return result;
  },
};

//   try {
//     console.log('entered scan');
//     const API = req.body.API;
//     console.log('using this API', API);
//     const response = await fetch(API, {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/graphql',
//       },
//       body: query,
//     });
//     // type DataType = {
//     //   details: Record<string, any>;
//     // };
//     console.log('response: ', response);
//     //this part is in the works- figuring how to break them up with types/might get rid of ts
//     const obj: any = await response.json();
//     console.log('obj: ', obj.data);

//     res.sendStatus(200);
//   } catch (err) {
//     console.log('injectionAttack middleware', err);
//     res.status(400).json('Unable to submit query. An error occurred.');
//   }
// }
// };

// import { Request, Response, NextFunction, RequestHandler } from 'express';

// export const injection: InjectionType = {
//     generateQuery: async (req: Request, res: Response, _next: NextFunction) => {
//         const schemaTypes: GraphQLType[] = res.locals.schema.data.__schema.types;

//         const SQLInputs = [
//             "OR 1=1",
//             "' OR '1'='1",
//             "--",
//             "';--",
//             "') OR ('1'='1"
//         ];

//         const generateSubFields = (type: GraphQLTypeReference): string => {
//             return type.fields ? type.fields.map(subField => subField.name).join('') : '';
//             const args = field.args?.map(arg => `${arg.name}: "${input}"`).join(', ') ?? '';
//             const subFields = field.type.ofType ? generateSubFields(field.type.ofType) : '';
//             return `${operationType} { ${field.name}(${args}) { ${subFields} } }`;
//         }
//         }

//         const generateQuery = (field : GraphQLField, input: string) => {
//             const subFields = field.type.ofType ? generateSubFields(field.type.ofType) : '';
//             return `${field.name}(${input}) { ${subFields} }`;
//         }

//         const arrOfQueries: string[] = [];

//         for (const typeName of ['queryType', 'mutationType']) {
//             const name: string | null = res.locals.schema.data.__schema[typeName]?.name;
//             if(!name) continue;

//             const types: GraphQLType | undefined = schemaTypes.find(type => type.name === name);
//             if(!types?.fields) continue;

//             for(const field of types.fields) {
//                 for (const input of SQLInputs){
//                     const query = generateQuery(field, input);
//                     arrOfQueries.push(query);
//                 }
//             }
//         }

//         console.log(arrOfQueries)
//         res.status(200).json(arrOfQueries)
//     },
//     attack: async (req: Request, res: Response, next: NextFunction) => {

//     }
// }

// fields?.forEach((field) => {
//   if (field.type.ofType?.kind === 'OBJECT') {
//     let firstObjName = customNameTypes[i].name; // PasteObject
//     objTypeName = field.type.ofType?.name; // OwnerObject
//     field_1_name = field.name; // owner

//   if (customNameTypes[i].name === objTypeName) {
//     const fields2 = customNameTypes[i].fields;
//     fields2?.forEach((field) => {
//       if (field.type.ofType?.kind === 'OBJECT' &&
//       field.type.ofType?.name === firstObjName) {
//         field_2_name = field.name;
//         return;
//       }
//     })
//   }
// }})

//
// for (let i = 0; i < customNameTypes.length; i++) {
//   if (customNameTypes[i].fields !== null) {
//     const fields = customNameTypes[i].fields;
//     for (let i = 0; i < fields.length; i++) {
//       if (fields[i].type.ofType?.kind === 'OBJECT') {
//         let firstObjName = customNameTypes[i].name; // PasteObject
//         objTypeName = fields[i].type.ofType?.name; // OwnerObject
//         field_1_name = fields[i].name; // owner

//         if (customNameTypes[i].name === objTypeName) {
//           if (fields?[i].type.ofType?.kind === 'OBJECT' &&
//             fields?[i].type.ofType?.name === firstObjName) {
//               field_2_name = fields?[i].name;
//               return;
//             }
//           }
//       }
//     }
//   }
// }

// for (let i = 0; i < customNameTypes.length; i++) {
//  fields?.forEach((field) => {
//   if (field.type.ofType?.kind === 'OBJECT') {
//     let firstObjName = customNameTypes[i].name; // PasteObject
//     objTypeName = field.type.ofType?.name; // OwnerObject
//     field_1_name = field.name; // owner

//   if (customNameTypes[i].name === objTypeName) {
//     const fields2 = customNameTypes[i].fields;
//     fields2?.forEach((field) => {
//       if (field.type.ofType?.kind === 'OBJECT' &&
//       field.type.ofType?.name === firstObjName) {
//         field_2_name = field.name;
//         return;
//       }
//     })
//   }
// }})
// }
