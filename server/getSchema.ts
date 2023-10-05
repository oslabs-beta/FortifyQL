/**
 * ************************************
 *
 * @module  getSchema.ts
 * @author  MADR Productions - AY
 * @date    9-23-23
 * @description middleware for all tests to generate introspection query to acquire schema for generating other queries.
 *
 * ************************************
 */

import { Request, Response } from 'express';

const getSchema = async (req: Request, res: Response) => {
  const fetchModule = await import('node-fetch');
  const fetch = fetchModule.default;

  const query = `query IntrospectionQuery {
    __schema {
        queryType {
            name
        }
        mutationType {
            name
        }
        subscriptionType {
            name
        }
        types {
         ...FullType
        }
        directives {
            name
            description
            args {
                ...InputValue
        }
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args {
            ...InputValue
        }
        type {
            ...TypeRef
        }
        isDeprecated
        deprecationReason
    }
    inputFields {
        ...InputValue
    }
    interfaces {
        ...TypeRef
    }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes {
        ...TypeRef
    }
}

fragment InputValue on __InputValue {
    name
    description
    type {
        ...TypeRef
    }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
            }
        }
    }
}`;

  try {
    console.log('Executing Introspection Query...');
    const API = req.body.API;
    // console.log('GraphQL API Endpoint', API);
    const response = await fetch(API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/graphql',
      },
      body: query,
    });

    // Should we store this in a file to avoid more unnecessary calls to the the GraphQL server?
    const result: any = await response.json(); // clean up any
    res.locals.schema = result;
    console.log('Retrieved Schema...');
    return;
  } catch (err) {
    console.log('getSchema middleware', err);
    res
      .status(400)
      .json('Unable to retrieve schema, please turn introspection on ');
  }
};

export default getSchema;
