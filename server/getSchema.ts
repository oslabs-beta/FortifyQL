import { Request, Response, NextFunction } from 'express';

const getSchema = async (req: Request, res: Response, next: NextFunction) => {
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
    console.log('GraphQL API Endpoint', API);
    const response = await fetch(API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/graphql',
      },
      body: query,
    });
    const result: any = await response.json();
    res.locals.schema = result;
    console.log('Retrieved Schema...');
    console.log(result);
    res.status(200).json(result);
  } catch (err) {
    console.log('getSchema middleware', err);
    res
      .status(400)
      .json('Unable to retrieve schema, please turn introspection on ');
  }
};

export default getSchema;
