import { Request, Response, NextFunction } from 'express';

const getSchema = async (req: Request, res: Response, _next: NextFunction) => {
  const fetchModule = await import ('node-fetch');
  const fetch = fetchModule.default; 
  const query = `
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        ...FullType
      }
      directives {
        name
        description
        locations
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
    type { ...TypeRef }
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
          ofType {
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
          }
        }
      }
    }
  }
`;

  try {
    console.log('entered scan');
    const API = req.body.API;
    console.log('using this API', API);
    const response = await fetch(API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ query }),
    });
    type DataType = {
      details: Record<string, any>;
    };
    //this part is in the works- figuring how to break them up with types/might get ride of ts 
    const obj: DataType = await response.json();
    console.log(obj.data.__schema.types);
    
    res.sendStatus(200);
  } catch (err) {
    console.log('getSchema middleware', err);
    res.status(400).json('Unable to retrieve schema, please turn introspection on ');
  }
};

export default getSchema;