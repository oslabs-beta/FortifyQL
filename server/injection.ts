import { Request, Response, NextFunction, RequestHandler } from 'express';

type InjectionType = {
    generateQueries: RequestHandler
    attack: RequestHandler
}
interface Schema {
    __schema: {
        types: GraphQLType[]
        queryType?: {name: string}
        mutationType?: {name: string}
    }
}
interface GraphQLType {
    name: string
    kind:string
    fields?: GraphQLField[]
}
interface GraphQLField {
    name: string
    args?: GraphQLArgs[]
    type: GraphQLTypeReference
    fields?: GraphQLField
}
interface GraphQLArgs {
    name: string
    type?: GraphQLTypeReference
}
interface GraphQLTypeReference {
    kind: string
    name?: string
    ofType?: GraphQLTypeReference
    fields?: GraphQLField[]
}

export const injection: InjectionType = {
    generateQueries: async (req: Request, res: Response, next: NextFunction) => {
        console.log('Generating SQL Injection Queries...')
        // const schema: Schema = res.locals.schema.data;
        const schemaTypes: GraphQLType[] = res.locals.schema.data.__schema.types

        const SQLInputs = [
            "OR 1=1",
            "' OR '1'='1",
            "--",
            "';--",
            "') OR ('1'='1"
        ];

        const getBaseType = (type: GraphQLTypeReference): string => {
            let curr = type;
            while(curr.ofType){
                curr = curr.ofType;
            }
            return curr.name || '';
        }

        const getSubFields = (type: GraphQLType | GraphQLTypeReference, depth: number = 0, maxDepth: number = 1): string => {
            if(!type.fields || depth > maxDepth) return '';
            return `{ ${type.fields
                .filter(field => {
                  const baseTypeName = getBaseType(field.type);
                  const baseType = schemaTypes.find(t => t.name === baseTypeName);
                  return !baseType?.fields;
                })
                .map(field => field.name)
                .join(' ')} }`;
        }

        const generateQuery = (field : GraphQLField, input: string, QueryType: string) => {
            const queryName = QueryType === 'queryType' ? 'query' : 'mutation';
            const args = field.args
            ?.filter(arg => arg.type?.kind === 'SCALAR' && arg.type?.name === 'String')
            .map(arg => `${arg.name}: "${input}"`)
            .join(', ') || '';

            const baseTypeName = field.type ? getBaseType(field.type) : '';
            const baseType = schemaTypes.find(type => type.name === baseTypeName);
            const subFields = baseType ? getSubFields(baseType) : '';

            return `${queryName} { ${field.name}(${args}) ${subFields} }`;
        };

        const arrOfQueries: string[] = [];

        for (const typeName of ['queryType', 'mutationType']) {
            const name: string | null = res.locals.schema.data.__schema[typeName]?.name; 
            if(!name) continue;

            const types: GraphQLType | undefined = schemaTypes.find(type => type.name === name);
            if(!types?.fields) continue;

            for(const field of types.fields) {
                if(!field.args || field.args.some(arg => arg.type?.kind == 'SCALAR' && arg.type?.name === 'String')){
                    for(const input of SQLInputs){
                        const query = generateQuery(field, input, typeName);
                        arrOfQueries.push(query)
                    }
                }
            }
        }
        res.locals.SQLQueries = arrOfQueries;
        console.log('Generated Queries...')

        return next();
    },
    attack: async (req: Request, res: Response, next: NextFunction) => {
        const result = [];
        const API: string = req.body.API;
        const sendReqAndEvaluate = async (query: string) => {
            try {
              const sendDate = Date.now();
              const response = await fetch(API, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/graphql',
                },
                body: query,
              });
              const obj = await response.json();
              return obj 
            } catch (err) {
                console.log(err)
            }
          
            //evaluate response
          };
          //loop here
          const query = res.locals.SQLQueries[0]
          console.log(query)
          const response = await sendReqAndEvaluate(query);
          console.log(response)
          res.status(200).json(response)

          //return result
        }
}