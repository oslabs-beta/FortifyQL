import { Request, Response, NextFunction, RequestHandler } from 'express';

type InjectionType = {
    generateQuery: RequestHandler
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
    generateQuery: async (req: Request, res: Response, _next: NextFunction) => {
        const schema: Schema = res.locals.schema.data;
        const schemaTypes: GraphQLType[] = res.locals.schema.data.__schema.types;

        const SQLInputs = [
            "OR 1=1",
            "' OR '1'='1",
            "--",
            "';--",
            "') OR ('1'='1"
        ];

        // const getFieldsForType = (typeName: string, visitedTypes: Set<string> = new Set(), memo: Map<string, string> = new Map()): string => {
        //     if (visitedTypes.has(typeName)) {
        //         return '';
        //     }
            
        //     if (memo.has(typeName)) {
        //         return memo.get(typeName)!; 
        //     }
        
        //     visitedTypes.add(typeName);
        
        //     const type = schema.__schema.types.find((t: GraphQLType) => t.name === typeName);
        //     if (type && type.fields) {
        //         const result = type.fields
        //             .filter(field => field.type.kind === 'SCALAR')
        //             .map(field => field.name)
        //             .slice(0, 1)
        //             .map(fieldName => `${fieldName} ${getFieldsForType(type.name, visitedTypes, memo)}`)
        //             .join(' ');
                    
        //         memo.set(typeName, result); 
        //         return result;
        //     }
        
        //     return '';
        // };
          

        const generateQuery = (field : GraphQLField, input: string, type: string) => {
            const queryName = type === 'queryType' ? 'query' : 'mutation';
            const args = field.args
            ?.filter(arg => arg.type?.kind === 'SCALAR' && arg.type?.name === 'String')
            .map(arg => `${arg.name}: "${input}"`)
            .join(', ') || '';
            
            // const typeName = field.type.name;
            // const fields = typeName ? getFieldsForType(typeName) : '';

            return `${queryName} { ${field.name}(${args}) }`;
        }

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

        console.log(arrOfQueries)
        res.status(200).json(schema)
    },
    attack: async (_req: Request, _res: Response, _next: NextFunction) => {

    }
}