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

        const generateQuery = (field : GraphQLField, input: string, type: string) => {
            const queryName = type === 'queryType' ? 'query' : 'mutation';
            const args = field.args
            ?.filter(arg => arg.type?.kind === 'SCALAR' && arg.type?.name === 'String')
            .map(arg => `${arg.name}: "${input}"`)
            .join(', ') || '';

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