import { Request, Response, NextFunction, RequestHandler } from 'express';

type InjectionType = {
    generateQuery: RequestHandler
    attack: RequestHandler
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
}

export const injection: InjectionType = {
    generateQuery: async (req: Request, res: Response, _next: NextFunction) => {
        const schemaTypes: GraphQLType[] = res.locals.schema.data.__schema.types;
        const queryName = res.locals.schema.data.__schema.queryType.name;
        const mutationName = res.locals.schema.data.__schema.mutationType.name;
        const queryTypes = schemaTypes.find(type => type.name === queryName);
        const mutationTypes = mutationName ? schemaTypes.find(type => type.kind === mutationName) : null;
        const arrOfQueries = [];
        if(queryTypes && queryTypes.fields){
            for(const field of queryTypes.fields){
                if(field.args && field.args.length > 0){
                    for(const arg of field.args){
                        const input = "' OR '1' = '1'";
                    }
                }
            }
        }

        console.log(queryTypes, mutationTypes)
        res.status(200).json(queryTypes)
    },
    attack: async (req: Request, res: Response, next: NextFunction) => {

    }
}