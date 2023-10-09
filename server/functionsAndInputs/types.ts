import { RequestHandler } from "express";

export type PentestType = {
  generateQueries: RequestHandler;
  attack: RequestHandler;
};
export interface GraphQLType {
  name: string;
  kind: string;
  fields?: GraphQLField[];
}
export interface GraphQLField {
  name: string;
  args?: GraphQLArgs[];
  type: GraphQLTypeReference;
  fields?: GraphQLField;
}
export interface GraphQLArgs {
  name: string;
  type?: GraphQLTypeReference;
}
export interface GraphQLTypeReference {
  kind: string;
  name?: string;
  ofType?: GraphQLTypeReference;
  fields?: GraphQLField[];
}
export interface QueryResult {
  id: string;
  status: string;
  title: string;
  query: string;
  description: string;
  severity: string | number;
  testDuration: string | number;
  lastDetected: string | number;
}
