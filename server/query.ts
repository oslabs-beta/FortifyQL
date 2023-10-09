import { QueryResult } from "./types";
export function createQueryResult(category: string, query: string, ID: number): QueryResult{
    return {
        id: `${category}-${ID}`,
        status: 'Pass',
        query: query,
        title: '',
        description: '',
        severity: 'P1',
        testDuration: '',
        lastDetected: `${new Date().toLocaleTimeString('en-GB')} - ${new Date()
            .toLocaleDateString('en-GB')
            .split('/')
            .reverse()
            .join('-')}`,
        };
    }
    export function createErrorResult(category: string, query: string, ID: number): QueryResult{
        return {
          id: `${category}-${ID}`,
          status: 'Error',
          query: 'Request errored out',
          title: 'Failed Test',
          description: `Error occured`,
          severity: 'P1',
          testDuration: '',
          lastDetected: `${new Date().toLocaleTimeString('en-GB')} - ${new Date()
            .toLocaleDateString('en-GB')
            .split('/')
            .reverse()
            .join('-')}`,
        }
      };