import { QueryResult } from './types';
export function createQueryResult(
  category: string,
  query: string,
  ID: number,
): QueryResult {
  return {
    id: `${category}-${ID}`,
    status: 'Pass',
    title: '',
    details: {
      query: '',
      response: '',
      description: '',
      link: '',
    },
    severity: 'P1',
    testDuration: '',
    lastDetected: `${new Date().toLocaleTimeString('en-GB')} - ${new Date()
      .toLocaleDateString('en-GB')
      .split('/')
      .reverse()
      .join('-')}`,
  };
}
export function createErrorResult(
  category: string,
  query: string,
  ID: number,
): QueryResult {
  return {
    id: `${category}-${ID}`,
    status: 'Error',
    title: 'Failed to Run Test',
    details: {
      query: '',
      response: '',
      description: '',
      link: '',
    },
    severity: 'P1',
    testDuration: '',
    lastDetected: `${new Date().toLocaleTimeString('en-GB')} - ${new Date()
      .toLocaleDateString('en-GB')
      .split('/')
      .reverse()
      .join('-')}`,
  };
}
