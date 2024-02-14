/**
 * ************************************
 *
 * @module  server.ts
 * @author  MADR Productions - AY
 * @date    9-21-23
 * @description server for FortifyQL
 *
 * ************************************
 */

import express, { Request, Response, NextFunction } from 'express';
// import path from 'path'
import cors from 'cors';

const server = express();
const PORT = 3000;

// REQUIRED ROUTES && MIDDLEWARE
import getSchema from './pentesting/getSchema.ts';
import { injection } from './pentesting/injection.ts';
import { batching } from './pentesting/batching.ts';
import { verboseError } from './pentesting/verboseError.ts';
import { circularQuery } from './pentesting/circularQuery.ts';
import { ITestResult } from '../src/interfaces/results.ts';

// Use cors
server.use(cors());

// PARSE JSON
server.use(express.urlencoded({ extended: true }));
server.use(express.json());

//GLOBAL ROUTE CHECK
server.use((req, _res, next) => {
  console.log('Request received', req.method, req.path, req.body);
  return next();
});
//PATHS
server.use('/api/runpentest', async (req: Request, res: Response) => {
  try {
    console.log('Starting Penetration Testing...');
    await getSchema(req, res);

    const testsMap: {
      [key: string]: { generate: Function; evaluate: Function };
    } = {
      SQL: {
        generate: injection.generateQueries,
        evaluate: injection.attack,
      },
      Verbose: {
        generate: verboseError.generateQueries,
        evaluate: verboseError.attack,
      },
      Circular: {
        generate: circularQuery.generateQueries,
        evaluate: circularQuery.attack,
      },
      Batching: {
        generate: batching.generateQueries,
        evaluate: batching.attack,
      },
    };

    const results: ITestResult[] = [];

    const runTest = async (test: string) => {
      if (req.body.tests.includes(test)) {
        await testsMap[test].generate(req, res);
        const testResult = await testsMap[test].evaluate(req, res);
        results.push(...testResult);
      }
    };

    const runAllTests = async () => {
      console.log('running all tests');
      await Promise.all(Object.keys(testsMap).map(runTest));
    };

    await runAllTests();
    console.log('sending response');
    return res.status(200).json(results);
  } catch (err) {
    return res.status(400).json('error running tests');
  }
});

// GLOBAL ERROR HANDLER
interface CustomError {
  log?: string;
  status?: number;
  message?: {
    err: string;
  };
}

server.use(
  (err: CustomError, _req: Request, res: Response, _next: NextFunction) => {
    const defaultErr = {
      log: 'Express error handler caught unknown middleware error',
      status: 500,
      message: { err: 'An error occurred' },
    };

    const errorObj = { ...defaultErr, ...err };
    console.log(errorObj.log);
    return res.status(errorObj.status).json(errorObj.message);
  },
);

server.listen(PORT, () => console.log(`Listening on port ${PORT}`));

export default server;