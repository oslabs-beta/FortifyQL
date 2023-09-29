/**
 * ************************************
 *
 * @module  dashboard.ts
 * @author  MADR Productions - RP
 * @date    9-26-23
 * @description middleware for server.use('/api/test') to initiate tests and send response back to client
 *
 * ************************************
 */

import { Request, Response, NextFunction } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

// Alternative way to define __dirname as this is not defined in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

type TestData = string[]; // Move to TS file

const dashboard = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fetchModule = await import('node-fetch');
    const fetch = fetchModule.default;
    let results: any[] = []; // Change any to TS interface
    const tests: TestData = req.body.tests;
    const URI: string = req.body.API;
    const requestBody = JSON.stringify({ API: URI });

    // iterate through the tests to initiate each each one
    for (const test of tests) {
      // console.log('Test: ', test);
      if (test === 'injection-scan') {
        // console.log('Initiating injection scan...');
        const injData = await fetch('http://localhost:3000/scan', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: requestBody,
        }).catch((err) => console.log(err));

        if (!injData) return; // not sure if this line is necessary
        const injRes = await injData.json();
        // console.log('Injection Response: ', injRes);
        results = results.concat(injRes);
      }

      if (test === 'introspection-scan') {
        // console.log('Initiating introspection scan...');
        const veData = await fetch('http://localhost:3000/error', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: requestBody,
        }).catch((err) => console.log(err));

        if (!veData) return; // not sure if this line is necessary
        const veRes = await veData.json();
        // console.log('Verbose Error Response: ', veRes);
        results = results.concat(veRes);
      }
    }

    // console.log('Results: ', results);
    res.locals.dashboard = results;
    return next();
  } catch (err) {
    console.log('dashboard middleware', err);
    res
      .status(500)
      .json('Unable to retrieve data, please see console for more details ');
  }
};

export default dashboard;
