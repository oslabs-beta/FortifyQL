import { Request, Response, NextFunction } from 'express';
// import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
// import { ITestResult } from '../src/interfaces/results';

// Alternative way to define __dirname as this is not defined in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

type TestData = string[]; // custom types seem to require creating of methods

const dashboard = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const fetchModule = await import('node-fetch');
    const fetch = fetchModule.default;
    let results: any[] = [];
    const tests: string[] = req.body.tests; // TestData didn't work
    const URI: string = req.body.API;
    const requestBody = JSON.stringify({ API: URI });

    for (const test of tests) {
      console.log('Test: ', test);
      if (test === 'injection-scan') {
        console.log('Initiating injection scan...');
        const injData = await fetch('http://localhost:3000/scan', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: requestBody,
        }).catch((err) => console.log(err));

        if (!injData) return;
        const injRes = await injData.json();
        console.log('Injection Response: ', injRes);
        results = results.concat(injRes);
      }

      if (test === 'introspection-scan') {
        console.log('Initiating introspection scan...');
        const veData = await fetch('http://localhost:3000/error', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: requestBody,
        }).catch((err) => console.log(err));

        if (!veData) return;
        const veRes = await veData.json();
        console.log('Verbose Error Response: ', veRes);
        results = results.concat(veRes);
      }
    }

    // fs.readFile(
    //   path.resolve(__dirname, './mockData.json'),
    //   (err: NodeJS.ErrnoException | null, data: Buffer): void => {
    //     if (err)
    //       return next({
    //         log: `dashboard ERROR: ${
    //           typeof err === 'object' ? JSON.stringify(err) : err
    //         }`,
    //         message: {
    //           err: 'Error occurred in the dashboard. Check server logs for more details.',
    //         },
    //       });
    //     const dashboardData: any = JSON.parse(data.toString()); // need to fix this because it wouldn't let me do index search with other types

    //     const results: ITestResult[] = [];
    //     for (let i = 0; i < tests.length; i++) {
    //       if (dashboardData[tests[i]]) {
    //         results.push(dashboardData[tests[i]]);
    //       } else {
    //         throw new Error(`${tests[i]} not found.`);
    //       }
    //     }
    console.log('Results: ', results);
    res.locals.dashboard = results;
    return next();
    //   },
    // );
  } catch (err) {
    console.log('dashboard middleware', err);
    res
      .status(500)
      .json('Unable to retrieve data, please see console for more details ');
  }
};

export default dashboard;
