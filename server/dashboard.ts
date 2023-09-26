import { Request, Response, NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import { URL, fileURLToPath } from 'url';
import { ITestResult } from '../src/interfaces/results';

// Alternative way to define __dirname as this is not defined in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

type TestData = string[];

const dashboard = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const tests: string[] = req.body.tests; // custom types seem to require creating of methods
    fs.readFile(
      path.resolve(__dirname, './mockData.json'),
      (err: any, data: any): void => {
        if (err)
          return next({
            log: `dashboard ERROR: ${
              typeof err === 'object' ? JSON.stringify(err) : err
            }`,
            message: {
              err: 'Error occurred in the dashboard. Check server logs for more details.',
            },
          });
        const dashboardData: any = JSON.parse(data.toString()); // need to fix this because it wouldn't let me do index search with other type

        const results: ITestResult[] = [];
        for (let i = 0; i < tests.length; i++) {
          if (dashboardData[tests[i]]) {
            results.push(dashboardData[tests[i]]);
          } else {
            throw new Error(`${tests[i]} not found.`);
          }
        }
        res.locals.dashboard = results;
        return next();
      },
    );
  } catch (err) {
    console.log('dashboard middleware', err);
    res
      .status(500)
      .json('Unable to retrieve data, please see console for more details ');
  }
};

export default dashboard;
