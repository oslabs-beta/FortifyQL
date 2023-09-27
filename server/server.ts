import express, { Request, Response, NextFunction } from 'express';
// import path from 'path'
import cors from 'cors';

const server = express();
const PORT = 3000;

// REQUIRED ROUTES && MIDDLEWARE
import getSchema from './getSchema';
import injectionAttack from './injectionAttack';
import verboseError from './verboseError';
import circularQuery from './circularQuery';
import dashboard from './dashboard';

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
server.use('/api/test', dashboard, (req, res, _next) => {
  res.json(res.locals.dashboard);
});
server.use('/scan', getSchema);
server.use('/inject', injectionAttack);
server.use('/error', verboseError);
server.use('/circular', circularQuery);

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
