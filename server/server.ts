import express, { Request, Response, NextFunction } from 'express';
// import path from 'path'
import cors from 'cors';

const server = express();
const PORT = 3000;

// REQUIRED ROUTES && MIDDLEWARE
import getSchema from './getSchema.ts';
import { injection } from './injection.ts';
import injectionAttack from './injectionAttack.ts';
import verboseError from './verboseError.ts';
import circularQuery from './circularQuery.ts';

// Use cors
server.use(cors());

// PARSE JSON
server.use(express.urlencoded({ extended: true }));
server.use(express.json());

//GLOBAL ROUTE CHECK
server.use((req, _res, next) => {
  console.log('Request recieved', req.method, req.path, req.body);
  return next();
});
//PATHS
server.use('/scan', getSchema, injection.generateQuery);
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

server.use((err: CustomError, _req: Request, res: Response, _next: NextFunction) => {
  const defaultErr = {
    log: 'Express error handler caught unknown middleware error',
    status: 500,
    message: { err: 'An error occurred' },
  };

  const errorObj = { ...defaultErr, ...err };
  console.log(errorObj.log);
  return res.status(errorObj.status).json(errorObj.message);
});

server.listen(PORT, () => console.log(`Listening on port ${PORT}`));
