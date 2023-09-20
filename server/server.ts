import express, { Request, Response, NextFunction } from 'express';
// import path from 'path'
import cors from 'cors';

const server = express();
const PORT = 3000;

// REQUIRED ROUTES

// Use cors
server.use(cors());

// PARSE JSON
server.use(express.urlencoded({ extended: true }));
server.use(express.json());

// GLOBAL ERROR HANDLER
interface CustomError {
  log?: string;
  status?: number;
  message?: {
    err: string;
  };
}

server.use(
  (err: CustomError, req: Request, res: Response, _next: NextFunction) => {
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
