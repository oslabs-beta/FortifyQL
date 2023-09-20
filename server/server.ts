import express, { Request, Response, NextFunction} from 'express'
// import path from 'path'
import cors from 'cors'

const app = express();
const PORT = 3000;

// REQUIRED ROUTES

// Use cors
app.use(cors());

// PARSE JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// GLOBAL ERROR HANDLER
interface CustomError {
    log?: string;
    status?: number;
    message?: {
      err: string;
    };
  }

app.use((err: CustomError, req: Request, res: Response, _next: NextFunction) => {
    const defaultErr = {
      log: 'Express error handler caught unknown middleware error',
      status: 500,
      message: { err: 'An error occurred' },
    };
  
    const errorObj = { ...defaultErr, ...err };
    console.log(errorObj.log);
    return res.status(errorObj.status).json(errorObj.message);
  });
  
  app.listen(PORT, () => console.log(`Listening on port ${PORT}`));
  