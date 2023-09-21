import { Request, Response, NextFunction } from 'express';

const verboseError = async (req: Request, res: Response, _next: NextFunction) => {
  const fetchModule = await import('node-fetch');
  const fetch = fetchModule.default;
  const query = `
  query {
    users {
        id
        username
        passwor
        }
    }`;

  try {
    console.log('entered scan');
    const API = req.body.API;
    console.log('using this API', API);
    const response = await fetch(API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/graphql',
      },
      body: query,
    });
    // type DataType = {
    //   details: Record<string, any>;
    // };
    console.log('response: ', response);
    //this part is in the works- figuring how to break them up with types/might get rid of ts
    const obj: any = await response.json();
    console.log('obj: ', obj.data);

    res.sendStatus(200);
  } catch (err) {
    console.log('injectionAttack middleware', err);
    res.status(400).json('Unable to submit query. An error occurred.');
  }
};

export default verboseError;
