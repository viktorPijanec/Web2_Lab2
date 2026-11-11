import { Request, Response, NextFunction } from "express";
export { setUserInfo, requiresAuthentication, isAuthenticated };

type User = {
  username: string;
  //latter we can add additional properties as isAdmin, groups, ...
};

//user(information) should be set using setUserInfo method below
declare global {
  namespace Express {
    export interface Request {
      user?: User;
    }
  }
}

declare module "express-session" {
  interface SessionData {
    username?: string;
    vulnerability1Enabled?: boolean;
    vulnerability2Enabled?: boolean;
    csrfToken?: string;
  }
}

//type guard: if it returns true, TypeScript knows that req.user is defined (User instead of User | undefined)
//Pick<Request, 'user'> = { user? : User }, Required<...> = { user : User }
function isAuthenticated(
  req: Request,
): req is Request & Required<Pick<Request, "user">> {
  return req.user !== undefined;
}

function requiresAuthentication(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  if (isAuthenticated(req)) next();
  else {
    res.redirect("/login");
  }
}

async function setUserInfo(req: Request, res: Response, next: NextFunction) {
  const username = req.session.username;

  if (username) {
    req.user = { username };
  }

  next();
}
