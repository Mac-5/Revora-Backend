import { NextFunction, RequestHandler, Response } from 'express';
import { LogoutService } from './logoutService';
import { AuthenticatedRequest } from './types';

export const createLogoutHandler = (logoutService: LogoutService): RequestHandler => {
  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const sessionId = req.auth?.sessionId;

      if (!sessionId) {
        res.status(401).json({ error: 'Unauthorized' });
        return;
      }

      await logoutService.logout(sessionId);
      res.status(204).send();
    } catch (error) {
      next(error);
    }
  };
};
