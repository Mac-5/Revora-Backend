import { RequestHandler, Router } from 'express';
import { createLogoutHandler } from './logoutHandler';
import { LogoutService } from './logoutService';
import { SessionRepository } from './types';

interface CreateLogoutRouterDeps {
  requireAuth: RequestHandler;
  sessionRepository: SessionRepository;
}

export const createLogoutRouter = ({
  requireAuth,
  sessionRepository,
}: CreateLogoutRouterDeps): Router => {
  const router = Router();
  const logoutService = new LogoutService(sessionRepository);

  router.post('/api/auth/logout', requireAuth, createLogoutHandler(logoutService));

  return router;
};
