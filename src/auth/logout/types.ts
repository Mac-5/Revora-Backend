import { Request } from 'express';

export interface AuthContext {
  userId: string;
  sessionId: string;
  tokenId?: string;
}

export type AuthenticatedRequest = Request & {
  auth?: AuthContext;
};

export interface SessionRepository {
  deleteSessionById(sessionId: string): Promise<void>;
}
