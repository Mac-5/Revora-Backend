import { SessionRepository } from './types';

export class LogoutService {
  constructor(private readonly sessionRepository: SessionRepository) {}

  async logout(sessionId: string): Promise<void> {
    await this.sessionRepository.deleteSessionById(sessionId);
  }
}
