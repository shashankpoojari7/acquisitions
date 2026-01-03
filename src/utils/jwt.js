import logger from '#config/logger.js';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN;

export const jwtToken = {
  sign: (payload) => {
    try {
      return jwt.sign( payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
    } catch (error) {
      logger.error('Failed to authenticate JWT token', error);
      throw new Error('Failed to authenticate JWT token');
    }
  },
  verify: (token) => {
    try {
      return jwt.verify( token, JWT_SECRET);
    } catch (error) {
      logger.error('Failed to authenticate JWT token', error);
      throw new Error('Failed to authenticate JWT token');
    }
  }
}
