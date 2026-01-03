import logger from '#config/logger.js';
import bcrypt from 'bcrypt';
import { eq } from 'drizzle-orm';
import { db } from '#config/database.config.js';
import { users } from '#models/user.model.js'

export const hashPassword = async (password) => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (e) {
    logger.error('Error hashing password:', e);
    throw new Error('Error Hashing Password');
  }
};

export const comparePassword = async (password, hash) => {
  try {
    return await bcrypt.compare(password, hash);
  } catch (e) {
    logger.error('Error comparing password:', e);
    throw new Error('Error Comparing Password');
  }
};

export const createUser = async ({name, email, password, role}) => {
  try {
    const existingUser = await db.select().from(users).where(eq(users.email, email)).limit(1);

    if (existingUser.length > 0)  throw new Error('User Already Exists');

    const password_hash = await hashPassword(password);

    const [newUser] = await db.insert(users).values({
      name, 
      email,
      password: password_hash,
      role
    }).returning({id: users.id, name: users.name, email: users.email, role: users.role, created_at: users.created_at});

    logger.info(`User ${email} created successfully.`);
    return newUser;
  } catch (e) {
    logger.error('Error creating user:', e);
    throw new Error('Error Creating User');
  }
}

export const authenticateUser = async ({ email, password }) => {
  try {
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!user) {
      throw new Error('Invalid email or password');
    }

    const isMatch = await comparePassword(password, user.password);

    if (!isMatch) {
      throw new Error('Invalid email or password');
    }

    const { password: _password, ...safeUser } = user;
    return safeUser;
  } catch (e) {
    logger.error('Error authenticating user:', e);

    if (e.message === 'Invalid email or password') {
      throw e;
    }

    throw new Error('Error Authenticating User');
  }
};
