import logger from "#config/logger.js";
import { db } from "#config/database.js";
import { users } from "#models/user.model.js";
import { eq } from "drizzle-orm";

export const getAllUsers = async () => {
  try {
    return await db
      .select({
        id: users.id,
        email: users.email,
        name: users.name,
        role: users.role,
        created_at: users.created_at,
        updated_at: users.updated_at,
      })
      .from(users);
  } catch (e) {
    logger.error('Error getting users', e);
    throw new Error('Error Getting Users');
  }
};

export const getUserById = async (id) => {
  try {
    const [user] = await db
      .select({
        id: users.id,
        email: users.email,
        name: users.name,
        role: users.role,
        created_at: users.created_at,
        updated_at: users.updated_at,
      })
      .from(users)
      .where(eq(users.id, id))
      .limit(1);

    if (!user) {
      throw new Error('User Not Found');
    }

    return user;
  } catch (e) {
    logger.error(`Error getting user by id ${id}`, e);

    if (e.message === 'User Not Found') {
      throw e;
    }

    throw new Error('Error Getting User');
  }
};

export const updateUser = async (id, updates) => {
  try {
    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.id, id))
      .limit(1);

    if (!existingUser) {
      throw new Error('User Not Found');
    }

    const [updatedUser] = await db
      .update(users)
      .set({
        ...updates,
        updated_at: new Date(),
      })
      .where(eq(users.id, id))
      .returning({
        id: users.id,
        email: users.email,
        name: users.name,
        role: users.role,
        created_at: users.created_at,
        updated_at: users.updated_at,
      });

    return updatedUser;
  } catch (e) {
    logger.error(`Error updating user with id ${id}`, e);

    if (e.message === 'User Not Found') {
      throw e;
    }

    throw new Error('Error Updating User');
  }
};

export const deleteUser = async (id) => {
  try {
    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.id, id))
      .limit(1);

    if (!existingUser) {
      throw new Error('User Not Found');
    }

    const [deletedUser] = await db
      .delete(users)
      .where(eq(users.id, id))
      .returning({
        id: users.id,
        email: users.email,
        name: users.name,
        role: users.role,
        created_at: users.created_at,
        updated_at: users.updated_at,
      });

    return deletedUser;
  } catch (e) {
    logger.error(`Error deleting user with id ${id}`, e);

    if (e.message === 'User Not Found') {
      throw e;
    }

    throw new Error('Error Deleting User');
  }
};
