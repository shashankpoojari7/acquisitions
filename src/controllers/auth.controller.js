import logger from '#config/logger.js';
import { createUser, authenticateUser } from '#services/auth.service.js';
import { formatValidationError } from '#utils/format.js';
import { signUpSchema, signInSchema } from '#validations/auth.validation.js';
import { jwtToken } from '#utils/jwt.js';
import { cookies } from '#utils/cookies.js'

export const signup = async(req, res, next) => {
  try {
    const validationResult = signUpSchema.safeParse(req.body);

    if(!validationResult.success) {
      return res.status(400).json({
        error: 'Validation Failed',
        details: formatValidationError(validationResult.error)
      });
    }
    const { email, password, name, role} = validationResult.data;

    const user = await createUser({ email, password, name, role});

    const token = jwtToken.sign({ id: user.id, email: user.email, role: user.role });

    cookies.set(res, 'token', token)

    logger.info(`User Registered successfully: ${email}`);
    res.status(201).json({ 
      message: 'User registered',
      user: {
        id: user.id, email: user.email, name: user.name, role: user.role
      }
    });

  } catch (e) {
    logger.error('SignUp error', e)

    if(e.message === "User with this email already exists") {
      return res.status(409).json({ error: "Email already exists" })
    }

    next(e);
  }
}

export const signIn = async (req, res, next) => {
  try {
    const validationResult = signInSchema.safeParse(req.body);

    if (!validationResult.success) {
      return res.status(400).json({
        error: 'Validation Failed',
        details: formatValidationError(validationResult.error),
      });
    }

    const { email, password } = validationResult.data;

    const user = await authenticateUser({ email, password });

    const token = jwtToken.sign({ id: user.id, email: user.email, role: user.role });

    cookies.set(res, 'token', token);

    logger.info(`User signed in successfully: ${email}`);

    res.status(200).json({
      message: 'User signed in',
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
    });
  } catch (e) {
    logger.error('SignIn error', e);

    if (e.message === 'Invalid email or password') {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    next(e);
  }
};

export const signOut = async (req, res, next) => {
  try {
    cookies.clear(res, 'token');
    logger.info('User signed out successfully');

    res.status(200).json({ message: 'User signed out' });
  } catch (e) {
    logger.error('SignOut error', e);
    next(e);
  }
};
