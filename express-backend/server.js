import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors({
  origin: 'http://localhost:8080',
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Auth middleware
const authenticateToken = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { name, email, password: hashedPassword }
    });

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });

    res.json({ success: true, user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !user.password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000 });

    res.json({ success: true, user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/signout', (req, res) => {
  res.clearCookie('token');
  res.json({ success: true });
});

// Group Routes
app.get('/api/groups', authenticateToken, async (req, res) => {
  try {
    const groups = await prisma.group.findMany({
      where: {
        members: {
          some: { userId: req.userId }
        }
      },
      include: {
        members: {
          include: {
            user: {
              select: { id: true, name: true, email: true, image: true }
            }
          }
        },
        expenses: {
          where: { settled: false },
          select: { id: true, amount: true }
        }
      }
    });
    res.json({ groups });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/groups', authenticateToken, async (req, res) => {
  try {
    const { name, description } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Group name is required' });
    }

    const group = await prisma.group.create({
      data: {
        name,
        description,
        members: {
          create: {
            userId: req.userId,
            role: 'admin'
          }
        }
      },
      include: {
        members: {
          include: {
            user: {
              select: { id: true, name: true, email: true, image: true }
            }
          }
        }
      }
    });

    res.json({ success: true, group });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/groups/:id', authenticateToken, async (req, res) => {
  try {
    const group = await prisma.group.findFirst({
      where: {
        id: req.params.id,
        members: {
          some: { userId: req.userId }
        }
      },
      include: {
        members: {
          include: {
            user: {
              select: { id: true, name: true, email: true, image: true }
            }
          }
        },
        expenses: {
          include: {
            paidBy: {
              select: { id: true, name: true, email: true }
            },
            splits: {
              include: {
                user: {
                  select: { id: true, name: true, email: true }
                }
              }
            }
          },
          orderBy: { createdAt: 'desc' }
        }
      }
    });

    if (!group) {
      return res.status(404).json({ error: 'Group not found' });
    }

    res.json({ group });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Expense Routes
app.post('/api/groups/:id/expenses', authenticateToken, async (req, res) => {
  try {
    const { description, amount, paidById, splitType, splits } = req.body;
    const groupId = req.params.id;

    // Verify user is a member of the group
    const membership = await prisma.groupMember.findFirst({
      where: { groupId, userId: req.userId }
    });

    if (!membership) {
      return res.status(403).json({ error: 'Not a member of this group' });
    }

    if (!description || !amount || !paidById) {
      return res.status(400).json({ error: 'Description, amount, and paidById are required' });
    }

    // Create expense with splits
    const expense = await prisma.expense.create({
      data: {
        description,
        amount: parseFloat(amount),
        groupId,
        paidById,
        settled: false,
        splits: {
          create: splits.map((split) => ({
            userId: split.userId,
            amount: parseFloat(split.amount)
          }))
        }
      },
      include: {
        paidBy: {
          select: { id: true, name: true, email: true, image: true }
        },
        splits: {
          include: {
            user: {
              select: { id: true, name: true, email: true, image: true }
            }
          }
        }
      }
    });

    res.json({ success: true, expense });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const { description, amount, settled } = req.body;
    const expenseId = req.params.id;

    // Verify expense exists and user is a member of the group
    const expense = await prisma.expense.findFirst({
      where: {
        id: expenseId,
        group: {
          members: {
            some: { userId: req.userId }
          }
        }
      }
    });

    if (!expense) {
      return res.status(404).json({ error: 'Expense not found' });
    }

    const updatedExpense = await prisma.expense.update({
      where: { id: expenseId },
      data: {
        ...(description && { description }),
        ...(amount && { amount: parseFloat(amount) }),
        ...(settled !== undefined && { settled })
      },
      include: {
        paidBy: {
          select: { id: true, name: true, email: true, image: true }
        },
        splits: {
          include: {
            user: {
              select: { id: true, name: true, email: true, image: true }
            }
          }
        }
      }
    });

    res.json({ success: true, expense: updatedExpense });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const expenseId = req.params.id;

    // Verify expense exists and user is a member of the group
    const expense = await prisma.expense.findFirst({
      where: {
        id: expenseId,
        group: {
          members: {
            some: { userId: req.userId }
          }
        }
      }
    });

    if (!expense) {
      return res.status(404).json({ error: 'Expense not found' });
    }

    // Delete expense splits first, then expense
    await prisma.expenseSplit.deleteMany({
      where: { expenseId }
    });

    await prisma.expense.delete({
      where: { id: expenseId }
    });

    res.json({ success: true, message: 'Expense deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Express server running on http://localhost:${PORT}`);
});
