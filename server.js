const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const pool = require("./db");

dotenv.config();
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET;

// --- Register ---
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id, email",
      [email, hashedPassword]
    );
    res.status(201).json({ message: "User registered", user: result.rows[0] });
  } catch (err) {
    if (err.code === "23505") {
      res.status(400).json({ message: "Email already exists" });
    } else {
      res.status(500).json({ error: err.message });
    }
  }
});

// --- Login ---
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rows.length === 0)
      return res.status(400).json({ message: "User not found" });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- Protected Route Example ---
app.get("/profile", async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: "Missing token" });

  try {
    const token = auth.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await pool.query("SELECT id, email FROM users WHERE id = $1", [
      decoded.id,
    ]);
    res.json({ profile: user.rows[0] });
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});

app.post('/statements', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Missing token' });

  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const { store_name, statement_date, total_amount, notes, denomination_details } = req.body;

    // Insert main statement
    const statementResult = await pool.query(
      'INSERT INTO statements (user_id, store_name, statement_date, total_amount, notes) VALUES ($1, $2, $3, $4, $5) RETURNING id',
      [decoded.id, store_name, statement_date, total_amount, notes]
    );
    const statementId = statementResult.rows[0].id;

    // Fetch denomination values for calculations
    const denomRes = await pool.query('SELECT id, denomination_value FROM denomination_master');
    const denominationMap = {};
    denomRes.rows.forEach(row => {
      denominationMap[row.id] = parseFloat(row.denomination_value);
    });

    // Insert denomination breakdown
    for (const item of denomination_details) {
      const { denomination_id, quantity } = item;

      const value = denominationMap[denomination_id];
      if (value === undefined) {
        return res.status(400).json({ message: `Invalid denomination_id: ${denomination_id}` });
      }

      const denomTotal = quantity * value;

      await pool.query(
        'INSERT INTO statement_denominations (statement_id, denomination_id, quantity, total) VALUES ($1, $2, $3, $4)',
        [statementId, denomination_id, quantity, denomTotal]
      );
    }

    res.status(201).json({ message: 'Statement with denominations added successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


app.get('/statements', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        s.id AS statement_id,
        s.user_id,
        s.store_name,
        s.statement_date,
        s.total_amount,
        s.notes,
        json_agg(
          json_build_object(
            'denomination_value', dm.denomination_value,
            'quantity', sd.quantity,
            'total', sd.total
          )
        ) AS denominations
      FROM statements s
      LEFT JOIN statement_denominations sd ON s.id = sd.statement_id
      LEFT JOIN denomination_master dm ON sd.denomination_id = dm.id
      GROUP BY s.id
      ORDER BY s.statement_date DESC
    `);

    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});


app.delete('/statements/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM statements WHERE id = $1 RETURNING *', [id]);

    if (result.rowCount === 0) {
      return res.status(404).json({ message: 'Statement not found' });
    }

    res.json({ message: 'Statement deleted successfully', deleted: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});


// GET /denominations
app.get("/denominations", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, denomination_value FROM denomination_master ORDER BY denomination_value DESC"
    );

    const denominations = result.rows.map((row) => ({
      id: row.id,
      denomination_value: row.denomination_value,
      count: null, // for frontend input
      total: null, // will be calculated on frontend or backend
    }));

    res.json({ denominations });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/statements/:id', async (req, res) => {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ message: 'Missing token' });

  try {
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const statementId = req.params.id;

    const { store_name, statement_date, total_amount, notes, denominations } = req.body;

    // 1. Check if statement belongs to user
    const check = await pool.query(
      'SELECT * FROM statements WHERE id = $1 AND user_id = $2',
      [statementId, decoded.id]
    );
    if (check.rows.length === 0) {
      return res.status(403).json({ message: 'Statement not found or access denied' });
    }

    // 2. Update the statement info
    await pool.query(
      'UPDATE statements SET store_name = $1, statement_date = $2, total_amount = $3, notes = $4 WHERE id = $5',
      [store_name, statement_date, total_amount, notes, statementId]
    );

    // 3. Delete old denominations
    await pool.query('DELETE FROM statement_denominations WHERE statement_id = $1', [statementId]);

    // 4. Insert new denominations
    for (const d of denominations) {
      const denomination = await pool.query(
        'SELECT id FROM denomination_master WHERE denomination_value = $1',
        [d.denomination]
      );

      if (denomination.rows.length > 0) {
        const denomId = denomination.rows[0].id;
        await pool.query(
          'INSERT INTO statement_denominations (statement_id, denomination_id, quantity, total) VALUES ($1, $2, $3, $4)',
          [statementId, denomId, d.quantity, d.total]
        );
      }
    }

    res.json({ message: 'Statement updated successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});


app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
