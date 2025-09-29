import express from "express"
import cors from "cors"
import sqlite3 from "sqlite3"
import { open } from "sqlite"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import dotenv from "dotenv"
import { fileURLToPath } from "url"
import path from "path"
import { dirname } from "path"
import nodemailer from "nodemailer"

dotenv.config()

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

const app = express()
const PORT = process.env.PORT || 5005
const JWT_SECRET =
  process.env.JWT_SECRET ||
  "1f82a5b1a6fe60a5b47972ef989a9da016b8678b931b63a7d776e66ef3cef03574b2b110f075755ae5b0028931871190026d3f14dc40cc0a73918a5121f64908b9413faf67ca0f1ac00a8ca41c65af34f1c4f23be1778b934b2e51d4988156e9f5dcbd1e1552fca0b73d43525e1d46efa38df0e53e8712c3a38a8009aea191503f59d9cfa5e9d0088fe47e61e9f0b22ee92f3ce3a888c9631b0f6f29973cf3532f87ed0a04d0d15ac78f1d0f2eed0a5ba3ab83e9ce8ecae4210f113e5d312aae8777e4d8f91d8b2ea1531589c393e7c87e9fb61fc1bcdb91c92194c3f34c09416a8bbf981a7bc173061ae87eb09d5e7e3d622be4d3fc7be00438f1be798ae115"

// Email configuration
const EMAIL_USER = "studioprovaep@libero.it"
const EMAIL_PASSWORD = "Ciaociao123!"
const EMAIL_HOST =  "smtp.libero.it"
const EMAIL_PORT = 465
const EMAIL_FROM =  "EP Studio <studioprovaep@libero.it>"
const FRONTEND_URL = "http://localhost:3003"

// Configure email transporter
let transporter = null

// Initialize email transporter if credentials are provided
if (EMAIL_PASSWORD) {
  transporter = nodemailer.createTransport({
    host: EMAIL_HOST,
    port: EMAIL_PORT,
    secure: EMAIL_PORT === 465, // true for 465, false for other ports
    auth: {
      user: EMAIL_USER,
      pass: EMAIL_PASSWORD,
    },
  })
}

// Email templates
const emailTemplates = {
  welcome: (name) => ({
    subject: "Benvenuto in EP Studio",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #333;">Benvenuto in EP Studio!</h1>
        <p>Ciao ${name},</p>
        <p>Grazie per esserti registrato su EP Studio. Siamo felici di averti con noi!</p>
        <p>Ora puoi prenotare i nostri studi di registrazione e iniziare a creare la tua musica.</p>
        <p>Visita il nostro sito per esplorare i nostri studi e i servizi che offriamo.</p>
        <a href="${FRONTEND_URL}" style="display: inline-block; background-color: #4a4a4a; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 15px;">Visita EP Studio</a>
        <p style="margin-top: 30px;">Cordiali saluti,<br>Il team di EP Studio</p>
      </div>
    `,
  }),
  bookingConfirmation: (booking, studioName, isGuest = false) => ({
    subject: "Conferma Prenotazione - EP Studio",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #333;">Prenotazione Confermata</h1>
        <p>Ciao ${isGuest ? booking.name : booking.name},</p>
        <p>La tua prenotazione è stata ricevuta con successo.</p>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <h3 style="margin-top: 0;">Dettagli della prenotazione:</h3>
          <p><strong>Studio:</strong> ${studioName}</p>
          <p><strong>Data:</strong> ${booking.date}</p>
          <p><strong>Orario:</strong> ${booking.startTime} - ${booking.endTime}</p>
          <p><strong>Con Tecnico:</strong> ${booking.withEngineer ? "Sì" : "No"}</p>
          <p><strong>Prezzo Totale:</strong> €${booking.totalPrice.toFixed(2)}</p>
          ${booking.notes ? `<p><strong>Note:</strong> ${booking.notes}</p>` : ""}
        </div>
        <p>Lo stato attuale della tua prenotazione è: <strong>${
          booking.status === "pending"
            ? "In attesa di conferma"
            : booking.status === "confirmed"
              ? "Confermata"
              : "Cancellata"
        }</strong></p>
        <p>Riceverai un'email di aggiornamento quando la tua prenotazione sarà confermata dal nostro staff.</p>
        ${
          !isGuest
            ? `<p>Puoi visualizzare e gestire le tue prenotazioni dal tuo account.</p>
               <a href="${FRONTEND_URL}/prenotazioni" style="display: inline-block; background-color: #4a4a4a; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 15px;">Le mie prenotazioni</a>`
            : ""
        }
        <p style="margin-top: 30px;">Cordiali saluti,<br>Il team di EP Studio</p>
      </div>
    `,
  }),
  bookingStatusUpdate: (booking, studioName, isGuest = false) => ({
    subject: `Aggiornamento Prenotazione - ${
      booking.status === "confirmed" ? "Confermata" : booking.status === "cancelled" ? "Cancellata" : "Aggiornata"
    }`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #333;">Aggiornamento Prenotazione</h1>
        <p>Ciao ${isGuest ? booking.name : booking.name},</p>
        <p>Lo stato della tua prenotazione è stato aggiornato a: <strong>${
          booking.status === "pending"
            ? "In attesa di conferma"
            : booking.status === "confirmed"
              ? "Confermata"
              : "Cancellata"
        }</strong></p>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <h3 style="margin-top: 0;">Dettagli della prenotazione:</h3>
          <p><strong>Studio:</strong> ${studioName}</p>
          <p><strong>Data:</strong> ${booking.date}</p>
          <p><strong>Orario:</strong> ${booking.startTime} - ${booking.endTime}</p>
          <p><strong>Con Tecnico:</strong> ${booking.withEngineer ? "Sì" : "No"}</p>
          <p><strong>Prezzo Totale:</strong> €${booking.totalPrice.toFixed(2)}</p>
          ${booking.notes ? `<p><strong>Note:</strong> ${booking.notes}</p>` : ""}
        </div>
        ${
          booking.status === "confirmed"
            ? `<p>Ti aspettiamo in studio! Ecco alcune informazioni utili:</p>
               <ul>
                 <li>Arriva 10-15 minuti prima dell'orario prenotato</li>
                 <li>Porta con te un documento d'identità</li>
                 <li>Se hai bisogno di assistenza, contattaci al numero: +39 123 456 7890</li>
               </ul>`
            : booking.status === "cancelled"
              ? `<p>La tua prenotazione è stata cancellata. Se hai domande o desideri prenotare nuovamente, non esitare a contattarci.</p>`
              : ""
        }
        ${
          !isGuest
            ? `<p>Puoi visualizzare e gestire le tue prenotazioni dal tuo account.</p>
               <a href="${FRONTEND_URL}/prenotazioni" style="display: inline-block; background-color: #4a4a4a; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 15px;">Le mie prenotazioni</a>`
            : ""
        }
        <p style="margin-top: 30px;">Cordiali saluti,<br>Il team di EP Studio</p>
      </div>
    `,
  }),
  bookingReminder: (booking, studioName, isGuest = false) => ({
    subject: "Promemoria: Prenotazione Studio Domani",
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h1 style="color: #333;">Promemoria Prenotazione</h1>
        <p>Ciao ${isGuest ? booking.name : booking.name},</p>
        <p>Ti ricordiamo che hai una prenotazione programmata per domani:</p>
        <div style="background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0;">
          <h3 style="margin-top: 0;">Dettagli della prenotazione:</h3>
          <p><strong>Studio:</strong> ${studioName}</p>
          <p><strong>Data:</strong> ${booking.date}</p>
          <p><strong>Orario:</strong> ${booking.startTime} - ${booking.endTime}</p>
          <p><strong>Con Tecnico:</strong> ${booking.withEngineer ? "Sì" : "No"}</p>
        </div>
        <p>Ti aspettiamo in studio! Ecco alcune informazioni utili:</p>
        <ul>
          <li>Arriva 10-15 minuti prima dell'orario prenotato</li>
          <li>Porta con te un documento d'identità</li>
          <li>Se hai bisogno di assistenza, contattaci al numero: +39 123 456 7890</li>
        </ul>
        <p>Se non puoi presentarti, ti preghiamo di cancellare la prenotazione con almeno 12 ore di anticipo.</p>
        ${
          !isGuest
            ? `<a href="${FRONTEND_URL}/prenotazioni" style="display: inline-block; background-color: #4a4a4a; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-top: 15px;">Gestisci prenotazione</a>`
            : ""
        }
        <p style="margin-top: 30px;">Cordiali saluti,<br>Il team di EP Studio</p>
      </div>
    `,
  }),
}

// Email sending function
async function sendEmail(to, template) {
  if (!transporter) {
    console.log("Email sending is not configured. Would have sent:", {
      to,
      subject: template.subject,
    })
    return
  }

  try {
    const info = await transporter.sendMail({
      from: EMAIL_FROM,
      to,
      subject: template.subject,
      html: template.html,
    })
    console.log("Email sent:", info.messageId)
    return info
  } catch (error) {
    console.error("Error sending email:", error)
    throw error
  }
}

// Middleware
app.use(cors())
app.use(express.json())

// Database setup
const dbPromise = open({
  filename: path.join(__dirname, "database.db"),
  driver: sqlite3.Database,
})

// Initialize database
async function initializeDatabase() {
  const db = await dbPromise

  // Users table
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      surname TEXT NOT NULL,
      artistName TEXT,
      phone TEXT,
      role TEXT DEFAULT 'user',
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `)

  // Studios table
  await db.exec(`
    CREATE TABLE IF NOT EXISTS studios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      hourlyRate REAL NOT NULL,
      hourlyRateWithEngineer REAL NOT NULL,
      equipment TEXT
    )
  `)

  // Bookings table
  await db.exec(`
    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      studioId INTEGER NOT NULL,
      service TEXT NOT NULL,
      date TEXT NOT NULL,
      startTime TEXT NOT NULL,
      endTime TEXT NOT NULL,
      withEngineer BOOLEAN DEFAULT 0,
      status TEXT DEFAULT 'pending',
      totalPrice REAL NOT NULL,
      notes TEXT,
      packageId INTEGER,
      paid BOOLEAN DEFAULT 0,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id),
      FOREIGN KEY (studioId) REFERENCES studios(id)
    )
  `)

  // Guest Bookings table
  await db.exec(`
    CREATE TABLE IF NOT EXISTS guest_bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      studioId INTEGER NOT NULL,
      service TEXT NOT NULL,
      date TEXT NOT NULL,
      startTime TEXT NOT NULL,
      endTime TEXT NOT NULL,
      withEngineer BOOLEAN DEFAULT 0,
      status TEXT DEFAULT 'pending',
      totalPrice REAL NOT NULL,
      notes TEXT,
      name TEXT NOT NULL,
      surname TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT,
      packageId INTEGER,
      paid BOOLEAN DEFAULT 0,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (studioId) REFERENCES studios(id)
    )
  `)

  await db.exec(`
    CREATE TABLE IF NOT EXISTS packages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      price REAL NOT NULL,
      hoursIncluded REAL NOT NULL,
      includesEngineer BOOLEAN DEFAULT 0,
      includesMixing BOOLEAN DEFAULT 0,
      isActive BOOLEAN DEFAULT 1,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      updatedAt DATETIME
    )
  `)

  const ensureColumn = async (table, column, definition) => {
    const pragma = await db.all(`PRAGMA table_info(${table})`)
    const exists = pragma.some((col) => col.name === column)
    if (!exists) {
      await db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`)
    }
  }

  await ensureColumn("bookings", "packageId", "INTEGER")
  await ensureColumn("bookings", "paid", "BOOLEAN DEFAULT 0")
  await ensureColumn("guest_bookings", "packageId", "INTEGER")
  await ensureColumn("guest_bookings", "paid", "BOOLEAN DEFAULT 0")
  await ensureColumn("portfolios", "videoUrl", "TEXT")

  // Email Queue table for tracking and retrying failed emails
  await db.exec(`
    CREATE TABLE IF NOT EXISTS email_queue (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      recipient TEXT NOT NULL,
      subject TEXT NOT NULL,
      content TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      retries INTEGER DEFAULT 0,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      sentAt DATETIME
    )
  `)

  // Portfolio table for showcasing projects
  await db.exec(`
    CREATE TABLE IF NOT EXISTS portfolios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT,
      imageUrl TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      updatedAt DATETIME
    )
  `)

  // Check if admin exists, if not create one
  const adminExists = await db.get("SELECT * FROM users WHERE role = ?", ["admin"])
  if (!adminExists) {
    const hashedPassword = await bcrypt.hash("admin123", 10)
    await db.run("INSERT INTO users (email, password, name, surname, role) VALUES (?, ?, ?, ?, ?)", [
      "admin@epstudio.com",
      hashedPassword,
      "Paul",
      "Manager",
      "admin",
    ])
  }

  // Check if studios exist, if not create them
  const studiosExist = await db.get("SELECT * FROM studios LIMIT 1")
  if (!studiosExist) {
    await db.run(
      "INSERT INTO studios (name, description, hourlyRate, hourlyRateWithEngineer, equipment) VALUES (?, ?, ?, ?, ?)",
      [
        "Studio 1",
        "Studio professionale con attrezzatura di alta qualità",
        35,
        45,
        JSON.stringify([
          "Focal Alpha Twin (Casse)",
          "Apollo Twin (Scheda Audio)",
          "iMac",
          "Neumann U87 AI (Microfono)",
          "MACKIE Big Knob Studio (Controller)",
          "M-Audio Oxygen Pro 61 (Midi Keyboard)",
        ]),
      ],
    )

    await db.run(
      "INSERT INTO studios (name, description, hourlyRate, hourlyRateWithEngineer, equipment) VALUES (?, ?, ?, ?, ?)",
      [
        "Studio 2",
        "Studio compatto ideale per registrazioni vocali e produzioni più semplici",
        30,
        40,
        JSON.stringify([
          "Yamaha HS7 (Casse)",
          "Apollo Solo (Scheda Audio)",
          "MacBook Air",
          "Neumann TLM 102 (Microfono)",
          "MACKIE Big Knob Studio (Controller)",
          "M-Audio Oxygen Pro 61 (Midi Keyboard)",
        ]),
      ],
    )
  }

  console.log("Database initialized successfully")
}

// Function to queue an email in the database
async function queueEmail(recipient, template) {
  try {
    const db = await dbPromise
    await db.run("INSERT INTO email_queue (recipient, subject, content) VALUES (?, ?, ?)", [
      recipient,
      template.subject,
      template.html,
    ])

    // Immediately process the email queue after queuing
    processEmailQueue().catch(err => console.error("Error processing email queue after enqueue:", err))
  } catch (error) {
    console.error("Error queueing email:", error)
  }
}

// Function to process the email queue (can be called periodically)
async function processEmailQueue() {
  if (!transporter) {
    console.log("Email sending is not configured. Skipping email queue processing.")
    return
  }

  try {
    const db = await dbPromise
    const pendingEmails = await db.all(
      "SELECT * FROM email_queue WHERE status = 'pending' AND retries < 3 ORDER BY createdAt ASC LIMIT 10",
    )

    for (const email of pendingEmails) {
      try {
        await transporter.sendMail({
          from: EMAIL_FROM,
          to: email.recipient,
          subject: email.subject,
          html: email.content,
        })

        // Update email status to sent
        await db.run("UPDATE email_queue SET status = 'sent', sentAt = CURRENT_TIMESTAMP WHERE id = ?", [email.id])
        console.log(`Queued email ${email.id} sent to ${email.recipient}`)
      } catch (error) {
        console.error(`Error sending queued email ${email.id}:`, error)

        // Increment retry count
        await db.run("UPDATE email_queue SET retries = retries + 1, status = ? WHERE id = ?", [
          error.message.substring(0, 100),
          email.id,
        ])
      }
    }
  } catch (error) {
    console.error("Error processing email queue:", error)
  }
}

// Set up a periodic task to process the email queue (every 5 minutes)
setInterval(processEmailQueue, 5 * 60 * 1000)

// Immediately process any queued emails on startup
processEmailQueue().catch(err => console.error("Error processing email queue on startup:", err))

// Function to send booking reminder emails for tomorrow's bookings
async function sendBookingReminders() {
  try {
    const db = await dbPromise

    // Get tomorrow's date in YYYY-MM-DD format
    const tomorrow = new Date()
    tomorrow.setDate(tomorrow.getDate() + 1)
    const tomorrowStr = tomorrow.toISOString().split("T")[0]

    // Get all confirmed bookings for tomorrow
    const regularBookings = await db.all(
      `
      SELECT b.*, u.name, u.surname, u.email, s.name as studioName
      FROM bookings b
      JOIN users u ON b.userId = u.id
      JOIN studios s ON b.studioId = s.id
      WHERE b.date = ? AND b.status = 'confirmed'
    `,
      [tomorrowStr],
    )

    // Get all confirmed guest bookings for tomorrow
    const guestBookings = await db.all(
      `
      SELECT b.*, s.name as studioName
      FROM guest_bookings b
      JOIN studios s ON b.studioId = s.id
      WHERE b.date = ? AND b.status = 'confirmed'
    `,
      [tomorrowStr],
    )

    // Send reminders for regular bookings
    for (const booking of regularBookings) {
      try {
        const template = emailTemplates.bookingReminder(booking, booking.studioName)
        await queueEmail(booking.email, template)
        console.log(`Reminder queued for booking ${booking.id} to ${booking.email}`)
      } catch (error) {
        console.error(`Error queueing reminder for booking ${booking.id}:`, error)
      }
    }

    // Send reminders for guest bookings
    for (const booking of guestBookings) {
      try {
        const template = emailTemplates.bookingReminder(booking, booking.studioName, true)
        await queueEmail(booking.email, template)
        console.log(`Reminder queued for guest booking ${booking.id} to ${booking.email}`)
      } catch (error) {
        console.error(`Error queueing reminder for guest booking ${booking.id}:`, error)
      }
    }

    console.log(`Processed reminders for ${regularBookings.length + guestBookings.length} bookings for ${tomorrowStr}`)
  } catch (error) {
    console.error("Error sending booking reminders:", error)
  }
}

// Set up a daily task to send booking reminders (runs at 10:00 AM)
function scheduleReminderCheck() {
  const now = new Date()
  const scheduledTime = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate(),
    10, // 10:00 AM
    0,
    0,
  )

  // If it's already past 10:00 AM, schedule for tomorrow
  if (now > scheduledTime) {
    scheduledTime.setDate(scheduledTime.getDate() + 1)
  }

  const timeUntilScheduled = scheduledTime.getTime() - now.getTime()

  // Schedule the first run
  setTimeout(() => {
    sendBookingReminders()
    // Then schedule it to run daily
    setInterval(sendBookingReminders, 24 * 60 * 60 * 1000)
  }, timeUntilScheduled)

  console.log(`Booking reminders scheduled to run at ${scheduledTime.toLocaleTimeString()} and then daily`)
}

// Start the reminder scheduler
scheduleReminderCheck()

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) return res.status(401).json({ message: "Accesso negato" })

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Token non valido" })
    req.user = user
    next()
  })
}

// Admin middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Accesso riservato agli amministratori" })
  }
  next()
}

// Initialize database on server start
initializeDatabase().catch((err) => {
  console.error("Database initialization error:", err)
})

// AUTH ROUTES
app.post("/api/register", async (req, res) => {
  try {
    const { email, password, name, surname, artistName, phone } = req.body

    if (!email || !password || !name || !surname) {
      return res.status(400).json({ message: "Tutti i campi obbligatori devono essere compilati" })
    }

    const db = await dbPromise
    const existingUser = await db.get("SELECT * FROM users WHERE email = ?", [email])

    if (existingUser) {
      return res.status(400).json({ message: "Email già registrata" })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const result = await db.run(
      "INSERT INTO users (email, password, name, surname, artistName, phone) VALUES (?, ?, ?, ?, ?, ?)",
      [email, hashedPassword, name, surname, artistName || null, phone || null],
    )

    const token = jwt.sign({ id: result.lastID, email, role: "user" }, JWT_SECRET, { expiresIn: "7d" })

    // Send welcome email
    try {
      const template = emailTemplates.welcome(name)
      await queueEmail(email, template)
    } catch (emailError) {
      console.error("Error sending welcome email:", emailError)
      // Continue with registration even if email fails
    }

    res.status(201).json({
      message: "Utente registrato con successo",
      token,
      user: {
        id: result.lastID,
        email,
        name,
        surname,
        artistName,
        role: "user",
      },
    })
  } catch (error) {
    console.error("Registration error:", error)
    res.status(500).json({ message: "Errore durante la registrazione" })
  }
})

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body

    if (!email || !password) {
      return res.status(400).json({ message: "Email e password sono richiesti" })
    }

    const db = await dbPromise
    const user = await db.get("SELECT * FROM users WHERE email = ?", [email])

    if (!user) {
      return res.status(401).json({ message: "Credenziali non valide" })
    }

    const validPassword = await bcrypt.compare(password, user.password)

    if (!validPassword) {
      return res.status(401).json({ message: "Credenziali non valide" })
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: "7d" })

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        surname: user.surname,
        artistName: user.artistName,
        role: user.role,
      },
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({ message: "Errore durante il login" })
  }
})

app.get("/api/me", authenticateToken, async (req, res) => {
  try {
    const db = await dbPromise
    const user = await db.get("SELECT id, email, name, surname, artistName, phone, role FROM users WHERE id = ?", [
      req.user.id,
    ])

    if (!user) {
      return res.status(404).json({ message: "Utente non trovato" })
    }

    res.json({ user })
  } catch (error) {
    console.error("Get user error:", error)
    res.status(500).json({ message: "Errore durante il recupero dei dati utente" })
  }
})

// STUDIOS ROUTES
app.get("/api/studios", async (req, res) => {
  try {
    const db = await dbPromise
    const studios = await db.all("SELECT * FROM studios")

    // Parse equipment JSON
    studios.forEach((studio) => {
      if (studio.equipment) {
        try {
          studio.equipment = JSON.parse(studio.equipment)
        } catch (e) {
          studio.equipment = []
        }
      }
    })

    res.json({ studios })
  } catch (error) {
    console.error("Get studios error:", error)
    res.status(500).json({ message: "Errore durante il recupero degli studi" })
  }
})

app.get("/api/studios/:id", async (req, res) => {
  try {
    const { id } = req.params
    const db = await dbPromise
    const studio = await db.get("SELECT * FROM studios WHERE id = ?", [id])

    if (!studio) {
      return res.status(404).json({ message: "Studio non trovato" })
    }

    // Parse equipment JSON
    if (studio.equipment) {
      try {
        studio.equipment = JSON.parse(studio.equipment)
      } catch (e) {
        studio.equipment = []
      }
    }

    res.json({ studio })
  } catch (error) {
    console.error("Get studio error:", error)
    res.status(500).json({ message: "Errore durante il recupero dello studio" })
  }
})

// PACKAGES ROUTES
app.get("/api/packages", async (req, res) => {
  try {
    const db = await dbPromise
    const includeInactive = req.query.includeInactive === "true"
    const rawPackages = await db.all(
      includeInactive ? "SELECT * FROM packages" : "SELECT * FROM packages WHERE isActive = 1",
    )
    res.json({ packages: rawPackages.map(normalizePackage) })
  } catch (error) {
    console.error("Get packages error:", error)
    res.status(500).json({ message: "Errore durante il recupero dei pacchetti" })
  }
})

app.get("/api/admin/packages", authenticateToken, isAdmin, async (req, res) => {
  try {
    const db = await dbPromise
    const packages = await db.all("SELECT * FROM packages ORDER BY createdAt DESC")
    res.json({ packages: packages.map(normalizePackage) })
  } catch (error) {
    console.error("Admin get packages error:", error)
    res.status(500).json({ message: "Errore durante il recupero dei pacchetti" })
  }
})

app.post("/api/packages", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, description, price, hoursIncluded, includesEngineer, includesMixing, isActive } = req.body

    if (!name || !price || !hoursIncluded) {
      return res.status(400).json({ message: "Nome, prezzo e ore incluse sono obbligatori" })
    }

    const db = await dbPromise
    const result = await db.run(
      `INSERT INTO packages (name, description, price, hoursIncluded, includesEngineer, includesMixing, isActive)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        description || null,
        Number(price),
        Number(hoursIncluded),
        includesEngineer ? 1 : 0,
        includesMixing ? 1 : 0,
        isActive === false ? 0 : 1,
      ],
    )

    const created = await db.get("SELECT * FROM packages WHERE id = ?", [result.lastID])
    res.status(201).json(normalizePackage(created))
  } catch (error) {
    console.error("Create package error:", error)
    res.status(500).json({ message: "Errore durante la creazione del pacchetto" })
  }
})

app.put("/api/packages/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params
    const { name, description, price, hoursIncluded, includesEngineer, includesMixing, isActive } = req.body

    const db = await dbPromise
    const existing = await db.get("SELECT * FROM packages WHERE id = ?", [id])
    if (!existing) {
      return res.status(404).json({ message: "Pacchetto non trovato" })
    }

    await db.run(
      `UPDATE packages
       SET name = COALESCE(?, name),
           description = COALESCE(?, description),
           price = COALESCE(?, price),
           hoursIncluded = COALESCE(?, hoursIncluded),
           includesEngineer = COALESCE(?, includesEngineer),
           includesMixing = COALESCE(?, includesMixing),
           isActive = COALESCE(?, isActive),
           updatedAt = CURRENT_TIMESTAMP
       WHERE id = ?`,
      [
        name || null,
        description !== undefined ? description : null,
        price !== undefined ? Number(price) : null,
        hoursIncluded !== undefined ? Number(hoursIncluded) : null,
        includesEngineer !== undefined ? (includesEngineer ? 1 : 0) : null,
        includesMixing !== undefined ? (includesMixing ? 1 : 0) : null,
        isActive !== undefined ? (isActive ? 1 : 0) : null,
        id,
      ],
    )

    const updated = await db.get("SELECT * FROM packages WHERE id = ?", [id])
    res.json(normalizePackage(updated))
  } catch (error) {
    console.error("Update package error:", error)
    res.status(500).json({ message: "Errore durante l'aggiornamento del pacchetto" })
  }
})

app.delete("/api/packages/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params
    const db = await dbPromise
    await db.run("DELETE FROM packages WHERE id = ?", [id])
    res.json({ message: "Pacchetto eliminato" })
  } catch (error) {
    console.error("Delete package error:", error)
    res.status(500).json({ message: "Errore durante l'eliminazione del pacchetto" })
  }
})

const GAP_MINUTES = 60
const MIN_DURATION_MINUTES = 60
const MAX_DURATION_MINUTES = 8 * 60

const timeToMinutes = (time) => {
  const [hours, minutes] = time.split(":").map((part) => Number.parseInt(part, 10))
  return hours * 60 + (minutes || 0)
}

const hasTimeConflict = (existing, startMinutes, endMinutes) => {
  const existingStart = timeToMinutes(existing.startTime)
  const existingEnd = timeToMinutes(existing.endTime)

  // new booking ends well before existing starts (with required gap)
  if (endMinutes + GAP_MINUTES <= existingStart) return false
  // new booking starts well after existing ends (with required gap)
  if (startMinutes >= existingEnd + GAP_MINUTES) return false
  // otherwise conflict
  return true
}

const normalizePackage = (pack) =>
  pack
    ? {
        ...pack,
        includesEngineer: !!pack.includesEngineer,
        includesMixing: !!pack.includesMixing,
        isActive: pack.isActive === 1 || pack.isActive === true,
      }
    : pack

// BOOKINGS ROUTES
app.post("/api/bookings", authenticateToken, async (req, res) => {
  try {
    const { studioId, service, date, startTime, endTime, withEngineer, notes, packageId, paid } = req.body
    const userId = req.user.id

    if (!studioId || !service || !date || !startTime || !endTime) {
      return res.status(400).json({ message: "Tutti i campi obbligatori devono essere compilati" })
    }

    const startMinutes = timeToMinutes(startTime)
    const endMinutes = timeToMinutes(endTime)
    if (Number.isNaN(startMinutes) || Number.isNaN(endMinutes) || endMinutes <= startMinutes) {
      return res.status(400).json({ message: "Orari non validi" })
    }

    const durationMinutes = endMinutes - startMinutes

    if (durationMinutes < MIN_DURATION_MINUTES) {
      return res.status(400).json({ message: "La prenotazione deve essere di almeno 1 ora" })
    }

    if (durationMinutes > MAX_DURATION_MINUTES) {
      return res.status(400).json({ message: "La prenotazione non può superare le 8 ore" })
    }

    // Check if the studio is available for the requested time
    const db = await dbPromise

    const bookingsSameDay = await db.all(
      `SELECT startTime, endTime FROM bookings WHERE studioId = ? AND date = ? AND status != 'cancelled'`,
      [studioId, date],
    )
    const guestBookingsSameDay = await db.all(
      `SELECT startTime, endTime FROM guest_bookings WHERE studioId = ? AND date = ? AND status != 'cancelled'`,
      [studioId, date],
    )

    const hasConflict = [...bookingsSameDay, ...guestBookingsSameDay].some((existing) =>
      hasTimeConflict(existing, startMinutes, endMinutes),
    )

    if (hasConflict) {
      return res.status(400).json({ message: "Lo studio non è disponibile nell'orario richiesto" })
    }

    // Get studio price
    const studio = await db.get("SELECT * FROM studios WHERE id = ?", [studioId])

    if (!studio) {
      return res.status(404).json({ message: "Studio non trovato" })
    }

    let resolvedWithEngineer = !!withEngineer
    let totalPrice = 0
    let resolvedPackageId = null

    if (packageId) {
      const packageData = await db.get("SELECT * FROM packages WHERE id = ? AND isActive = 1", [packageId])
      if (!packageData) {
        return res.status(400).json({ message: "Pacchetto non valido o non attivo" })
      }

      const packageMinutes = packageData.hoursIncluded * 60
      if (Math.abs(packageMinutes - durationMinutes) > 1) {
        return res.status(400).json({ message: "La durata selezionata non corrisponde al pacchetto scelto" })
      }

      resolvedWithEngineer = packageData.includesEngineer ? true : resolvedWithEngineer
      totalPrice = packageData.price
      resolvedPackageId = packageData.id
    } else {
      const hourlyRate = resolvedWithEngineer ? studio.hourlyRateWithEngineer : studio.hourlyRate
      totalPrice = Number((hourlyRate * (durationMinutes / 60)).toFixed(2))
    }

    // Create booking
    const result = await db.run(
      `INSERT INTO bookings 
       (userId, studioId, service, date, startTime, endTime, withEngineer, totalPrice, notes, packageId, paid) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        userId,
        studioId,
        service,
        date,
        startTime,
        endTime,
        resolvedWithEngineer ? 1 : 0,
        totalPrice,
        notes || null,
        resolvedPackageId,
        paid ? 1 : 0,
      ],
    )

    const booking = await db.get(
      `SELECT b.*, u.name, u.surname, u.email, p.name AS packageName 
       FROM bookings b 
       JOIN users u ON b.userId = u.id 
       LEFT JOIN packages p ON b.packageId = p.id
       WHERE b.id = ?`,
      [result.lastID],
    )

    booking.paid = !!booking.paid

    // Send booking confirmation email
    try {
      const template = emailTemplates.bookingConfirmation(booking, studio.name)
      await queueEmail(booking.email, template)
    } catch (emailError) {
      console.error("Error sending booking confirmation email:", emailError)
      // Continue with booking creation even if email fails
    }

    res.status(201).json({
      message: "Prenotazione creata con successo",
      booking,
    })
  } catch (error) {
    console.error("Create booking error:", error)
    res.status(500).json({ message: "Errore durante la creazione della prenotazione" })
  }
})

// GUEST BOOKINGS ROUTE
app.post("/api/guest-bookings", async (req, res) => {
  try {
    const { studioId, service, date, startTime, endTime, withEngineer, notes, guestInfo, packageId, paid } = req.body

    if (!studioId || !service || !date || !startTime || !endTime || !guestInfo) {
      return res.status(400).json({ message: "Tutti i campi obbligatori devono essere compilati" })
    }

    const { name, surname, email } = guestInfo
    if (!name || !surname || !email) {
      return res.status(400).json({ message: "Nome, cognome ed email sono obbligatori" })
    }

    const startMinutes = timeToMinutes(startTime)
    const endMinutes = timeToMinutes(endTime)
    if (Number.isNaN(startMinutes) || Number.isNaN(endMinutes) || endMinutes <= startMinutes) {
      return res.status(400).json({ message: "Orari non validi" })
    }

    const durationMinutes = endMinutes - startMinutes
    if (durationMinutes < MIN_DURATION_MINUTES) {
      return res.status(400).json({ message: "La prenotazione deve essere di almeno 1 ora" })
    }
    if (durationMinutes > MAX_DURATION_MINUTES) {
      return res.status(400).json({ message: "La prenotazione non può superare le 8 ore" })
    }

    const db = await dbPromise
    const bookingsSameDay = await db.all(
      `SELECT startTime, endTime FROM bookings WHERE studioId = ? AND date = ? AND status != 'cancelled'`,
      [studioId, date],
    )
    const guestBookingsSameDay = await db.all(
      `SELECT startTime, endTime FROM guest_bookings WHERE studioId = ? AND date = ? AND status != 'cancelled'`,
      [studioId, date],
    )

    const hasConflict = [...bookingsSameDay, ...guestBookingsSameDay].some((existing) =>
      hasTimeConflict(existing, startMinutes, endMinutes),
    )

    if (hasConflict) {
      return res.status(400).json({ message: "Lo studio non è disponibile nell'orario richiesto" })
    }

    const studio = await db.get("SELECT * FROM studios WHERE id = ?", [studioId])
    if (!studio) {
      return res.status(404).json({ message: "Studio non trovato" })
    }

    let resolvedWithEngineer = !!withEngineer
    let resolvedPackageId = null
    let totalPrice = 0

    if (packageId) {
      const packageData = await db.get("SELECT * FROM packages WHERE id = ? AND isActive = 1", [packageId])
      if (!packageData) {
        return res.status(400).json({ message: "Pacchetto non valido o non attivo" })
      }

      const packageMinutes = packageData.hoursIncluded * 60
      if (Math.abs(packageMinutes - durationMinutes) > 1) {
        return res.status(400).json({ message: "La durata selezionata non corrisponde al pacchetto scelto" })
      }

      resolvedWithEngineer = packageData.includesEngineer ? true : resolvedWithEngineer
      totalPrice = packageData.price
      resolvedPackageId = packageData.id
    } else {
      const hourlyRate = resolvedWithEngineer ? studio.hourlyRateWithEngineer : studio.hourlyRate
      totalPrice = Number((hourlyRate * (durationMinutes / 60)).toFixed(2))
    }

    const result = await db.run(
      `INSERT INTO guest_bookings        (studioId, service, date, startTime, endTime, withEngineer, totalPrice, notes, name, surname, email, phone, packageId, paid)        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        studioId,
        service,
        date,
        startTime,
        endTime,
        resolvedWithEngineer ? 1 : 0,
        totalPrice,
        notes || null,
        name,
        surname,
        email,
        guestInfo.phone || null,
        resolvedPackageId,
        paid ? 1 : 0,
      ],
    )

    const booking = await db.get(
      `SELECT gb.*, s.name as studioName, p.name as packageName
       FROM guest_bookings gb
       JOIN studios s ON gb.studioId = s.id
       LEFT JOIN packages p ON gb.packageId = p.id
       WHERE gb.id = ?`,
      [result.lastID],
    )

    booking.paid = !!booking.paid

    try {
      const template = emailTemplates.bookingConfirmation(booking, booking.studioName, true)
      await queueEmail(email, template)
    } catch (emailError) {
      console.error("Error sending guest booking confirmation email:", emailError)
    }

    res.status(201).json({
      message: "Prenotazione effettuata con successo",
      booking,
    })
  } catch (error) {
    console.error("Guest booking error:", error)
    res.status(500).json({ message: "Errore durante la prenotazione" })
  }
})


app.get("/api/bookings", authenticateToken, async (req, res) => {
  try {
    const db = await dbPromise
    const {
      status,
      studio,
      from,
      to,
      service,
      packageId,
      payment,
      withEngineer,
      search,
    } = req.query

    const formatFilterValue = (value) => (typeof value === "string" && value.trim() !== "" ? value.trim() : null)

    const adminBaseQuery = `
      SELECT b.*, u.name, u.surname, u.email, u.phone, u.artistName,
             s.name as studioName, p.name as packageName
      FROM bookings b
      JOIN users u ON b.userId = u.id
      JOIN studios s ON b.studioId = s.id
      LEFT JOIN packages p ON b.packageId = p.id
      WHERE 1=1
    `

    const userBaseQuery = `
      SELECT b.*, s.name as studioName, p.name as packageName
      FROM bookings b
      JOIN studios s ON b.studioId = s.id
      LEFT JOIN packages p ON b.packageId = p.id
      WHERE b.userId = ?
    `

    const conditions = []
    const params = []

    const addFilter = (condition, value) => {
      if (value !== null && value !== undefined && value !== "") {
        conditions.push(condition)
        params.push(value)
      }
    }

    const statusFilter = formatFilterValue(status)
    const studioFilter = formatFilterValue(studio)
    const serviceFilter = formatFilterValue(service)
    const packageFilter = formatFilterValue(packageId)
    const paymentFilter = formatFilterValue(payment)
    const searchTerm = formatFilterValue(search)
    const engineerFilter = formatFilterValue(withEngineer)
    const fromFilter = formatFilterValue(from)
    const toFilter = formatFilterValue(to)

    if (statusFilter && statusFilter !== "all") addFilter("b.status = ?", statusFilter)
    if (studioFilter && studioFilter !== "all") addFilter("s.name = ?", studioFilter)
    if (serviceFilter && serviceFilter !== "all") addFilter("b.service = ?", serviceFilter)
    if (packageFilter && packageFilter !== "all") addFilter("(p.name = ? OR CAST(b.packageId AS TEXT) = ?)", packageFilter)
    if (paymentFilter && paymentFilter !== "all") {
      addFilter("b.paid = ?", paymentFilter === "paid" ? 1 : 0)
    }
    if (engineerFilter && engineerFilter !== "all") {
      addFilter("b.withEngineer = ?", engineerFilter === "with" ? 1 : 0)
    }
    if (fromFilter) addFilter("b.date >= ?", fromFilter)
    if (toFilter) addFilter("b.date <= ?", toFilter)

    let query
    let finalParams

    if (req.user.role === "admin") {
      query = adminBaseQuery
      if (searchTerm) {
        conditions.push(
          "(u.name LIKE ? OR u.surname LIKE ? OR u.email LIKE ? OR s.name LIKE ? OR COALESCE(p.name, '') LIKE ? OR CAST(b.id AS TEXT) LIKE ?)",
        )
        for (let i = 0; i < 6; i += 1) params.push(`%${searchTerm}%`)
      }
      if (conditions.length > 0) query += ` AND ${conditions.join(" AND ")}`
      query += " ORDER BY b.date DESC, b.startTime ASC"
      finalParams = params
    } else {
      query = userBaseQuery
      if (searchTerm) {
        conditions.push("(s.name LIKE ? OR COALESCE(p.name, '') LIKE ? OR CAST(b.id AS TEXT) LIKE ?)")
        for (let i = 0; i < 3; i += 1) params.push(`%${searchTerm}%`)
      }
      if (conditions.length > 0) query += ` AND ${conditions.join(" AND ")}`
      query += " ORDER BY b.date DESC, b.startTime ASC"
      finalParams = [req.user.id, ...params]
    }

    const bookings = await db.all(query, finalParams)

    bookings.forEach((booking) => {
      booking.paid = !!booking.paid
    })

    res.json({ bookings })
  } catch (error) {
    console.error("Get bookings error:", error)
    res.status(500).json({ message: "Errore durante il recupero delle prenotazioni" })
  }
})

app.get("/api/bookings/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const db = await dbPromise

    let booking

    if (req.user.role === "admin") {
      booking = await db.get(
        `
        SELECT b.*, u.name, u.surname, u.email, u.phone, u.artistName, s.name as studioName, p.name as packageName
        FROM bookings b
        JOIN users u ON b.userId = u.id
        JOIN studios s ON b.studioId = s.id
        LEFT JOIN packages p ON b.packageId = p.id
        WHERE b.id = ?
      `,
        [id],
      )
    } else {
      booking = await db.get(
        `
        SELECT b.*, s.name as studioName, p.name as packageName
        FROM bookings b
        JOIN studios s ON b.studioId = s.id
        LEFT JOIN packages p ON b.packageId = p.id
        WHERE b.id = ? AND b.userId = ?
      `,
        [id, req.user.id],
      )
    }

    if (!booking) {
      return res.status(404).json({ message: "Prenotazione non trovata" })
    }

    booking.paid = !!booking.paid

    res.json({ booking })
  } catch (error) {
    console.error("Get booking error:", error)
    res.status(500).json({ message: "Errore durante il recupero della prenotazione" })
  }
})

app.put("/api/bookings/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const { status, notes, paid, totalPrice, startTime, endTime, withEngineer, packageId } = req.body
    const db = await dbPromise

    const booking = await db.get(
      `SELECT b.*, u.email, u.name, u.surname, s.name as studioName
       FROM bookings b
       JOIN users u ON b.userId = u.id
       JOIN studios s ON b.studioId = s.id
       WHERE b.id = ?`,
      [id],
    )

    if (!booking) {
      return res.status(404).json({ message: "Prenotazione non trovata" })
    }

    if (status && req.user.role !== "admin") {
      return res.status(403).json({ message: "Non autorizzato a modificare lo stato della prenotazione" })
    }

    if (req.user.role !== "admin" && booking.userId !== req.user.id) {
      return res.status(403).json({ message: "Non autorizzato a modificare questa prenotazione" })
    }

    const newStartTime = startTime || booking.startTime
    const newEndTime = endTime || booking.endTime
    const newStartMinutes = timeToMinutes(newStartTime)
    const newEndMinutes = timeToMinutes(newEndTime)

    if (newEndMinutes <= newStartMinutes) {
      return res.status(400).json({ message: "Orari non validi" })
    }

    const durationMinutes = newEndMinutes - newStartMinutes
    if (durationMinutes < MIN_DURATION_MINUTES) {
      return res.status(400).json({ message: "La prenotazione deve essere di almeno 1 ora" })
    }
    if (durationMinutes > MAX_DURATION_MINUTES) {
      return res.status(400).json({ message: "La prenotazione non può superare le 8 ore" })
    }

    let resolvedWithEngineer = typeof withEngineer === "boolean" ? withEngineer : !!booking.withEngineer
    let resolvedPackageId = packageId !== undefined ? packageId : booking.packageId
    let resolvedTotalPrice = typeof totalPrice === "number" ? Number(totalPrice.toFixed(2)) : booking.totalPrice

    if (resolvedPackageId) {
      const packageData = await db.get("SELECT * FROM packages WHERE id = ?", [resolvedPackageId])
      if (!packageData) {
        return res.status(400).json({ message: "Pacchetto specificato non valido" })
      }

      const packageMinutes = packageData.hoursIncluded * 60
      if (Math.abs(packageMinutes - durationMinutes) > 1) {
        return res.status(400).json({ message: "La durata non corrisponde al pacchetto selezionato" })
      }

      resolvedWithEngineer = packageData.includesEngineer ? true : resolvedWithEngineer
      resolvedTotalPrice = packageData.price
    }

    const bookingsSameDay = await db.all(
      `SELECT startTime, endTime FROM bookings WHERE studioId = ? AND date = ? AND id != ? AND status != 'cancelled'`,
      [booking.studioId, booking.date, id],
    )
    const guestBookingsSameDay = await db.all(
      `SELECT startTime, endTime FROM guest_bookings WHERE studioId = ? AND date = ? AND status != 'cancelled'`,
      [booking.studioId, booking.date],
    )

    const hasConflict = [...bookingsSameDay, ...guestBookingsSameDay].some((existing) =>
      hasTimeConflict(existing, newStartMinutes, newEndMinutes),
    )

    if (hasConflict) {
      return res.status(400).json({ message: "Orario non disponibile per la modifica richiesta" })
    }

    await db.run(
      `UPDATE bookings
       SET status = COALESCE(?, status),
           notes = COALESCE(?, notes),
           paid = COALESCE(?, paid),
           totalPrice = ?,
           startTime = ?,
           endTime = ?,
           withEngineer = ?,
           packageId = ?
       WHERE id = ?`,
      [
        status || null,
        notes !== undefined ? notes : null,
        paid === undefined ? null : paid ? 1 : 0,
        resolvedTotalPrice,
        newStartTime,
        newEndTime,
        resolvedWithEngineer ? 1 : 0,
        resolvedPackageId || null,
        id,
      ],
    )

    if (status && status !== booking.status) {
      try {
        const updatedBooking = { ...booking, status }
        const template = emailTemplates.bookingStatusUpdate(updatedBooking, booking.studioName)
        await queueEmail(booking.email, template)
      } catch (emailError) {
        console.error("Error sending booking status update email:", emailError)
      }
    }

    const updatedBooking = await db.get(
      `SELECT b.*, u.email, u.name, u.surname, s.name as studioName, p.name as packageName
       FROM bookings b
       JOIN users u ON b.userId = u.id
       JOIN studios s ON b.studioId = s.id
       LEFT JOIN packages p ON b.packageId = p.id
       WHERE b.id = ?`,
      [id],
    )

    updatedBooking.paid = !!updatedBooking.paid

    res.json({
      message: "Prenotazione aggiornata con successo",
      booking: updatedBooking,
    })
  } catch (error) {
    console.error("Update booking error:", error)
    res.status(500).json({ message: "Errore durante l'aggiornamento della prenotazione" })
  }
})

app.delete("/api/bookings/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params
    const db = await dbPromise

    // Check if booking exists
    const booking = await db.get(
      `SELECT b.*, u.email, u.name, u.surname, s.name as studioName
       FROM bookings b
       JOIN users u ON b.userId = u.id
       JOIN studios s ON b.studioId = s.id
       WHERE b.id = ?`,
      [id],
    )

    if (!booking) {
      return res.status(404).json({ message: "Prenotazione non trovata" })
    }

    // Only admin or booking owner can cancel
    if (req.user.role !== "admin" && booking.userId !== req.user.id) {
      return res.status(403).json({ message: "Non autorizzato a cancellare questa prenotazione" })
    }

    // Check cancellation policy (12 hours before)
    if (req.user.role !== "admin") {
      const bookingDate = new Date(`${booking.date}T${booking.startTime}`)
      const now = new Date()
      const hoursDifference = (bookingDate - now) / (1000 * 60 * 60)

      if (hoursDifference < 12) {
        return res.status(400).json({
          message: "Non è possibile cancellare la prenotazione meno di 12 ore prima dell'inizio",
        })
      }
    }

    // Update booking status to cancelled
    await db.run("UPDATE bookings SET status = ? WHERE id = ?", ["cancelled", id])

    // Send cancellation email
    try {
      const cancelledBooking = { ...booking, status: "cancelled" }
      const template = emailTemplates.bookingStatusUpdate(cancelledBooking, booking.studioName)
      await queueEmail(booking.email, template)
    } catch (emailError) {
      console.error("Error sending booking cancellation email:", emailError)
    }

    res.json({ message: "Prenotazione cancellata con successo" })
  } catch (error) {
    console.error("Cancel booking error:", error)
    res.status(500).json({ message: "Errore durante la cancellazione della prenotazione" })
  }
})

// ADMIN ROUTES
app.get("/api/admin/users", authenticateToken, isAdmin, async (req, res) => {
  try {
    const db = await dbPromise
    const users = await db.all(`
      SELECT u.id, u.email, u.name, u.surname, u.artistName, u.phone, u.role, u.createdAt,
             COALESCE(b.bookingsCount, 0) as bookingsCount,
             COALESCE(b.totalRevenue, 0) as totalRevenue
      FROM users u
      LEFT JOIN (
        SELECT userId, COUNT(*) as bookingsCount, SUM(totalPrice) as totalRevenue
        FROM bookings
        GROUP BY userId
      ) b ON b.userId = u.id
      ORDER BY u.createdAt DESC
    `)

    res.json({ users })
  } catch (error) {
    console.error("Get users error:", error)
    res.status(500).json({ message: "Errore durante il recupero degli utenti" })
  }
})

// Add endpoint to get all guest bookings for admin
app.get("/api/admin/guest-bookings", authenticateToken, isAdmin, async (req, res) => {
  try {
    const db = await dbPromise

    const guestBookings = await db.all(`
      SELECT b.*, s.name as studioName, p.name as packageName
      FROM guest_bookings b
      JOIN studios s ON b.studioId = s.id
      LEFT JOIN packages p ON b.packageId = p.id
      ORDER BY b.date DESC, b.startTime ASC
    `)

    guestBookings.forEach((booking) => {
      booking.paid = !!booking.paid
    })

    res.json({ guestBookings })
  } catch (error) {
    console.error("Get guest bookings error:", error)
    res.status(500).json({ message: "Errore durante il recupero delle prenotazioni ospiti" })
  }
})

// Add endpoint to update guest booking status
app.put("/api/admin/guest-bookings/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params
    const { status, notes, paid, totalPrice, startTime, endTime, withEngineer, packageId } = req.body
    const db = await dbPromise

    const booking = await db.get(
      `SELECT b.*, s.name as studioName
       FROM guest_bookings b
       JOIN studios s ON b.studioId = s.id
       WHERE b.id = ?`,
      [id],
    )

    if (!booking) {
      return res.status(404).json({ message: "Prenotazione non trovata" })
    }

    const newStart = startTime || booking.startTime
    const newEnd = endTime || booking.endTime
    const startMinutes = timeToMinutes(newStart)
    const endMinutes = timeToMinutes(newEnd)

    if (endMinutes <= startMinutes) {
      return res.status(400).json({ message: "Orari non validi" })
    }

    const durationMinutes = endMinutes - startMinutes
    if (durationMinutes < MIN_DURATION_MINUTES) {
      return res.status(400).json({ message: "La prenotazione deve essere di almeno 1 ora" })
    }

    const bookingsSameDay = await db.all(
      `SELECT startTime, endTime FROM bookings WHERE studioId = ? AND date = ? AND status != 'cancelled'`,
      [booking.studioId, booking.date],
    )
    const guestBookingsSameDay = await db.all(
      `SELECT startTime, endTime FROM guest_bookings WHERE studioId = ? AND date = ? AND id != ? AND status != 'cancelled'`,
      [booking.studioId, booking.date, id],
    )

    const hasConflict = [...bookingsSameDay, ...guestBookingsSameDay].some((existing) =>
      hasTimeConflict(existing, startMinutes, endMinutes),
    )

    if (hasConflict) {
      return res.status(400).json({ message: "Orario non disponibile" })
    }

    let resolvedPackageId = packageId !== undefined ? packageId : booking.packageId
    let resolvedWithEngineer = typeof withEngineer === "boolean" ? withEngineer : !!booking.withEngineer
    let resolvedTotalPrice = typeof totalPrice === "number" ? Number(totalPrice.toFixed(2)) : booking.totalPrice

    if (resolvedPackageId) {
      const packageData = await db.get("SELECT * FROM packages WHERE id = ?", [resolvedPackageId])
      if (!packageData) {
        return res.status(400).json({ message: "Pacchetto specificato non valido" })
      }
      const packageMinutes = packageData.hoursIncluded * 60
      if (Math.abs(packageMinutes - durationMinutes) > 1) {
        return res.status(400).json({ message: "La durata non corrisponde al pacchetto selezionato" })
      }
      resolvedWithEngineer = packageData.includesEngineer ? true : resolvedWithEngineer
      resolvedTotalPrice = packageData.price
    }

    await db.run(
      `UPDATE guest_bookings
       SET status = COALESCE(?, status),
           notes = COALESCE(?, notes),
           paid = COALESCE(?, paid),
           startTime = ?,
           endTime = ?,
           withEngineer = ?,
           totalPrice = ?,
           packageId = ?
       WHERE id = ?`,
      [
        status || null,
        notes !== undefined ? notes : null,
        paid === undefined ? null : paid ? 1 : 0,
        newStart,
        newEnd,
        resolvedWithEngineer ? 1 : 0,
        resolvedTotalPrice,
        resolvedPackageId || null,
        id,
      ],
    )

    if (status && status !== booking.status) {
      try {
        const updatedBooking = { ...booking, status }
        const template = emailTemplates.bookingStatusUpdate(updatedBooking, booking.studioName, true)
        await queueEmail(booking.email, template)
      } catch (emailError) {
        console.error("Error sending guest booking status update email:", emailError)
      }
    }

    const updatedBooking = await db.get(
      `SELECT b.*, s.name as studioName, p.name as packageName
       FROM guest_bookings b
       JOIN studios s ON b.studioId = s.id
       LEFT JOIN packages p ON b.packageId = p.id
       WHERE b.id = ?`,
      [id],
    )

    updatedBooking.paid = !!updatedBooking.paid

    res.json({
      message: "Prenotazione aggiornata con successo",
      booking: updatedBooking,
    })
  } catch (error) {
    console.error("Update guest booking error:", error)
    res.status(500).json({ message: "Errore durante l'aggiornamento della prenotazione" })
  }
})

// Add endpoint to cancel guest booking
app.delete("/api/admin/guest-bookings/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params
    const db = await dbPromise

    // Check if booking exists
    const booking = await db.get(
      `SELECT b.*, s.name as studioName
       FROM guest_bookings b
       JOIN studios s ON b.studioId = s.id
       WHERE b.id = ?`,
      [id],
    )

    if (!booking) {
      return res.status(404).json({ message: "Prenotazione non trovata" })
    }

    // Update booking status to cancelled
    await db.run("UPDATE guest_bookings SET status = ? WHERE id = ?", ["cancelled", id])

    // Send cancellation email
    try {
      const cancelledBooking = { ...booking, status: "cancelled" }
      const template = emailTemplates.bookingStatusUpdate(cancelledBooking, booking.studioName, true)
      await queueEmail(booking.email, template)
    } catch (emailError) {
      console.error("Error sending guest booking cancellation email:", emailError)
    }

    res.json({ message: "Prenotazione cancellata con successo" })
  } catch (error) {
    console.error("Cancel guest booking error:", error)
    res.status(500).json({ message: "Errore durante la cancellazione della prenotazione" })
  }
})

app.get("/api/admin/dashboard", authenticateToken, isAdmin, async (req, res) => {
  try {
    const db = await dbPromise

    // Get counts
    const totalUsers = await db.get('SELECT COUNT(*) as count FROM users WHERE role != "admin"')
    const totalBookings = await db.get("SELECT COUNT(*) as count FROM bookings")
    const totalGuestBookings = await db.get("SELECT COUNT(*) as count FROM guest_bookings")
    const pendingBookings = await db.get('SELECT COUNT(*) as count FROM bookings WHERE status = "pending"')
    const pendingGuestBookings = await db.get('SELECT COUNT(*) as count FROM guest_bookings WHERE status = "pending"')
    const confirmedBookings = await db.get('SELECT COUNT(*) as count FROM bookings WHERE status = "confirmed"')
    const confirmedGuestBookings = await db.get(
      'SELECT COUNT(*) as count FROM guest_bookings WHERE status = "confirmed"',
    )

    // Get revenue
    const revenue = await db.get('SELECT SUM(totalPrice) as total FROM bookings WHERE status != "cancelled"')
    const guestRevenue = await db.get('SELECT SUM(totalPrice) as total FROM guest_bookings WHERE status != "cancelled"')

    // Get recent bookings (both regular and guest)
    const recentRegularBookings = await db.all(`
      SELECT b.*, u.name, u.surname, u.email, s.name as studioName, 'regular' as bookingType
      FROM bookings b
      JOIN users u ON b.userId = u.id
      JOIN studios s ON b.studioId = s.id
      ORDER BY b.createdAt DESC
      LIMIT 3
    `)

    const recentGuestBookings = await db.all(`
      SELECT b.*, b.name, b.surname, b.email, s.name as studioName, 'guest' as bookingType
      FROM guest_bookings b
      JOIN studios s ON b.studioId = s.id
      ORDER BY b.createdAt DESC
      LIMIT 2
    `)

    // Combine and sort by creation date
    const recentBookings = [...recentRegularBookings, ...recentGuestBookings]
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 5)

    res.json({
      stats: {
        totalUsers: totalUsers.count,
        totalBookings: totalBookings.count + totalGuestBookings.count,
        pendingBookings: pendingBookings.count + pendingGuestBookings.count,
        confirmedBookings: confirmedBookings.count + confirmedGuestBookings.count,
        revenue: (revenue.total || 0) + (guestRevenue.total || 0),
      },
      recentBookings,
    })
  } catch (error) {
    console.error("Get dashboard error:", error)
    res.status(500).json({ message: "Errore durante il recupero dei dati della dashboard" })
  }
})

app.get("/api/admin/statistics", authenticateToken, isAdmin, async (req, res) => {
  try {
    const db = await dbPromise
    const {
      from = "1970-01-01",
      to = "2999-12-31",
      studio,
      service,
      packageId,
      payment,
    } = req.query

    const addCondition = (conditions, params, clause, value) => {
      if (value && value !== "all") {
        conditions.push(clause)
        params.push(value)
      }
    }

    const baseFilters = []
    const baseParams = [from, to]

    addCondition(baseFilters, baseParams, "studioName = ?", studio)
    addCondition(baseFilters, baseParams, "service = ?", service)
    addCondition(baseFilters, baseParams, "packageName = ?", packageId)
    if (payment && payment !== "all") {
      addCondition(baseFilters, baseParams, "paid = ?", payment === "paid" ? 1 : 0)
    }

    const whereClause = baseFilters.length > 0 ? "AND " + baseFilters.join(" AND ") : ""

    const params = [...baseParams, ...baseParams]

    const summaryRow = await db.get(
      `SELECT 
         SUM(totalPrice) as totalRevenue,
         COUNT(*) as totalBookings,
         AVG(totalPrice) as avgTicket,
         AVG(CASE WHEN status = 'confirmed' THEN 1.0 ELSE 0 END) as confirmedRate
       FROM (
         SELECT b.totalPrice, b.status, s.name as studioName, b.service, p.name as packageName, b.paid
         FROM bookings b
         JOIN studios s ON b.studioId = s.id
         LEFT JOIN packages p ON b.packageId = p.id
         WHERE b.date BETWEEN ? AND ? ${whereClause}
         UNION ALL
         SELECT gb.totalPrice, gb.status, s.name as studioName, gb.service, p.name as packageName, gb.paid
         FROM guest_bookings gb
         JOIN studios s ON gb.studioId = s.id
         LEFT JOIN packages p ON gb.packageId = p.id
         WHERE gb.date BETWEEN ? AND ? ${whereClause}
       )
      `,
      [...params],
    )

    const topStudios = await db.all(
      `SELECT studioName, COUNT(*) as bookings, SUM(totalPrice) as revenue
       FROM (
         SELECT s.name as studioName, b.totalPrice
         FROM bookings b JOIN studios s ON b.studioId = s.id
         WHERE b.date BETWEEN ? AND ? ${whereClause}
         UNION ALL
         SELECT s.name as studioName, gb.totalPrice
         FROM guest_bookings gb JOIN studios s ON gb.studioId = s.id
         WHERE gb.date BETWEEN ? AND ? ${whereClause}
       )
       GROUP BY studioName
       ORDER BY revenue DESC
       LIMIT 5`,
      [...params],
    )

    const topClients = await db.all(
      `SELECT name, bookings, revenue FROM (
         SELECT u.name || ' ' || u.surname AS name, COUNT(*) as bookings, SUM(b.totalPrice) as revenue
         FROM bookings b JOIN users u ON b.userId = u.id
         WHERE b.date BETWEEN ? AND ? ${whereClause}
         GROUP BY u.id
         UNION ALL
         SELECT gb.name || ' ' || gb.surname AS name, COUNT(*) as bookings, SUM(gb.totalPrice) as revenue
         FROM guest_bookings gb
         WHERE gb.date BETWEEN ? AND ? ${whereClause}
         GROUP BY gb.email
       )
       ORDER BY revenue DESC
       LIMIT 5`,
      [...params],
    )

    const revenueTrend = await db.all(
      `SELECT date, SUM(totalPrice) as revenue, COUNT(*) as bookings
       FROM (
         SELECT date, totalPrice
         FROM bookings
         WHERE date BETWEEN ? AND ? ${whereClause}
         UNION ALL
         SELECT date, totalPrice
         FROM guest_bookings
         WHERE date BETWEEN ? AND ? ${whereClause}
       )
       GROUP BY date
       ORDER BY date ASC`,
      [...params],
    )

    const summary = {
      totalRevenue: summaryRow?.totalRevenue || 0,
      totalBookings: summaryRow?.totalBookings || 0,
      avgTicket: summaryRow?.avgTicket || 0,
      confirmedRate: summaryRow?.confirmedRate || 0,
    }

    res.json({
      summary,
      topStudios,
      topClients,
      revenueTrend,
    })
  } catch (error) {
    console.error("Admin stats error:", error)
    res.status(500).json({ message: "Errore durante il calcolo delle statistiche" })
  }
})

// Email management endpoints for admin
app.get("/api/admin/emails", authenticateToken, isAdmin, async (req, res) => {
  try {
    const db = await dbPromise
    const emails = await db.all("SELECT * FROM email_queue ORDER BY createdAt DESC LIMIT 100")

    res.json({ emails })
  } catch (error) {
    console.error("Get emails error:", error)
    res.status(500).json({ message: "Errore durante il recupero delle email" })
  }
})

app.post("/api/admin/emails/retry", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { ids } = req.body

    if (!Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ message: "Nessun ID email fornito" })
    }

    const db = await dbPromise

    // Reset status and retry count for the specified emails
    await db.run(
      `UPDATE email_queue 
       SET status = 'pending', retries = 0 
       WHERE id IN (${ids.map(() => "?").join(",")})`,
      ids,
    )

    // Trigger immediate processing
    processEmailQueue()

    res.json({ message: `${ids.length} email impostate per il nuovo tentativo` })
  } catch (error) {
    console.error("Retry emails error:", error)
    res.status(500).json({ message: "Errore durante il nuovo tentativo di invio delle email" })
  }
})

app.post("/api/admin/emails/test", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { email } = req.body

    if (!email) {
      return res.status(400).json({ message: "Email richiesta" })
    }

    // Send a test email
    const template = {
      subject: "Test Email - EP Studio",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h1 style="color: #333;">Test Email</h1>
          <p>Questa è un'email di test dal sistema di EP Studio.</p>
          <p>Se stai ricevendo questa email, il sistema di invio email è configurato correttamente.</p>
          <p>Data e ora del test: ${new Date().toLocaleString()}</p>
          <p style="margin-top: 30px;">Cordiali saluti,<br>Il team di EP Studio</p>
        </div>
      `,
    }

    await queueEmail(email, template)
    processEmailQueue() // Process immediately

    res.json({ message: "Email di test inviata" })
  } catch (error) {
    console.error("Test email error:", error)
    res.status(500).json({ message: "Errore durante l'invio dell'email di test" })
  }
})

// Portfolio routes
// Public: list portfolios
app.get("/api/portfolios", async (req, res) => {
  try {
    const db = await dbPromise
    const portfolios = await db.all("SELECT * FROM portfolios ORDER BY createdAt DESC")
    res.json({ portfolios })
  } catch (error) {
    console.error("Get portfolios error:", error)
    res.status(500).json({ message: "Errore durante il recupero dei portfolio" })
  }
})

// Admin: CRUD portfolios
app.get("/api/admin/portfolios", authenticateToken, isAdmin, async (req, res) => {
  try {
    const db = await dbPromise
    const portfolios = await db.all("SELECT * FROM portfolios ORDER BY createdAt DESC")
    res.json({ portfolios })
  } catch (error) {
    console.error("Get admin portfolios error:", error)
    res.status(500).json({ message: "Errore durante il recupero dei portfolio" })
  }
})

app.post("/api/admin/portfolios", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { title, description, imageUrl, videoUrl } = req.body
    if (!title) return res.status(400).json({ message: "Titolo è obbligatorio" })
    const db = await dbPromise
    const result = await db.run(
      "INSERT INTO portfolios (title, description, imageUrl, videoUrl) VALUES (?, ?, ?, ?)",
      [title, description || null, imageUrl || null, videoUrl || null]
    )
    const portfolio = await db.get("SELECT * FROM portfolios WHERE id = ?", [result.lastID])
    res.status(201).json({ message: "Portfolio creato", portfolio })
  } catch (error) {
    console.error("Create portfolio error:", error)
    res.status(500).json({ message: "Errore durante la creazione del portfolio" })
  }
})

app.put("/api/admin/portfolios/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params
    const { title, description, imageUrl, videoUrl } = req.body
    if (!title) return res.status(400).json({ message: "Titolo è obbligatorio" })
    const db = await dbPromise
    const existing = await db.get("SELECT * FROM portfolios WHERE id = ?", [id])
    if (!existing) return res.status(404).json({ message: "Portfolio non trovato" })
    await db.run(
      "UPDATE portfolios SET title = ?, description = ?, imageUrl = ?, videoUrl = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?",
      [title, description || null, imageUrl || null, videoUrl || null, id]
    )
    const portfolio = await db.get("SELECT * FROM portfolios WHERE id = ?", [id])
    res.json({ message: "Portfolio aggiornato", portfolio })
  } catch (error) {
    console.error("Update portfolio error:", error)
    res.status(500).json({ message: "Errore durante l'aggiornamento del portfolio" })
  }
})

app.delete("/api/admin/portfolios/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params
    const db = await dbPromise
    const existing = await db.get("SELECT * FROM portfolios WHERE id = ?", [id])
    if (!existing) return res.status(404).json({ message: "Portfolio non trovato" })
    await db.run("DELETE FROM portfolios WHERE id = ?", [id])
    res.json({ message: "Portfolio eliminato" })
  } catch (error) {
    console.error("Delete portfolio error:", error)
    res.status(500).json({ message: "Errore durante l'eliminazione del portfolio" })
  }
})

// AVAILABILITY ROUTES
app.get("/api/availability", async (req, res) => {
  try {
    const { studioId, date } = req.query

    if (!studioId || !date) {
      return res.status(400).json({ message: "Studio ID e data sono richiesti" })
    }

    const db = await dbPromise

    // Get all regular bookings for the specified studio and date
    const bookings = await db.all(
      'SELECT startTime, endTime FROM bookings WHERE studioId = ? AND date = ? AND status != "cancelled"',
      [studioId, date],
    )

    // Get all guest bookings for the specified studio and date
    const guestBookings = await db.all(
      'SELECT startTime, endTime FROM guest_bookings WHERE studioId = ? AND date = ? AND status != "cancelled"',
      [studioId, date],
    )

    // Combine all bookings
    const allBookings = [...bookings, ...guestBookings]

    // Generate available time slots (11:00 - 22:00, minimum 2 hours)
    const availableSlots = []
    const openingHour = 11
    const closingHour = 22

    for (let hour = openingHour; hour < closingHour - 1; hour++) {
      for (let nextHour = hour + 2; nextHour <= Math.min(hour + 8, closingHour); nextHour++) {
        const startTime = `${hour.toString().padStart(2, "0")}:00`
        const endTime = `${nextHour.toString().padStart(2, "0")}:00`

        // Check if this slot overlaps with any booking
        const isAvailable = !allBookings.some((booking) => {
          const bookingStart = booking.startTime
          const bookingEnd = booking.endTime

          return (
            (startTime <= bookingStart && endTime > bookingStart) ||
            (startTime < bookingEnd && endTime >= bookingEnd) ||
            (startTime >= bookingStart && endTime <= bookingEnd)
          )
        })

        if (isAvailable) {
          availableSlots.push({
            startTime,
            endTime,
            duration: nextHour - hour,
          })
        }
      }
    }

    res.json({ availableSlots })
  } catch (error) {
    console.error("Get availability error:", error)
    res.status(500).json({ message: "Errore durante il recupero della disponibilità" })
  }
})

// Health check endpoint
app.get("/api/health", (req, res) => {
  res.status(200).json({ status: "ok" })
})

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})

export default app
