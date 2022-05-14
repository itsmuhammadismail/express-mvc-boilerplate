const express = require("express");
const dotenv = require("dotenv");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const corsOptions = require("./config/cors_options.js");
const connectDB = require("./config/db.js");
const errorHandler = require("./middlewares/error.middleware.js");
const credentials = require("./middlewares/credentials.middleware.js");
const authRouter = require("./routes/auth.route.js");

// Configurations
dotenv.config();
const app = express();
connectDB();
const port = process.env.PORT || 5000;

// Handle options credentials check - before CORS!
// and fetch cookies credentials requirement
app.use(credentials);

// Cross Origin Resource Sharing
app.use(cors(corsOptions));

// built-in middleware to handle urlencoded form data
app.use(express.urlencoded({ extended: false }));

// built-in middleware for json
app.use(express.json());

//middleware for cookies
app.use(cookieParser());

// Routes
app.use("/api", authRouter);

// Error Handler Middleware
app.use(errorHandler);

// Listning to port
app.listen(port, () => console.log(`Server started on port ${port}`));
