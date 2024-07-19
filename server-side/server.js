
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const connectDB = require('./config/db');
const authRoutes = require('./routes/authRoutes');
const dotenv = require('dotenv');

dotenv.config();


connectDB();

const app = express();


app.use(express.json());
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));


require('./config/passport')(passport);
app.use(passport.initialize());
app.use(passport.session());


app.use('/auth', authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
