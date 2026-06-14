const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 4000;

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(cors());

// Serve the main attacker page
app.get('/', (req, res) => {
  res.render('index');
});



app.listen(PORT, () => {
  console.log(`Attacker Site listening on http://localhost:${PORT}`);
  console.log(`Waiting for stolen cookies...`);
});
