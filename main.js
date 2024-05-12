const express = require('express');
const fs = require('fs');
const app = express();
app.use(express.urlencoded({ extended: true }));

app.post('/submit-key', (req, res) => {
    const { password, hashedPassword } = req.body;
    // Store the keys securely
    // Example: Append to a file - not recommended for production
    fs.appendFileSync('keys.txt', `Password: ${password}, Hashed: ${hashedPassword}\n`);
    res.send('Key received');
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
