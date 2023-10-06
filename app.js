const express = require('express');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const session = require('express-session');
const flash = require('connect-flash');
const ejs = require('ejs');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'votre-clé-secrète',
    resave: false,
    saveUninitialized: true
}));
app.use(flash());

// Configuration de la base de données SQLite3
const db = new sqlite3.Database('mydb.db');

db.serialize(() => {
    db.run('CREATE TABLE IF NOT EXISTS utilisateurs (id INTEGER PRIMARY KEY AUTOINCREMENT, nom_utilisateur TEXT, mot_de_passe TEXT)');
});

// EJS comme moteur de modèle pour les vues
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.get('/', (req, res) => {
    res.render('login', { message: req.flash('message') });
});

app.get('/inscription', (req, res) => {
    res.render('inscription', { message: req.flash('message') });
});

app.post('/inscription', (req, res) => {
    const { nom_utilisateur, mot_de_passe } = req.body;

    // Hacher le mot de passe
    const saltRounds = 10;
    bcrypt.hash(mot_de_passe, saltRounds, (err, hash) => {
        if (err) {
            req.flash('message', 'Erreur lors de l\'inscription. Veuillez réessayer.');
            res.redirect('/inscription');
            return;
        }

        // Insérer l'utilisateur dans la base de données
        db.run('INSERT INTO utilisateurs (nom_utilisateur, mot_de_passe) VALUES (?, ?)', [nom_utilisateur, hash], (err) => {
            if (err) {
                req.flash('message', 'L\'inscription a échoué. Veuillez réessayer.');
                res.redirect('/inscription');
                return;
            }

            req.flash('message', 'Utilisateur enregistré avec succès. Veuillez vous connecter.');
            res.redirect('/');
        });
    });
});

app.post('/connexion', (req, res) => {
    const { nom_utilisateur, mot_de_passe } = req.body;

    // Vérifier si l'utilisateur existe dans la base de données
    db.get('SELECT id, mot_de_passe FROM utilisateurs WHERE nom_utilisateur = ?', [nom_utilisateur], (err, row) => {
        if (err) {
            res.redirect('/');
            return;
        }

        if (!row) {
            req.flash('message', 'Nom d\'utilisateur non trouvé.');
            res.redirect('/');
            return;
        }

        // Comparer le mot de passe fourni avec le mot de passe haché de la base de données
        bcrypt.compare(mot_de_passe, row.mot_de_passe, (err, result) => {
            if (err || !result) {
                req.flash('message', 'Mot de passe incorrect.');
                res.redirect('/');
                return;
            }

            // Stocker la session utilisateur
            req.session.userId = row.id;
            res.redirect('/profil');
        });
    });
});

app.get('/profil', (req, res) => {
    // Vérifier si l'utilisateur est authentifié
    if (!req.session.userId) {
        req.flash('message', 'Vous devez être connecté pour accéder au profil.');
        res.redirect('/');
        return;
    }

    // Récupérer les données du profil de l'utilisateur depuis la base de données
    db.get('SELECT id, nom_utilisateur FROM utilisateurs WHERE id = ?', [req.session.userId], (err, row) => {
        if (err) {
            res.redirect('/');
            return;
        }

        res.render('profil', { utilisateur: row });
    });
});

app.listen(port, () => {
    console.log(`Le serveur fonctionne sur le port ${port}`);
});
