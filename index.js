// Cloud Function Dependencies
// const functions = require('@google-cloud/functions-framework');
 // "@google-cloud/functions-framework": "^3.0.0",
const express = require('express');
const bodyParser = require('body-parser');
const admin = require('firebase-admin');

// 🔑 Initialize Firebase Admin SDK
// This assumes your GCF environment already has the necessary service account credentials.
// Initializes only if not already initialized (standard GCF pattern)
if (admin.apps.length === 0) {
    admin.initializeApp();
}
const db = admin.firestore();

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));

// --- Environment Variables (Must be configured in GCF) ---
const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const DEVICE_AUTH_KEY = process.env.DEVICE_AUTH_KEY;
const SCOPES = 'user-read-playback-state user-modify-playback-state user-read-currently-playing';
const SPOTIFY_AUTH_URL = 'https://accounts.spotify.com/authorize';
const SPOTIFY_TOKEN_URL = 'https://accounts.spotify.com/api/token';
const TOKENS_COLLECTION = 'spotifyTokens'; // Firestore collection name
// ------------------------------------------------------------------

// Helper function to get the Firestore Document Reference
const getTokenDocRef = (deviceId) => db.collection(TOKENS_COLLECTION).doc(deviceId);

// ------------------------------------------------------------------
// 1. /login: Endpoint the ESP32 user visits to start the flow.
// ------------------------------------------------------------------
app.get('/login', (req, res) => {
  const deviceId = req.query.deviceId;

  if (!deviceId) {
    return res.status(400).send('Missing deviceId parameter. Must use a persistent UUID.');
  }

  const authUrl = new URL(SPOTIFY_AUTH_URL);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('client_id', CLIENT_ID);
  authUrl.searchParams.append('scope', SCOPES);
  authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.append('state', deviceId); // UUID ensures state validation and device linking

  res.redirect(authUrl.toString());
});

// ------------------------------------------------------------------
// 2. /callback: Spotify Redirect (Saves tokens to Firestore)
// ------------------------------------------------------------------
app.get('/callback', async (req, res) => {
  const code = req.query.code || null;
  const deviceId = req.query.state || null; // The UUID passed in /login
  const error = req.query.error || null;

  if (error || !deviceId) {
    return res.status(400).send(`Authorization failed. Error: ${error || 'Missing device ID.'}`);
  }

  // 1. Exchange authorization code for tokens
  try {
    const tokenResponse = await fetch(SPOTIFY_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        // Secretly encode the Client ID and Client Secret
        'Authorization': 'Basic ' + Buffer.from(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64')
      },
      body: new URLSearchParams({
        code: code,
        redirect_uri: REDIRECT_URI,
        grant_type: 'authorization_code'
      }).toString()
    });

    const tokenData = await tokenResponse.json();

    if (tokenData.error) {
      throw new Error(tokenData.error_description || 'Token exchange failed.');
    }

    // 2. Write tokens to Firestore using deviceId as the Document ID
    const tokenDocRef = getTokenDocRef(deviceId);
    await tokenDocRef.set({
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expiresIn: tokenData.expires_in,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    res.send(`✅ **Success!** Device ID: ${deviceId}. Tokens saved securely. You can now close this window.`);

  } catch (err) {
    console.error('Callback/Token Exchange Error:', err);
    res.status(500).send(`Token exchange failed on the server: ${err.message}`);
  }
});

// ------------------------------------------------------------------
// 3. /token: ESP32 Polling (Retrieves initial tokens from Firestore)
// ------------------------------------------------------------------
app.get('/token', async (req, res) => {
    // Allows CORS for potential testing, though not strictly needed for ESP32
    res.set('Access-Control-Allow-Origin', '*'); 

    const deviceId = req.query.deviceId;
    const authKey = req.query.authKey;

    // 🔐 1. Authentication Check
    if (authKey !== DEVICE_AUTH_KEY || !deviceId) {
        return res.status(401).json({ error: 'Unauthorized', message: 'Authentication failed.' });
    }

    try {
        // 2. Read token data from Firestore
        const doc = await getTokenDocRef(deviceId).get();

        if (!doc.exists) {
            return res.status(404).json({ error: 'Not Found', message: 'Tokens not yet available.' });
        }
        
        const tokens = doc.data();

        // 3. Respond to the ESP32
        res.json({
            access_token: tokens.accessToken,
            expires_in: tokens.expiresIn,
            // The ESP32 is assumed to know its refresh timing based on expiresIn
        });
    } catch (err) {
        console.error('Firestore Read Error:', err);
        res.status(500).send({ error: 'Server Error', message: 'Database lookup failed.' });
    }
});

// ------------------------------------------------------------------
// 4. /refresh: Renew Access Token (Uses stored refresh token)
// ------------------------------------------------------------------
app.get('/refresh', async (req, res) => {
    res.set('Access-Control-Allow-Origin', '*'); 

    const deviceId = req.query.deviceId;
    const authKey = req.query.authKey;

    // 🔐 1. Authentication Check
    if (authKey !== DEVICE_AUTH_KEY || !deviceId) {
        return res.status(401).json({ error: 'Unauthorized', message: 'Authentication failed.' });
    }

    try {
        const tokenDocRef = getTokenDocRef(deviceId);
        const doc = await tokenDocRef.get();

        if (!doc.exists) {
            return res.status(404).json({ error: 'Not Found', message: 'No record found to refresh.' });
        }
        
        const { refreshToken } = doc.data();

        if (!refreshToken) {
            // Should not happen if initial flow worked
             return res.status(404).json({ error: 'Not Found', message: 'Refresh token missing from storage.' });
        }

        // 2. POST request to Spotify with the stored refresh_token
        const tokenResponse = await fetch(SPOTIFY_TOKEN_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic ' + Buffer.from(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64')
            },
            body: new URLSearchParams({
                grant_type: 'refresh_token',
                refresh_token: refreshToken,
            }).toString()
        });

        const tokenData = await tokenResponse.json();

        if (tokenData.error) {
            console.error('Spotify Refresh Error:', tokenData.error_description || tokenData.error);
            // If the refresh token is invalid/revoked, delete the record to force re-login
            await tokenDocRef.delete(); 
            return res.status(400).json({ error: 'Refresh Failed', message: 'Refresh token invalid. Re-authorization required.' });
        }

        // 3. Prepare update object for Firestore
        const updateData = {
            accessToken: tokenData.access_token,
            expiresIn: tokenData.expires_in,
            timestamp: admin.firestore.FieldValue.serverTimestamp()
        };

        // Spotify sometimes returns a new refresh token (rotation). We MUST save it.
        if (tokenData.refresh_token) {
            updateData.refreshToken = tokenData.refresh_token;
        }

        // 4. Atomic update the document in Firestore
        await tokenDocRef.update(updateData);
        
        // 5. Respond to the ESP32
        res.json({
            access_token: updateData.accessToken,
            expires_in: updateData.expiresIn
        });

    } catch (err) {
        console.error('Refresh or Database Error:', err);
        res.status(500).send({ error: 'Server Error', message: 'Refresh failed due to a server or network issue.' });
    }
});


// Exports the Express app instance. In Google Cloud Functions, the entry point 
// would be configured to be 'app' if using the 'HTTP trigger' type.
exports.app = app;