const functions = require('@google-cloud/functions-framework');

const express = require('express');

const app = express();

const bodyParser = require('body-parser');

app.use(bodyParser.urlencoded({ extended: true }));

// ⚠️ IMPORTANT: In production, replace this with a persistent database like Firestore.
// { 'unique-esp32-id': { accessToken: '...', refreshToken: '...' } }
const deviceTokenStore = {}; 

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const DEVICE_AUTH_KEY = process.env.DEVICE_AUTH_KEY;
const SCOPES = 'user-read-playback-state user-modify-playback-state user-read-currently-playing';
const SPOTIFY_AUTH_URL = 'https://accounts.spotify.com/authorize';
const SPOTIFY_TOKEN_URL = 'https://accounts.spotify.com/api/token';

// ------------------------------------------------------------------
// 1. /login: Endpoint the ESP32 tells the user to visit (or polls).
// ------------------------------------------------------------------
app.get('/login', (req, res) => {
  const deviceId = req.query.deviceId; // Unique ID sent by ESP32 (e.g., MAC address)

  if (!deviceId) {
    return res.status(400).send('Missing deviceId parameter.');
  }

  // Store the deviceId temporarily in a secure manner (or use it as the state)
  // In this example, we just pass it along.

  const authUrl = new URL(SPOTIFY_AUTH_URL);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('client_id', CLIENT_ID);
  authUrl.searchParams.append('scope', SCOPES);
  authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.append('state', deviceId); // Use the deviceId as the state for tracking

  // Redirect the user's browser to Spotify's login page
  res.redirect(authUrl.toString());
});

// ------------------------------------------------------------------
// 2. /callback: Endpoint Spotify redirects the user's browser to.
// ------------------------------------------------------------------
app.get('/callback', async (req, res) => {
  const code = req.query.code || null;
  const deviceId = req.query.state || null;
  const error = req.query.error || null;

  if (error || !deviceId) {
    return res.send(`Authorization failed. Error: ${error || 'Missing device ID.'}`);
  }

  // Securely exchange the authorization code for tokens
  try {
    const tokenResponse = await fetch(SPOTIFY_TOKEN_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
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

    // 🔑 SUCCESS: Store the tokens securely, associated with the deviceId
    deviceTokenStore[deviceId] = {
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token,
      expires_in: tokenData.expires_in
    };

    res.send(`✅ **Success!** You have granted access. Your device (**${deviceId}**) can now fetch the token.`);

  } catch (err) {
    console.error('Token Exchange Error:', err);
    res.status(500).send(`Token exchange failed on the server: ${err.message}`);
  }
});

// ------------------------------------------------------------------
// 3. /token: Endpoint the ESP32 polls to retrieve its tokens.
// ------------------------------------------------------------------
app.get('/token', (req, res) => {
    const deviceId = req.query.deviceId;
    const authKey = req.query.authKey;

    // 🔐 Check device authentication
    if (authKey !== DEVICE_AUTH_KEY) {
        return res.status(401).json({ error: 'Unauthorized', message: 'Invalid device authentication key.' });
    }

    const tokens = deviceTokenStore[deviceId];
    if (!tokens) {
        return res.status(404).json({ error: 'Not Found', message: 'Tokens not yet available for this deviceId.' });
    }

    // Return the tokens to the ESP32
    res.json({
        access_token: tokens.accessToken,
        refresh_token: tokens.refreshToken,
        expires_in: tokens.expires_in
    });
});

// Export the Express app as the Cloud Function entry point
exports.spotifyAuth = functions.https.onRequest(app);

