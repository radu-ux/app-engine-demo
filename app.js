const express = require('express');
const cors = require('cors')
const metadata = require('gcp-metadata');
const {OAuth2Client} = require('google-auth-library');

const app = express();
const oAuth2Client = new OAuth2Client();

// Cache externally fetched information for future invocations
let aud;

async function audience() {
  if (!aud && (await metadata.isAvailable())) {
    let project_number = await metadata.project('numeric-project-id');
    let project_id = await metadata.project('project-id');

    aud = '/projects/' + project_number + '/apps/' + project_id;
  }

  return aud;
}

async function validateAssertion(assertion) {
  if (!assertion) {
    return {};
  }

  // Check that the assertion's audience matches ours
  const aud = await audience();

  // Fetch the current certificates and verify the signature on the assertion
  const response = await oAuth2Client.getIapPublicKeys();
  const ticket = await oAuth2Client.verifySignedJwtWithCertsAsync(
    assertion,
    response.pubkeys,
    aud,
    ['https://cloud.google.com/iap']
  );
  const payload = ticket.getPayload();

  // Return the two relevant pieces of information
  return {
    email: payload.email,
    sub: payload.sub,
  };
}

app.use(cors())
app.use(express.json())

app.get('/google-sign-in', async (req, res) => {
  const assertion = req.header('X-Goog-IAP-JWT-Assertion');
  let email = 'None';
  let type = 'None'
  try {
    const info = await validateAssertion(assertion);
    email = info.email || 'radu.uivari@vspartners.us';
    type = 'Admin'
  } catch (error) {
    console.log(error);
  }   
  res.cookie('user', {email, type}, {
      domain: 'inventory-management-349907.lm.r.appspot.com'
  })
  res.redirect('http://localhost:3000')
});
app.get('/test', (req, res) => { 
    res.send({message: 'Success'})
})
app.options('/*', (req, res) => { 
    res.sendStatus(200)
})


// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`App listening on port ${PORT}`);
  console.log('Press Ctrl+C to quit.');
});
