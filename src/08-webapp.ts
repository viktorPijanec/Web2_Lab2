import express from 'express';
import path from 'path'
import oidc from 'express-openid-connect';
const { auth, requiresAuth } = oidc;
import dotenv from 'dotenv'
dotenv.config()

const app = express();
app.set("views", path.join(import.meta.dirname, "views"));
app.set('view engine', 'pug');

const externalUrl = process.env.RENDER_EXTERNAL_URL;
const port =
  externalUrl && process.env.PORT ? parseInt(process.env.PORT) : 4080;
const baseURL = externalUrl || `http://localhost:${port}`;

const config = { 
  authRequired : false,
  idpLogout : true, //logout not only from the app, but also from identity provider
  secret: process.env.SESSION_SECRET,
  baseURL: baseURL,
  clientID: process.env.CLIENT_ID,
  issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
  clientSecret: process.env.CLIENT_SECRET,
  routes: {
    logout: false as const // library registers GET /logout only; POST is used instead (see below)
  },
  authorizationParams: {
    response_type: 'code' ,
    //scope: "openid profile email"   
   },
};
// auth router attaches /login and /callback routes to the baseURL (/logout is disabled in routes)
app.use(auth(config));

// logout changes state (removes session), so POST is used instead of GET
// (otherwise any page could log the user out with a link or redirect - logout CSRF)
app.post('/logout', (req, res) => res.oidc.logout());

app.get('/',  function (req, res) {
  let username : string | undefined;
  if (req.oidc.isAuthenticated()) {
    username = req.oidc.user?.name ?? req.oidc.user?.sub;
  }
  res.render('index', {username});
});


// app.get("/sign-up", (req, res) => {
//   res.oidc.login({
//     returnTo: '/',
//     authorizationParams: {      
//       screen_hint: "signup",
//     },
//   });
// });


const hostname = externalUrl ? "0.0.0.0" : "localhost";

app.listen(port, hostname, () => {
  console.log(`Server locally running at http://${hostname}:${port}/`);
  if (externalUrl) {
    console.log(`External URL: ${externalUrl}/`);
  }
});