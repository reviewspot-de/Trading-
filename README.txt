ReviewSpot Cloud Sync – deployment files

Repository root should contain:
  index.html
  _routes.json
  functions/api/data.js

The D1 binding must be named DB and point to reviewspot-database.
The API only accepts requests on control.reviewspot.de and cryptographically verifies the Cloudflare Access JWT.
Before the API works, add the Pages environment variable POLICY_AUD with the Application Audience (AUD) Tag from your control.reviewspot.de Access application.
The database tables create themselves on the first authenticated API request.

schema.sql is included only as a reference/manual fallback; you do not need to run it manually.

After committing these files to main, Cloudflare Pages should redeploy automatically.
Use control.reviewspot.de for the cloud-backed app. The pages.dev preview is deliberately blocked from the D1 API.
