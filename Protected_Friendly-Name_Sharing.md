# Protected Friendly-Name Sharing

This project creates opaque, encrypted share tokens. A shared page displays only the saved **Friendly Name**. Firebase URL and authentication key remain inside the encrypted token on the server and are never placed in the visible URL or returned to the shared browser.

## Vercel deployment — important

The Vercel project root must be the folder that contains **all** of these items at its top level:

```text
index.html
api/share.js
package.json
vercel.json
```

If using Vercel Drop, unzip this project and drag the complete `Eraweb-main` folder into Vercel Drop. Do not drag only `index.html`, and do not select a nested folder that contains only the HTML file. If using Git, import the repository with the same folder as the Vercel **Root Directory**. The `api` folder must be directly inside that root; otherwise `/api/share` returns 404.

After importing the project, add this environment variable in **Project Settings → Environment Variables**:

```text
SHARE_ENCRYPTION_KEY=<64-character random hexadecimal value>
```

Generate a value with:

```bash
openssl rand -hex 32
```

Set it for the Production environment, then create a new deployment. Do not commit the value to the repository. After deployment, a request to `/api/share` without a token should return a JSON error such as `Missing share token`; it should not return a Vercel 404 page.

## How the protected share flow works

The frontend calls `POST /api/share` when the Share button is used. The server encrypts the Friendly Name, Firebase URL, and authentication key with AES-256-GCM and returns an opaque token. The frontend converts that token into a URL such as `https://your-domain.vercel.app/?share=<opaque-token>`. Shared pages call `GET /api/share?token=...` to resolve only the Friendly Name, then send database operations to the same endpoint. The endpoint performs Firebase reads, writes, and deletes server-side.

The frontend now accepts the standard response shape as well as common wrapped response shapes from serverless adapters. It also converts nested API errors into readable text, so a deployment problem is displayed as a useful message instead of `[object Object]`.

## Important limitation

Never deploy the app without `SHARE_ENCRYPTION_KEY`. A static-only host that cannot execute `/api/share` cannot provide secure name-only sharing; it can display the UI, but protected sharing requires a serverless or backend deployment.

## References

[1]: https://vercel.com/docs/functions/runtimes/node-js "Vercel Node.js Runtime"
[2]: https://vercel.com/docs/project-configuration/vercel-json "Vercel vercel.json Configuration"
[3]: https://vercel.com/docs/deployments "Deploying to Vercel"
