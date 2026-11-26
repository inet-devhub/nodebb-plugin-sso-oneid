# NodeBB Plugin SSO OneID

Log in to NodeBB with a [OneID](https://one.th) account.

## Installation

    npm install nodebb-plugin-sso-oneid

Requires NodeBB 4.x.

## Configuration

Open **ACP → Plugins → One ID** and set:

| Setting              | Notes                                                                                                       |
| -------------------- | ----------------------------------------------------------------------------------------------------------- |
| Server               | `https://one.th` in production, `https://testoneid.inet.co.th` for UAT. Must be `https://`.                 |
| Client ID / Secret   | From [dpc.one.th](https://dpc.one.th). Fallback: `SSO_ONEID_CLIENT_ID`, `SSO_ONEID_CLIENT_SECRET` env vars. |
| RefCode              | Sent with the shared-token exchange when set.                                                               |
| Associate Businesses | Optional allowlist: only members of one of these OneID businesses may log in.                               |
| Block One ID account | OneID account ids that may never log in.                                                                    |
| Intranet sync        | Optional avatar source (`<API server>/account/<id>/avatar`, Bearer API key).                                |

Restart NodeBB after saving.

## Login URLs

- Normal login: `/auth/oneid`
- Shared-token hand-off from another OneID service: `/auth/oneid/callback?sharedtoken=<token>`

## Development

    npm ci
    npm run lint
    npm run format:check
    npm test

## Releasing

1. Bump `version` in `package.json` in a pull request and merge it.
2. Create a GitHub Release with tag `v<version>` (for example `gh release create v1.1.0 --generate-notes`).
3. The **Release** workflow checks the tag against `package.json`, runs the tests and publishes to npm with provenance.

Publishing uses [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) only (no npm token): the trusted publisher on npmjs.com is this repository, workflow `release.yml`, environment `npm`.
