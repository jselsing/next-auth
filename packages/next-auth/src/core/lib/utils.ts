import { createHash } from "crypto"

import {
  CognitoIdentityClient,
  GetIdCommand,
  GetCredentialsForIdentityCommand,
} from "@aws-sdk/client-cognito-identity";

import type { AuthOptions } from "../.."
import type { InternalOptions } from "../types"
import type { InternalUrl } from "../../utils/parse-url"

/**
 * Takes a number in seconds and returns the date in the future.
 * Optionally takes a second date parameter. In that case
 * the date in the future will be calculated from that date instead of now.
 */
export function fromDate(time: number, date = Date.now()) {
  return new Date(date + time * 1000)
}

export function hashToken(token: string, options: InternalOptions<"email">) {
  const { provider, secret } = options
  return (
    createHash("sha256")
      // Prefer provider specific secret, but use default secret if none specified
      .update(`${token}${provider.secret ?? secret}`)
      .digest("hex")
  )
}

/**
 * Secret used salt cookies and tokens (e.g. for CSRF protection).
 * If no secret option is specified then it creates one on the fly
 * based on options passed here. If options contains unique data, such as
 * OAuth provider secrets and database credentials it should be sufficent. If no secret provided in production, we throw an error. */
export function createSecret(params: {
  authOptions: AuthOptions
  url: InternalUrl
}) {
  const { authOptions, url } = params

  return (
    authOptions.secret ??
    // TODO: Remove falling back to default secret, and error in dev if one isn't provided
    createHash("sha256")
      .update(JSON.stringify({ ...url, ...authOptions }))
      .digest("hex")
  )
}

const cognitoClient = new CognitoIdentityClient({ region: process.env.REGION as string });
  
export async function getAWSCreds(token: string) {

  const logins = `cognito-idp.${process.env.REGION}.amazonaws.com/${process.env.COGNITO_USER_POOL_ID}`

  const idResponse = await cognitoClient.send(
    new GetIdCommand({
      IdentityPoolId: process.env.COGNITO_IDENTITY_POOL_ID as string,
      Logins: {
        [logins]: token
    }
    })
  );
  const { IdentityId } = idResponse;
  

  const credentialsResponse = await cognitoClient.send(
    new GetCredentialsForIdentityCommand({
      IdentityId,
      Logins: {
        [logins]: token
    }
    })
  );

  return credentialsResponse;
}

export interface awsCreds {
  access_key?: string;
  secret_access_key?: string;
  session_token?: string;
}
