import fetch from 'node-fetch'
import express from 'express'
import jwt from 'express-jwt'
import jwksRsa from 'jwks-rsa'

declare module '@hydrofoil/labyrinth' {
  export interface User {
    sub?: string
    name?: string
    permissions?: string[]
  }
}

const createJwtHandler = (jwksUri: string) => {
  return jwt({
    // Dynamically provide a signing key
    // based on the kid in the header and
    // the signing keys provided by the JWKS endpoint.
    secret: jwksRsa.expressJwtSecret({
      cache: false,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri,
    }),

    // Validate the audience and the issuer.
    audience: process.env.AUTH_AUDIENCE,
    issuer: process.env.AUTH_ISSUER,
    algorithms: ['RS256'],
    credentialsRequired: false,
  })
}

export async function authentication(): Promise<express.RequestHandler> {
  if (process.env.AUTH_JWKS_URI) {
    return createJwtHandler(process.env.AUTH_JWKS_URI)
  }

  const response = await fetch(`${process.env.AUTH_ISSUER}/.well-known/openid-configuration`)

  if (response.ok) {
    const oidcConfig = await response.json()
    return createJwtHandler(oidcConfig.jwks_uri)
  }

  throw new Error('Failed to initialize authentication middleware')
}
