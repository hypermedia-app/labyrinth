import express from 'express'
import { nanoid } from 'nanoid'
import { Debugger } from 'debug'
import asyncMiddleware from 'middleware-async'
import { NamedNode } from 'rdf-js'
import { SELECT } from '@tpluscode/sparql-builder'
import { ParsingClient } from 'sparql-http-client/ParsingClient'
import { knossos } from '../namespace'
import error from 'http-errors'

interface SystemAuth {
  log: Debugger
  client: ParsingClient
}

export const systemAuth = ({ log, client }: SystemAuth): express.RequestHandler => {
  const systemAuthKey = process.env.SYSTEM_AUTH_KEY || nanoid()
  let systemAccountId: NamedNode | undefined

  log('System account authentication token: %s', systemAuthKey)

  return asyncMiddleware(async (req, res, next) => {
    if (req.headers.authorization === `System ${systemAuthKey}`) {
      if (!systemAccountId) {
        const [result, ...more] = await SELECT`?account`
          .WHERE`?account a ${knossos.SystemAccount}`
          .execute(client.query)

        if (more.length) {
          return next(new error.InternalServerError('Multiple system accounts found'))
        }

        systemAccountId = result.account as any
      }

      req.user = {
        id: systemAccountId,
      }
    }

    next()
  })
}
