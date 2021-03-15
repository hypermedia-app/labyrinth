import asyncMiddleware from 'middleware-async'
import { ASK } from '@tpluscode/sparql-builder'
import { acl, auth } from '@hydrofoil/labyrinth/lib/namespace'
import error from 'http-errors'
import { NamedNode, Term } from 'rdf-js'
import type { StreamClient } from 'sparql-http-client/StreamClient'
import type * as express from 'express'

interface Check {
  accessMode: Term[] | Term
  client: StreamClient
  agent?: Term
}

interface ResourceCheck extends Check {
  term: NamedNode
}

interface TypeCheck extends Check {
  types: Term[]
}

export async function check({ accessMode, client, agent, ...check }: ResourceCheck | TypeCheck): Promise<Error | null> {
  if (!agent) {
    return new error.Unauthorized('No user authenticated')
  }

  let hasAccess = false
  if ('term' in check) {
    hasAccess = await ASK`
      VALUES ?mode { ${acl.Control} ${accessMode} )
    
      ?authorization a ${acl.Authorization} ;
                     ${acl.mode} ?mode ; 
                     ${acl.accessTo} ${check.term} ;
                     ${acl.agent} ${agent}.
    `.execute(client.query)
  } else {
    hasAccess = await ASK`
    VALUES ?type { ${check.types} }
    VALUES ?mode { ${acl.Control} ${accessMode} }
  
    ?authorization a ${acl.Authorization} ;
                   ${acl.mode} ?mode ; 
                   ${acl.accessToClass} ?type ;
                   ${acl.agent} ${agent} .
  `.execute(client.query)
  }

  return hasAccess ? null : new error.Unauthorized()
}

export const middleware = (client: StreamClient): express.RequestHandler => asyncMiddleware(async (req, res, next) => {
  const accessMode = req.hydra.operation?.out(auth.access).term

  const error = accessMode && await check({
    term: req.hydra.term,
    accessMode,
    client,
    agent: req.user?.id,
  })

  if (error) {
    return next(error)
  }

  return next()
})
