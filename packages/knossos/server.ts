import express from 'express'
import { hydraBox } from '@hydrofoil/labyrinth'
import StreamClient from 'sparql-http-client/StreamClient'
import { resource } from 'express-rdf-request'
import debug from 'debug'
import cors from 'cors'
import * as webAccessControl from 'hydra-box-middleware-wac'
import createApi from './lib/api'
import { ResourcePerGraphStore } from './lib/store'
import { create } from './resource'
import { problemJson } from '../labyrinth/errors'
import { authentication } from './lib/middleware/authentication'
import { systemAuth } from './lib/middleware/systemAuth'
import ParsingClient from 'sparql-http-client/ParsingClient'

const app = express()

async function main() {
  const log = debug('knossos')

  const sparql = {
    endpointUrl: process.env.SPARQL_QUERY_ENDPOINT!,
    updateUrl: process.env.SPARQL_UPDATE_ENDPOINT!,
  }

  const client = new StreamClient(sparql)
  const parsingClient = new ParsingClient(sparql)
  const store = new ResourcePerGraphStore(client)

  app.enable('trust proxy')
  app.use(cors())

  app.use(await authentication())
  app.use(systemAuth({ log, client: parsingClient }))
  app.use(resource(req => req.hydra.term))
  app.use((req, res, next) => {
    req.knossos = {
      store,
      log,
    }
    next()
  })
  app.use(await hydraBox({
    codePath: '.',
    sparql,
    loadApi: createApi({
      store,
      log,
    }),
    middleware: {
      resource: webAccessControl.middleware(client),
    },
  }))
  app.put('/*', create(client))
  app.use(problemJson({ captureNotFound: true }))

  app.listen(8888, () => log('API started'))
}

main().catch(debug('knossos').extend('error'))
