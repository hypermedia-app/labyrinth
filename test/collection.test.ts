import { describe, it, beforeEach, afterEach } from 'mocha'
import { expect } from 'chai'
import express from 'express'
import request from 'supertest'
import $rdf from 'rdf-ext'
import cf from 'clownface'
import sinon, { SinonStub, SinonStubbedInstance } from 'sinon'
import { hydra, rdf, schema } from '@tpluscode/rdf-ns-builders'
import RdfResource from '@tpluscode/rdfine'
import * as Hydra from '@rdfine/hydra'
import { parsers } from '@rdfjs/formats-common'
import toStream from 'string-to-stream'
import { hydraBox } from './support/hydra-box'
import { get } from '../collection'
import { auth, query } from '../lib/namespace'
import { ex } from './support/namespace'
import * as collectionQuery from '../lib/query/collection'
import * as ns from '../lib/namespace'

RdfResource.factory.addMixin(...Object.values(Hydra))

describe('labyrinth/collection', () => {
  let collectionQueryMock: SinonStubbedInstance<typeof collectionQuery>
  let membersQuery: SinonStub
  let totalsQuery: SinonStub

  beforeEach(() => {
    collectionQueryMock = sinon.stub(collectionQuery)
    membersQuery = sinon.stub().resolves($rdf.dataset().toStream())
    totalsQuery = sinon.stub().resolves([])

    collectionQueryMock.getSparqlQuery.resolves({
      members: {
        execute: membersQuery,
      },
      totals: {
        execute: totalsQuery,
      },
    } as any)
  })

  afterEach(() => {
    sinon.restore()
  })

  describe('get', () => {
    it('returns 401 when collection is restricted', async () => {
      // given
      const app = express()
      app.use(hydraBox({
        setup: hydra => {
          hydra.operation.addOut(auth.required, true)
        },
      }))
      app.use(get)

      // when
      const response = request(app).get('/')

      // then
      await response.expect(401)
    })

    it('sets canonical link header', async () => {
      // given
      const app = express()
      app.use(hydraBox({
        setup: hydra => {
          hydra.resource.term = ex.people
        },
      }))
      app.use(get)

      // when
      const { links } = await request(app).get('/')

      // then
      expect(links).to.have.property('canonical', 'http://example.com/people')
    })

    it('does not add view when there is no page variable', async () => {
      // given
      const app = express()
      app.use(hydraBox({
        setup: api => {
          api.operation.addOut(ns.hydraBox.variables, template => {
            template.addOut(rdf.type, hydra.IriTemplate)
            template.addOut(hydra.template, '/{?title}')
            template.addOut(hydra.mapping, mapping => {
              mapping.addOut(rdf.type, hydra.IriTemplateMapping)
              mapping.addOut(hydra.property, schema.title)
              mapping.addOut(hydra.variable, 'title')
            })
          })
        },
      }))
      app.use(get)

      // when
      const res = await request(app).get('/')

      // then
      const dataset = await $rdf.dataset().import(parsers.import('application/ld+json', toStream(res.text))!)
      const views = cf({ dataset })
        .has(hydra.view)
        .values

      expect(views).to.have.length(0)
    })

    it('adds mapped template values to collection', async () => {
      // given
      const app = express()
      app.use(hydraBox({
        setup: api => {
          api.resource.term = ex.people
          api.operation.addOut(ns.hydraBox.variables, template => {
            template.addOut(rdf.type, hydra.IriTemplate)
            template.addOut(hydra.template, '/{?title}')
            template.addOut(hydra.mapping, mapping => {
              mapping.addOut(rdf.type, hydra.IriTemplateMapping)
              mapping.addOut(hydra.property, schema.title)
              mapping.addOut(hydra.variable, 'title')
            })
          })
        },
        query: cf({ dataset: $rdf.dataset() }).blankNode().addOut(schema.title, 'Titanic'),
      }))
      app.use(get)

      // when
      const res = await request(app).get('/')

      // then
      const dataset = await $rdf.dataset().import(parsers.import('application/ld+json', toStream(res.text))!)
      const title = cf({ dataset })
        .out(query.templateMappings)
        .out(schema.title)
        .value

      expect(title).to.eq('Titanic')
    })

    it('adds pages links', async () => {
      // given
      const app = express()
      app.use(hydraBox({
        setup: api => {
          api.resource.term = ex.people
          api.operation.addOut(ns.hydraBox.variables, template => {
            template.addOut(rdf.type, hydra.IriTemplate)
            template.addOut(hydra.template, '/{?title,page}')
            template.addOut(hydra.mapping, mapping => {
              mapping.addOut(rdf.type, hydra.IriTemplateMapping)
              mapping.addOut(hydra.property, schema.title)
              mapping.addOut(hydra.variable, 'title')
            })
            template.addOut(hydra.mapping, mapping => {
              mapping.addOut(rdf.type, hydra.IriTemplateMapping)
              mapping.addOut(hydra.property, hydra.pageIndex)
              mapping.addOut(hydra.variable, 'page')
            })
          })
        },
        query: cf({ dataset: $rdf.dataset() }).blankNode()
          .addOut(hydra.pageIndex, 50)
          .addOut(schema.title, 'Titanic'),
      }))
      totalsQuery.resolves([{
        count: { value: 1000 },
      }])
      app.use(get)

      // when
      const res = await request(app).get('/')

      // then
      const dataset = await $rdf.dataset().import(parsers.import('application/ld+json', toStream(res.text))!)
      const view = cf({ dataset }).out(hydra.view)

      expect(view.out(hydra.first).value).to.eq('?title=Titanic')
      expect(view.out(hydra.previous).value).to.eq('?title=Titanic&page=49')
      expect(view.out(hydra.next).value).to.eq('?title=Titanic&page=51')
      expect(view.out(hydra.last).value).to.eq('?title=Titanic&page=84')
    })

    it('passes pageSize to create query function', async () => {
      // given
      const app = express()
      app.use(hydraBox({
        setup: api => {
          api.resource.term = ex.people
        },
      }))
      app.use((req, res, next) => {
        req.labyrinth.collection.pageSize = 25
        next()
      })
      app.use(get)

      // when
      await request(app).get('/')

      // then
      expect(collectionQueryMock.getSparqlQuery).to.have.been.calledOnceWith(sinon.match({
        pageSize: 25,
      }))
    })

    it('passes collection-type-defined page size to create query function', async () => {
      // given
      const app = express()
      app.use(hydraBox({
        setup: hydraBox => {
          hydraBox.resource.types.add(ex.Collection)
          cf(hydraBox.api).namedNode(ex.Collection)
            .addOut(hydra.limit, 15)
        },
      }))
      app.use((req, res, next) => {
        req.labyrinth.collection.pageSize = 25
        next()
      })
      app.use(get)

      // when
      await request(app).get('/')

      // then
      expect(collectionQueryMock.getSparqlQuery).to.have.been.calledOnceWith(sinon.match({
        pageSize: 15,
      }))
    })

    it('passes collection-specific page size to create query function', async () => {
      // given
      const app = express()
      app.use(hydraBox({
        setup: async hydraBox => {
          hydraBox.resource.types.add(ex.Collection);
          (await hydraBox.resource.clownface())
            .addOut(hydra.limit, 10)
          cf(hydraBox.api).namedNode(ex.Collection)
            .addOut(hydra.limit, 15)
        },
      }))
      app.use((req, res, next) => {
        req.labyrinth.collection.pageSize = 25
        next()
      })
      app.use(get)

      // when
      await request(app).get('/')

      // then
      expect(collectionQueryMock.getSparqlQuery).to.have.been.calledOnceWith(sinon.match({
        pageSize: 10,
      }))
    })

    it('returns empty collection when no query is returned', async function () {
      // given
      const app = express()
      collectionQueryMock.getSparqlQuery.resolves(null)
      app.use(hydraBox({
        setup: async api => {
          api.resource.term = ex.movies;
          (await api.resource.clownface())
            .addOut(rdf.type, ex.Collection)
          cf(api.api)
            .namedNode(ex.Collection)
            .addOut(hydra.manages,
              m => m.addOut(hydra.property, rdf.type).addOut(hydra.object, ex.Person))
        },
      }))
      app.use(get)

      // when
      const response = await request(app).get('/movies').expect(200)

      // then
      expect(response.body).to.matchSnapshot(this)
    })
  })
})
