import { Router } from 'express'
import asyncMiddleware from 'middleware-async'
import { hydra, rdf } from '@tpluscode/rdf-ns-builders'
import error from 'http-errors'
import httpStatus from 'http-status'
import $rdf from 'rdf-ext'
import { NamedNode } from 'rdf-js'
import { fromPointer } from '@rdfine/hydra/lib/IriTemplate'
import type { ResourceIdentifier } from '@tpluscode/rdfine'
import clownface, { AnyPointer, GraphPointer } from 'clownface'
import { shaclValidate } from './lib/middleware/shacl'
import { knossos } from './lib/namespace'

function checkMemberTemplate(ptr: AnyPointer): ptr is GraphPointer<ResourceIdentifier> {
  return ptr.term?.termType === 'NamedNode' || ptr.term?.termType === 'BlankNode'
}

function rename(member: GraphPointer, id: NamedNode): GraphPointer<NamedNode> {
  for (const match of member.dataset.match(member.term)) {
    member.dataset.delete(match)
    member.dataset.add($rdf.quad(id, match.predicate, match.object, match.graph))
  }
  for (const match of member.dataset.match(null, null, member.term)) {
    member.dataset.delete(match)
    member.dataset.add($rdf.quad(match.subject, match.predicate, id, match.graph))
  }

  return member.node(id)
}

export const POST = Router().use(shaclValidate).use(asyncMiddleware(async (req, res, next) => {
  const api = clownface(req.hydra.api)
  const collection = await req.hydra.resource.clownface()
  const types = collection.out(hydra.manages).has(hydra.property, rdf.type).out(hydra.object)

  if (!types.terms.length) {
    return next(new error.InternalServerError('Collection does not have a member assertion with `hydra:property rdf:type`'))
  }

  const { type } = rdf
  const { memberTemplate } = knossos
  const memberTemplateS = api.node(collection.out(type)).out(memberTemplate)
  if (!checkMemberTemplate(memberTemplateS)) {
    req.knossos.log.extend('collection')('Found member templates %o', memberTemplateS.map(mt => mt.out(hydra.template).value))
    return next(new error.InternalServerError(`No unique knossos:memberTemplate found for collection ${collection.value}`))
  }

  let member = await req.resource()
  const memberId = new URL(fromPointer(memberTemplateS).expand(member), req.absoluteUrl()).toString()

  req.knossos.log(`Creating resource ${memberId}`)
  member = rename(member, $rdf.namedNode(memberId)).addOut(rdf.type, types)
  await req.knossos.store.save(member)

  res.status(httpStatus.CREATED)
  return res.dataset(member.dataset)
}))
