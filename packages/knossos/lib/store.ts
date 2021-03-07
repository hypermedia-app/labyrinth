import { NamedNode, Term } from 'rdf-js'
import clownface, { GraphPointer } from 'clownface'
import { StreamClient } from 'sparql-http-client/StreamClient'
import { ASK, CONSTRUCT, INSERT } from '@tpluscode/sparql-builder'
import $rdf from 'rdf-ext'
import { sparql } from '@tpluscode/rdf-string'

export interface ResourceStore {
  exists(term: Term): Promise<boolean>

  load(term: Term): Promise<GraphPointer<NamedNode>>

  save(resource: GraphPointer<NamedNode>): Promise<void>
}

function assertNamedNode(term: Term): asserts term is NamedNode {
  if (term.termType !== 'NamedNode') {
    throw new Error('Term must be a named node')
  }
}

export class ResourcePerGraphStore implements ResourceStore {
  constructor(private client: StreamClient) {
  }

  exists(term: Term): Promise<boolean> {
    assertNamedNode(term)

    return ASK`?s ?p ?o`.FROM(term).execute(this.client.query)
  }

  async load(term: Term): Promise<GraphPointer<NamedNode>> {
    assertNamedNode(term)

    const dataset = await $rdf.dataset().import(await CONSTRUCT`?s ?p ?o`
      .FROM(term)
      .WHERE`?s ?p ?o`
      .execute(this.client.query))

    return clownface({ dataset, term })
  }

  async save(resource: GraphPointer<NamedNode>): Promise<void> {
    const insert = INSERT.DATA`GRAPH ${resource.term} { ${resource.dataset} }`
    const query = sparql`DROP SILENT GRAPH ${resource.term}; ${insert}`

    return this.client.query.update(query.toString())
  }
}