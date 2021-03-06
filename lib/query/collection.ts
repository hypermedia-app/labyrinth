import { CONSTRUCT, SELECT } from '@tpluscode/sparql-builder'
import { hydra, ldp, rdf } from '@tpluscode/rdf-ns-builders'
import $rdf from 'rdf-ext'
import cf, { AnyPointer, GraphPointer } from 'clownface'
import { sparql, SparqlTemplateResult } from '@tpluscode/rdf-string'
import { IriTemplate, IriTemplateMapping } from '@rdfine/hydra'
import { Term, Variable } from 'rdf-js'
import { loaders } from '../rdfLoaders'
import { query } from '../namespace'
import { log, warn } from '../logger'

interface CreatePattern {
  (options: { subject: Variable; predicate: Term; object: AnyPointer }): string | SparqlTemplateResult
}

function createTemplateVariablePatterns(subject: Variable, queryPointer: AnyPointer, basePath: string) {
  return async (mapping: IriTemplateMapping): Promise<string | SparqlTemplateResult> => {
    const property = mapping.property
    if (!property) {
      log('Skipping mapping without property')
      return ''
    }

    if (hydra.pageIndex.equals(property.id)) {
      log('Skipping hydra:pageIndex property from query filters')
      return ''
    }

    const value = queryPointer.out(property.id)
    if (value.values.length === 0) {
      return ''
    }

    const queryFilters = mapping.pointer.out(query.filter)
    if (!queryFilters.value) {
      return ''
    }

    const createPattern = await loaders.load<CreatePattern>(queryFilters.toArray()[0], { basePath })
    if (!createPattern) {
      warn('Failed to load pattern function')
      return ''
    }

    return createPattern({
      subject,
      predicate: property.id,
      object: value,
    })
  }
}

function createManagesBlockPatterns(member: Variable) {
  return function (previous: SparqlTemplateResult, manages: GraphPointer): SparqlTemplateResult {
    const subject = manages.out(hydra.subject).term
    const predicate = manages.out(hydra.property).term
    const object = manages.out(hydra.object).term

    if (subject && predicate) {
      return sparql`${previous}\n${subject} ${predicate} ${member} .`
    }
    if (subject && object) {
      return sparql`${previous}\n${subject} ${member} ${object} .`
    }
    if (predicate && object) {
      return sparql`${previous}\n${member} ${predicate} ${object} .`
    }

    return previous
  }
}

function onlyValidManagesBlocks(manages: GraphPointer) {
  return manages.out([hydra.subject, hydra.property, hydra.object]).values.length === 2
}

type SelectBuilder = ReturnType<typeof SELECT>

function createOrdering(api: GraphPointer, collection: GraphPointer, subject: Variable): { patterns: SparqlTemplateResult; addClauses(q: SelectBuilder): SelectBuilder } {
  const orders = api.node(collection.out(rdf.type) as any).out(query.order).toArray()
  if (!orders.length) {
    return {
      patterns: sparql``,
      addClauses: q => q,
    }
  }

  let orderIndex = 0
  let patterns = sparql``
  const clauses: Array<{ variable: Variable; descending: boolean }> = []

  for (const order of orders[0].list()!) {
    const propertyPath = order.out(query.path).list()
    if (!propertyPath) continue

    const path = [...propertyPath].reduce((current, prop, index) => {
      const next = index ? sparql`/${prop.term}` : sparql`${prop.term}`

      return sparql`${current}${next}`
    }, sparql``)
    const variable = $rdf.variable(`order${++orderIndex}`)

    const pattern = sparql`OPTIONAL { ${subject} ${path} ${variable} } .`
    patterns = sparql`${patterns}\n${pattern}`

    clauses.push({
      variable,
      descending: ldp.Descending.equals(order.out(query.direction).term),
    })
  }

  return {
    patterns,
    addClauses(query) {
      return clauses.reduce((orderedQuery, { variable, descending }) => {
        return orderedQuery.ORDER().BY(variable, descending)
      }, query)
    },
  }
}

interface CollectionQueryParams {
  api: GraphPointer
  collection: GraphPointer
  query?: AnyPointer
  variables: IriTemplate | null
  pageSize: number
  basePath: string
}

export interface SparqlQueries {
  members: ReturnType<typeof CONSTRUCT>
  totals: ReturnType<typeof SELECT>
}

export async function getSparqlQuery({ api, basePath, collection, pageSize, query = cf({ dataset: $rdf.dataset() }), variables } : CollectionQueryParams): Promise<SparqlQueries | null> {
  const subject = $rdf.variable('member')
  const manages = collection
    .out(hydra.manages)
    .filter(onlyValidManagesBlocks)
  if (!manages.values.length) {
    warn(`Collection ${collection.value} has no valid manages block and will always return empty`)
    return null
  }

  const managesBlockPatterns = manages.toArray().reduce(createManagesBlockPatterns(subject), sparql``)
  let filterPatters: Array<string | SparqlTemplateResult> = []
  if (variables) {
    filterPatters = await Promise.all(variables.mapping.map(createTemplateVariablePatterns(subject, query, basePath)))
  }

  const order = createOrdering(api, collection, subject)

  const memberPatterns = sparql`${managesBlockPatterns}\n${filterPatters}`

  let subselect = SELECT`?g`.WHERE` 
              GRAPH ?g {
                ${memberPatterns}
                
                ${order.patterns}
              }`

  if (variables && variables.mapping.some(mapping => mapping.property?.equals(hydra.pageIndex))) {
    const page = Number.parseInt(query.out(hydra.pageIndex).value || '1')
    const hydraLimit = query.out(hydra.limit).value
    const limit = hydraLimit ? parseInt(hydraLimit) : pageSize

    subselect = subselect.LIMIT(limit).OFFSET((page - 1) * limit)
    subselect = order.addClauses(subselect)
  }

  return {
    members: CONSTRUCT`?s ?p ?o`.WHERE`
        {
            ${subselect}
        }
        
        GRAPH ?g { ?s ?p ?o }`,
    totals: SELECT`(count(${subject}) as ?count)`.WHERE`GRAPH ?g { ${memberPatterns} }`,
  }
}
