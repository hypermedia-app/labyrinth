import clownface, { GraphPointer } from 'clownface'
import { NamedNode } from 'rdf-js'
import $rdf from 'rdf-ext'
import { foaf, hydra, rdf, rdfs, sh } from '@tpluscode/rdf-ns-builders'
import { acl, auth, code } from '@hydrofoil/labyrinth/lib/namespace'
import { fromPointer as initCollection } from '@rdfine/hydra/lib/Collection'
import { NamespaceBuilder } from '@rdfjs/namespace'
import { knossos } from './namespace'

interface Namespaces {
  api: NamespaceBuilder
  root: NamespaceBuilder
}

export function ApiDocumentation({ api, root }: Namespaces): GraphPointer<NamedNode> {
  const graph = clownface({ dataset: $rdf.dataset() })

  graph.node(hydra.Resource)
    .addOut(hydra.supportedOperation, operation => {
      operation
        .addOut(hydra.method, 'GET')
        .addOut(auth.access, acl.Read)
        .addOut(code.implementedBy, implementation => {
          implementation
            .addOut(rdf.type, code.EcmaScript)
            .addOut(code.link, graph.namedNode('node:@hydrofoil/labyrinth/resource#get'))
        })
    })

  graph.node(hydra.Collection)
    .addOut(hydra.supportedOperation, operation => {
      operation
        .addOut(hydra.method, 'GET')
        .addOut(auth.access, acl.Read)
        .addOut(code.implementedBy, implementation => {
          implementation
            .addOut(rdf.type, code.EcmaScript)
            .addOut(code.link, graph.namedNode('node:@hydrofoil/labyrinth/collection#get'))
        })
    })

  return graph.node(api())
    .addOut(rdf.type, hydra.ApiDocumentation)
    .addOut(hydra.entrypoint, graph.namedNode(root()))
}

export function Entrypoint({ api }: Namespaces): GraphPointer<NamedNode> {
  return clownface({ dataset: $rdf.dataset() })
    .namedNode(api())
    .addOut(rdf.type, hydra.Resource)
}

export function ClassesCollection({ api }: Namespaces): GraphPointer<NamedNode> {
  const pointer = clownface({ dataset: $rdf.dataset() })
    .namedNode(api.classes)

  initCollection(pointer, {
    manages: [{
      property: rdf.type,
      object: hydra.Class,
    }],
  })

  return pointer
}

export function HydraClass(): GraphPointer<NamedNode> {
  const graph = clownface({ dataset: $rdf.dataset() })

  return graph.namedNode(hydra.Class)
    .addOut(rdf.type, [sh.NodeShape, rdfs.Class, hydra.Class])
    .addOut(knossos.createWithPUT, true)
    .addOut(hydra.supportedOperation, operation => {
      operation
        .addOut(hydra.method, 'PUT')
        .addOut(auth.access, acl.Write)
        .addOut(code.implementedBy, implementation => {
          implementation
            .addOut(rdf.type, code.EcmaScript)
            .addOut(code.link, graph.namedNode('node:@hydrofoil/knossos/resource#PUT'))
        })
    })
    .addOut(hydra.supportedOperation, operation => {
      operation
        .addOut(hydra.method, 'DELETE')
        .addOut(auth.access, acl.Delete)
        .addOut(code.implementedBy, implementation => {
          implementation
            .addOut(rdf.type, code.EcmaScript)
            .addOut(code.link, graph.namedNode('node:@hydrofoil/knossos/resource#DELETE'))
        })
    })
}

export function SystemUser({ root }: Namespaces): GraphPointer<NamedNode> {
  return clownface({ dataset: $rdf.dataset() })
    .namedNode(root('user/SYSTEM'))
    .addOut(rdf.type, [foaf.Agent, knossos.SystemAccount])
}

export function * SystemAuthorizations({ api, root }: Namespaces): Generator<GraphPointer<NamedNode>> {
  yield clownface({ dataset: $rdf.dataset() })
    .namedNode(api('authorization/system-controls-resources'))
    .addOut(rdf.type, acl.Authorization)
    .addOut(acl.accessToClass, hydra.Resource)
    .addOut(acl.mode, acl.Control)
    .addOut(acl.agent, root('user/SYSTEM'))

  yield clownface({ dataset: $rdf.dataset() })
    .namedNode(api('authorization/system-controls-classes'))
    .addOut(rdf.type, acl.Authorization)
    .addOut(acl.accessToClass, hydra.Class)
    .addOut(acl.mode, acl.Control)
    .addOut(acl.agent, root('user/SYSTEM'))

  yield clownface({ dataset: $rdf.dataset() })
    .namedNode(api('authorization/system-controls-authorizations'))
    .addOut(rdf.type, acl.Authorization)
    .addOut(acl.accessToClass, acl.Authorization)
    .addOut(acl.mode, acl.Control)
    .addOut(acl.agent, root('user/SYSTEM'))
}
