import { rdf, sh } from '@tpluscode/rdf-ns-builders'
import { shaclMiddleware } from 'express-middleware-shacl'

export const shaclValidate = shaclMiddleware({
  async loadShapes(req, res, next) {
    const loaded = req.shacl.dataGraph.out(rdf.type).map(type => req.knossos.store.load(type.term))

    const shapes = await Promise.all(loaded)

    for (const shape of shapes) {
      if (shape.has(rdf.type, sh.NodeShape).terms.length) {
        req.shacl.shapesGraph.addAll(shape.dataset)
      }
    }

    next()
  },
  getTerm: req => req.hydra.term,
})
