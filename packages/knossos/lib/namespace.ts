import namespace from '@rdfjs/namespace'

type KnossosTerms = 'createWithPUT' | 'memberTemplate' | 'SystemAccount'

export const knossos = namespace<KnossosTerms>('https://hypermedia.app/knossos#')
