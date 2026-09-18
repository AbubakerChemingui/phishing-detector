import core
print('Before loading:')
print('MODEL:', core.MODEL)
print('VECTORIZER:', core.VECTORIZER)
core.load_artifacts()
print('After loading:')
print('MODEL:', core.MODEL)
print('VECTORIZER:', core.VECTORIZER)