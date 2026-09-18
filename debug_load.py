from core import load_artifacts, MODEL, VECTORIZER
print('Before loading:')
print('MODEL:', MODEL)
print('VECTORIZER:', VECTORIZER)
try:
    load_artifacts()
    print('After loading:')
    print('MODEL:', MODEL)
    print('VECTORIZER:', VECTORIZER)
except Exception as e:
    print('Exception:', e)
    import traceback
    traceback.print_exc()