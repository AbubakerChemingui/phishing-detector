import os
from core import SCRIPT_DIR, MODEL_PATH, VECTORIZER_PATH
print('SCRIPT_DIR:', SCRIPT_DIR)
print('MODEL_PATH:', MODEL_PATH)
print('VECTORIZER_PATH:', VECTORIZER_PATH)
print('Model file exists:', os.path.exists(MODEL_PATH))
print('Vectorizer file exists:', os.path.exists(VECTORIZER_PATH))

from core import load_artifacts, MODEL, VECTORIZER
print('Before loading:')
print('MODEL:', MODEL)
print('VECTORIZER:', VECTORIZER)
load_artifacts()
print('After loading:')
print('MODEL:', MODEL)
print('VECTORIZER:', VECTORIZER)