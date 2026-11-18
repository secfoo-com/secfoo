import pickle

def restore_session(uploaded_bytes):
    return pickle.loads(uploaded_bytes)
