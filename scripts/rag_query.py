import chromadb
import requests
from pathlib import Path
from sentence_transformers import SentenceTransformer

BASE_DIR = Path(__file__).resolve().parent
CHROMA_PATH = BASE_DIR / "chroma_db"
COLLECTION_NAME = "attack_kb"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "phi3"

def retrieve_context(query, n_results=5):
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    collection = client.get_collection(COLLECTION_NAME)
    embed_model = SentenceTransformer("all-MiniLM-L6-v2")

    query_embedding = embed_model.encode([query]).tolist()[0]
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results
    )
    return results["documents"][0]

def ask_ollama(prompt):
    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        },
        timeout=300
    )
    response.raise_for_status()
    return response.json()["response"]

def main():
    scenario_query = """
Volt Typhoon techniques involving proxy command and control,
valid account abuse, exploitation of edge infrastructure,
remote services lateral movement, and software deployment tools
inside U.S. electric utility networks
"""
    context_docs = retrieve_context(scenario_query, n_results=10)
    context = "\n\n".join(context_docs)

    prompt = f"""
You are a cybersecurity threat intelligence analyst.

Use ONLY the ATT&CK techniques listed in the context below.
Do NOT introduce techniques that are not present.
Do NOT invent ATT&CK IDs.
Do NOT invent timestamps, dates, infrastructure names, or tools.
If a detail is unknown, state "not specified in retrieved ATT&CK context".

ATT&CK Context:
{context}

Task:

Write a structured simulated incident report describing Volt Typhoon activity
targeting a U.S. electric utility environment.

Use ONLY techniques explicitly present in the context.

Include:

Executive Summary
Initial Access
Command and Control
Lateral Movement
Persistence
Impact Assessment
Containment Actions
"""

    print("RETRIEVED CONTEXT")
    print(context)

    print("OLLAMA RESPONSE")
    response_text = ask_ollama(prompt)
    print(response_text)

if __name__ == "__main__":
    main()
