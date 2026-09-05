from pathlib import Path
import chromadb
from sentence_transformers import SentenceTransformer

BASE_DIR = Path(__file__).resolve().parent
CHROMA_PATH = BASE_DIR / "chroma_db"
COLLECTION_NAME = "attack_kb"

def run_query(collection, embed_model, query, n_results=3):
    query_embedding = embed_model.encode([query]).tolist()[0]
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results
    )

    for i, doc in enumerate(results["documents"][0], start=1):
        print(f"\nResult {i} \n{doc}\n")

def main():
    if not CHROMA_PATH.exists():
        raise FileNotFoundError(f"Could not find {CHROMA_PATH.resolve()}")

    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    collection = client.get_collection(COLLECTION_NAME)
    embed_model = SentenceTransformer("all-MiniLM-L6-v2")

    queries = [
        "living off the land techniques using built in Windows tools",
        "credential access and lateral movement in enterprise networks",
        "long term persistence and data exfiltration"
    ]

    for query in queries:
        run_query(collection, embed_model, query, n_results=3)

if __name__ == "__main__":
    main()
