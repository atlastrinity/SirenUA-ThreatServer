import os
import sys

# Add the current directory to python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Load dotenv if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import firebase_admin
from firebase_admin import firestore
from server import init_firebase
from database.db_helpers import get_db

print("🔄 Initializing Firebase...")
init_firebase()
db = get_db()
if not db:
    print("❌ Failed to get Firestore client!")
    sys.exit(1)

# List of collections to wipe
collections = ['sirenua_backup', 'sirenua_history', 'sirenua_state', 'sirenua_errors', 'sirenua_rules']

def delete_collection_in_batches(db, col_name, batch_size=500):
    print(f"🔄 Wiping collection '{col_name}' in batches...")
    col_ref = db.collection(col_name)
    total_deleted = 0
    while True:
        docs = list(col_ref.limit(batch_size).stream())
        if not docs:
            break
        batch = db.batch()
        for doc in docs:
            batch.delete(doc.reference)
        batch.commit()
        total_deleted += len(docs)
        print(f"  🗑️ Deleted {len(docs)} documents (Total: {total_deleted})")
    print(f"✅ Collection '{col_name}' cleared! Deleted {total_deleted} documents in total.")

for col_name in collections:
    try:
        delete_collection_in_batches(db, col_name)
    except Exception as e:
        print(f"⚠️ Error clearing collection '{col_name}': {e}")

# Delete local SQLite db if exists
db_path = "threat_analytics.db"
if os.path.exists(db_path):
    os.remove(db_path)
    print(f"🗑️ Deleted local SQLite database file '{db_path}'.")
else:
    print("ℹ️ Local SQLite database file not found, skipping delete.")

# We also want to delete it in the deployment directory just in case it is run locally there
deploy_db_path = "../SirenUA-ThreatServer/threat_analytics.db"
if os.path.exists(deploy_db_path):
    os.remove(deploy_db_path)
    print(f"🗑️ Deleted deployment SQLite database file '{deploy_db_path}'.")
