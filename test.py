from google import genai
import os
from dotenv import load_dotenv

load_dotenv()

# Initialisation du nouveau client
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

try:
    response = client.models.generate_content(
        model="gemini-2.0-flash-lite",
        contents="Dis 'Connexion établie avec le nouveau SDK' !"
    )
    print(response.text)
except Exception as e:
    print(f"Erreur avec le nouveau SDK : {e}")