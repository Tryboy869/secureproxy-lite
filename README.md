# 🔐 SecureProxy Lite

**SecureProxy Lite** est une passerelle proxy sécurisée simplifiée, conçue pour permettre aux utilisateurs d'accéder à différentes API (OpenAI, Anthropic, Stripe, etc.) via un point d'entrée unique, tout en protégeant leurs clés API.

> ⚠️ Cette version est un **prototype open-source** à but pédagogique ou expérimental. Elle n'est **pas prête pour une utilisation en production** sans durcissement de la sécurité.

---

## ✨ Fonctionnalités

- Proxy vers OpenAI, Anthropic, Stripe, GitHub (support de base inclus)
- Stockage chiffré des clés API via AES-GCM
- Authentification utilisateur par token
- Limitation de débit personnalisée par utilisateur
- Autorisation par IP (optionnelle)
- Interface CLI simple (`add`, `user`, `start`, `list`)
- Base de données SQLite autonome

---

## 📁 Structure du projet

secureproxy-lite/ ├── main.go           # Code principal (~350 lignes) ├── go.mod / go.sum   # Dépendances ├── .gitignore └── README.md

---

## 🚀 Démarrage rapide

### 1. Installer Go

Assurez-vous d'avoir Go 1.20+ :
```bash
go version

2. Cloner le dépôt

git clone https://gitlab.com/Tryboy869/secureproxy-lite.git
cd secureproxy-lite

3. Lancer le proxy

go run main.go start

Le serveur démarre sur http://localhost:8080


---

🔐 Ajouter un utilisateur

go run main.go user youremail@example.com 0.0.0.0

Un token d'accès sera généré et affiché.


---

🔑 Ajouter une clé API

Exemple avec OpenAI :

go run main.go add openai sk-xxxxxx


---

🌐 Appeler une API via le proxy

curl -H "Authorization: Bearer VOTRE_TOKEN" http://localhost:8080/proxy/openai/v1/models


---

🛠️ Commandes disponibles

go run main.go start
go run main.go user <email> [ips]
go run main.go add <service> <api-key>
go run main.go add-service <name> <url> <header> <scheme> <key>
go run main.go list


---

📌 Avertissements

Pas de gestion avancée des erreurs dans cette version.

Pas de logs structurés ni de shutdown propre.

Pas de nettoyage mémoire des utilisateurs inactifs.

Ne convient pas pour une utilisation commerciale.



---

📄 Licence

MIT


---

👤 Auteur

Projet initié par Daouda Abdoul Anzize 
🔗 anzizdaouda0@gmail.com / nexusstudio100@gmail.com
📅 Date de création : 13/07/2025


---

🌱 Version étendue

➡️ Une version plus robuste et sécurisée est en cours de développement.
