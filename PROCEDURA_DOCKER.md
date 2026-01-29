# FASE 2: Build & Push (Procedura Docker)

Esegui questi comandi dalla cartella del backend (`auth-python`).

## 1. Login al registro AWS ECR (token vale 12 ore)

```powershell
aws ecr get-login-password --region eu-south-1 | docker login --username AWS --password-stdin 000876600482.dkr.ecr.eu-south-1.amazonaws.com
```

## 2. Build dell'immagine

```powershell
docker build -t 000876600482.dkr.ecr.eu-south-1.amazonaws.com/ebartex-auth:latest .
```

## 3. Push su ECR

```powershell
docker push 000876600482.dkr.ecr.eu-south-1.amazonaws.com/ebartex-auth:latest
```

---

*Se il nome del repository ECR è diverso (es. `brx-auth`), sostituisci `ebartex-auth` con il nome corretto.*
