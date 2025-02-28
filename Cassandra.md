# Cassandra - Installation & Configuration

## Introduction
Ce document explique comment installer et configurer Apache Cassandra sur un environnement Linux. Il inclut également les commandes essentielles pour la gestion du cluster.

---

## Installation de Cassandra

###  **Ajout des clés et du dépôt Apache**
```bash
sudo curl -o /etc/apt/keyrings/apache-cassandra.asc https://downloads.apache.org/cassandra/KEYS
echo "deb [signed-by=/etc/apt/keyrings/apache-cassandra.asc] https://debian.cassandra.apache.org 41x main" | sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
```

### **Mise à jour**
```bash
sudo apt-get update
sudo apt-get install cassandra -y
```

### **Démarrer et activer Cassandra au démarrage**
```bash
sudo systemctl start cassandra
sudo systemctl status cassandra
```

---

## **Résolution de l'erreur "Exited" après installation**

Si Cassandra ne démarre pas correctement après l'installation (**hors problème de mémoire OOM**), il peut s'agir d'un problème lié au **nom du cluster** non mis à jour.

### **Correction**
```bash
sudo systemctl stop cassandra
sudo rm -rf /var/lib/cassandra/data/system/*
sudo systemctl start cassandra
```

---

## Configuration du Cluster

### **Fichier de configuration**
Le fichier principal de configuration de Cassandra est :
```bash
/etc/cassandra/cassandra.yaml
```

### **Paramètres essentiels**
| Paramètre | Explication |
|-----------|------------|
| `cluster_name` | Nom du cluster (doit être identique sur tous les nœuds) |
| `listen_address` | Adresse IP privée du nœud (@PRIVE_VM1, @PRIVE_VM2...) |
| `rpc_address` | Adresse d'écoute pour les clients.  |
| `seed_provider` | Liste des **nœuds SEED** pour initialiser le cluster |

### **Mise à jour du fichier `cassandra.yaml`**
Exemple de configuration **à faire sur chaque VM** :
```yaml
cluster_name: "KnobCluster"
listen_address: @PRIVE_VM1
rpc_address: 0.0.0.0
broadcast_rpc_address: @PRIVE_VM1
seed_provider:
  - class_name: org.apache.cassandra.locator.SimpleSeedProvider
    parameters:
      - seeds: "@PRIVE_VM1, @PRIVE_VM2"
endpoint_snitch: GossipingPropertyFileSnitch
auto_bootstrap: true
```

Après modification :
```bash
sudo systemctl restart cassandra
```

---

## Création des Keyspaces et Tables

### **Vérifier les keyspaces existants**
```cqlsh
DESCRIBE KEYSPACES;
```

### **Créer un keyspace**
```cqlsh
CREATE KEYSPACE IF NOT EXISTS data_keyspace
WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 3};
```

### **Créer une table pour stocker les fichiers chiffrés**
```cqlsh
CREATE TABLE IF NOT EXISTS data_keyspace.file_blocks (
    file_id UUID PRIMARY KEY,
    block_data BLOB,
    metadata TEXT
);
```

### **Lister les tables d'un keyspace**
```cqlsh
USE data_keyspace;
DESCRIBE TABLES;
```

---

## Commandes Usuelles

### **Vérifier l'état du cluster**
```bash
nodetool status
```
**Sortie attendue si tout fonctionne correctement :**
```
Datacenter: datacenter1
=======================
Status=Up/Down
|/ State=Normal/Leaving/Joining/Moving
--  Address        Load       Tokens  Owns  Host ID                               Rack
UN  @PRIVE_VM1    214.37 KiB  16      ?     4caeb9b8-e6c1-46f4-b450-dbc1f484a7e7  rack1
UN  @PRIVE_VM2    316.14 KiB  16      ?     53f79de6-6277-4682-b461-05437fc6ec73  rack1
UN  @PRIVE_VM3    286.44 KiB  16      ?     05c316d0-ed56-4208-91eb-a00768ec1461  rack1
UN  @PRIVE_VM4    323.5 KiB   16      ?     652251ea-edc4-444a-b1f3-ae6b0f22a6c0  rack1
```
- `UN` signifie **Up & Normal** → Le nœud fonctionne et est bien dans le cluster.
- `Down` signifie qu'un nœud ne répond pas et peut nécessiter une vérification.

### **Se connecter à Cassandra via CQLSH**
```bash
cqlsh
```

### **Vérifier les tables dans un keyspace**
```cqlsh
USE data_keyspace;
DESCRIBE TABLES;
```

### **Insérer un fichier chiffré**
```cqlsh
INSERT INTO data_keyspace.file_blocks (file_id, block_data, metadata)
VALUES (uuid(), 0x48656C6C6F20576F726C64, 'Encrypted file example');
```

### **Lire les données stockées**
```cqlsh
SELECT * FROM data_keyspace.file_blocks;
```

### **Arrêter et redémarrer Cassandra**
```bash
sudo systemctl stop cassandra
sudo systemctl start cassandra
```

---
