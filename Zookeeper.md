# ZooKeeper - Installation & Configuration

## Introduction
Ce document détaille l'installation, la configuration et l'utilisation de **Apache ZooKeeper** pour le projet **KNOB**. 

---

## **Installation de ZooKeeper**

### **1. Télécharger et extraire ZooKeeper**
```bash
wget https://downloads.apache.org/zookeeper/stable/apache-zookeeper-3.8.4-bin.tar.gz
tar -xvzf apache-zookeeper-3.8.4-bin.tar.gz
cd apache-zookeeper-3.8.4-bin
```

### **2. Créer le fichier de configuration**
```bash
cp conf/zoo_sample.cfg conf/zoo.cfg
```

### **3. Modifier le fichier `conf/zoo.cfg`**
```bash
nano conf/zoo.cfg
```
Ajoutez/modifiez les paramètres suivants :
```properties
tickTime=2000
dataDir=/home/ubuntu/apache-zookeeper-3.8.4-bin/data
clientPort=2181
initLimit=5
syncLimit=2
```
 **Sauvegardez et quittez** : `CTRL + X` puis `Y` puis `ENTER`

---

## **Démarrer et arrêter ZooKeeper**

### **1. Lancer ZooKeeper**
```bash
cd apache-zookeeper-3.8.4-bin
bin/zkServer.sh start
```

### **2. Vérifier l'état de ZooKeeper**
```bash
bin/zkServer.sh status
```
**Résultat attendu :**
```
Mode: standalone
Client port found: 2181
```

### **3. Arrêter ZooKeeper**
```bash
bin/zkServer.sh stop
```

---

## **Client ZooKeeper (`zkCli.sh`)**

### **1. Se connecter au client ZooKeeper**
```bash
bin/zkCli.sh
```
**Exemples de commandes utiles dans `zkCli.sh`** :
| Commande | Explication |
|----------|------------|
| `ls /` | Lister les nœuds racines |
| `create /test "hello"` | Créer un nœud `/test` avec la valeur `"hello"` |
| `get /test` | Lire le contenu du nœud `/test` |
| `set /test "world"` | Modifier la valeur de `/test` |
| `delete /test` | Supprimer le nœud `/test` |

### **2. Vérifier les nœuds créés**
```bash
ls /knob
ls /knob/tasks
ls /knob/assign
```

---

## **Lancer l'architecture KNOB**

Nous avons automatisé **le lancement de ZooKeeper et de tous les scripts nécessaires** à l'aide d'un script **`start_knob.sh`**.

### **1. Créer et modifier `start_knob.sh`**
```bash
nano start_knob.sh
```
### **2. Lancer tout l’environnement**
```bash
./start_knob.sh
```

---

## **Gestion des tâches avec l’Admin**
Après lancement de `start_knob.sh`, utilisez le **menu interactif** pour gérer l'état du système.

### **1. Lancer l'Admin seul**
```bash
python3 knob_admin_tasks.py
```
**Exemples d'actions :**
```
=== MENU ADMIN ===
1. Lister l'état du système
2. Créer une tâche
3. Assigner les tâches
4. Quitter
```
- **Créer une tâche** (saisie manuelle) ➝ Assignation automatique par le Master.
- **Lister les workers et tâches en cours**.
- **Vérifier si un leader est actif**.

---

## **Vérifications post-exécution**
### **1. Voir les tâches créées**
```bash
ls /knob/tasks
```

### **2. Vérifier les assignations des workers**
```bash
ls /knob/assign
get /knob/assign/worker-XYZ
```

### **3. Vérifier l’exécution des tâches**
```bash
ls /knob/status
```
Si la tâche a bien été traitée, elle apparaîtra dans `/knob/status`.

---

## **Relancer des services**
Si un service tombe en panne, redémarrez-le **sans tout relancer**.

### **Redémarrer uniquement le worker**
```bash
python3 knob_worker.py &
```

### **Redémarrer uniquement l’Admin**
```bash
python3 knob_admin_tasks.py
```

### **Redémarrer uniquement le coordinateur (Master)**
```bash
python3 knob_coordinator.py &
```

---

## **Arrêter tout proprement**
```bash
pkill -f python3
bin/zkServer.sh stop
```

---

## **Résumé des Commandes Clés**
| Commande | Explication |
|----------|------------|
| `bin/zkServer.sh start` | Démarrer ZooKeeper |
| `bin/zkServer.sh status` | Vérifier l'état de ZooKeeper |
| `bin/zkServer.sh stop` | Arrêter ZooKeeper |
| `bin/zkCli.sh` | Accéder au client ZooKeeper |
| `ls /knob` | Lister les nœuds de l'architecture KNOB |
| `python3 knob_admin_tasks.py` | Lancer l'admin KNOB |
| `python3 knob_worker.py` | Lancer un worker |
| `python3 knob_coordinator.py` | Lancer le Master |
| `./start_knob.sh` | Démarrer tout l’environnement automatiquement |

---

