# testrez

# 1. Créer la lib outil (une fois)
system "CRTLIB LIB(NETDIAGLIB)"

# 2. Transférer ftpbatch.clle dans l'IFS (ex: /home/netdiag/) puis compiler
system "CRTBNDCL PGM(NETDIAGLIB/FTPBATCH) SRCSTMF('/home/netdiag/ftpbatch.clle')"

# 3. Rendre le script exécutable
chmod 700 /home/netdiag/netsavf_probe.sh

# 4. Lancer (mot de passe par env, pas en argv)
POV_FTP_PASSWORD='secret' /QOpenSys/usr/bin/sh /home/netdiag/netsavf_probe.sh \
  -h 10.10.20.30 -u FTPUSER -l MYLIB -s MYSAVF -d /incoming -L NETDIAGLIB
---------------------------

# Sources dans l'IFS : /home/netdiag/runprobe.cmd et runprobecl.clle
# 1) Le programme de traitement
system "CRTBNDCL PGM(NETDIAGLIB/RUNPROBECL) SRCSTMF('/home/netdiag/runprobecl.clle')"




ADDENVVAR ENVVAR('POV_FTP_PASSWORD') VALUE('secret') LEVEL(*JOB)
SBMJOB CMD(QSH CMD('/QOpenSys/usr/bin/sh /home/netdiag/netsavf_probe_nc.sh -h 10.10.20.30 -u FTPUSER -l MYLIB -s MYSAVF -d /incoming')) JOB(NETPROBE)


Pour une cible Windows (IIS FTP) je force le mode passif (-M passive) — c'est ce qui passe le mieux à travers un pare-feu quand l'IBM i est client. Pas de -i (le distant n'est pas un IBM i).

Commande SBMJOB
Remplace FTPUSER, MOTDEPASSE, MYLIB/MYSAVF et le répertoire distant -d / par tes valeurs :

SBMJOB CMD(QSH CMD('POV_FTP_PASSWORD=MOTDEPASSE /QOpenSys/usr/bin/sh /home/netdiag/netsavf_probe_nc.sh -h 10.249.48.175 -u FTPUSER -l MYLIB -s MYSAVF -d / -M passive')) JOB(NETPROBE) JOBQ(QBATCH)
Premier essai conseillé (sans trace, petit SAVF)
Ça valide le chemin FTP/rapport sans dépendre de l'autorité *SERVICE (requise par TRCCNN) :

SBMJOB CMD(QSH CMD('POV_FTP_PASSWORD=MOTDEPASSE /QOpenSys/usr/bin/sh /home/netdiag/netsavf_probe_nc.sh -h 10.249.48.175 -u FTPUSER -l MYLIB -s MYSAVF -d / -M passive -x')) JOB(NETPROBE) JOBQ(QBATCH)
Points d'attention
-d / = répertoire distant sur le serveur Windows. Mets le vrai dossier cible IIS (ex. -d /incoming ou -d /upload). / = racine du site FTP.
Mot de passe dans le joblog : en SBMJOB, le mot de passe est en clair dans la requête du job soumis (visible via WRKSBMJOB → option 5 → données de requête). C'est inhérent à SBMJOB — ADDENVVAR posé dans ta session interactive n'est pas propagé au job soumis. Si la discrétion prime, lance plutôt en interactif (Méthode A avec ADDENVVAR/RMVENVVAR) ou purge le joblog ensuite. Évite un mot de passe contenant ', $, ` (casse le quoting CL/shell).
Mode actif si besoin : si le passif est bloqué par le pare-feu Windows, réessaie avec -M active. Le rapport te dira si le canal DATA a un souci (425/426).
Résultat : à la fin du job, le rapport est dans /tmp/netsavf/<run_id>/ :
WRKLNK '/tmp/netsavf'
EDTF STMF('/tmp/netsavf/<run_id>/report.txt')
Suivi du job : WRKSBMJOB (ou WRKJOB JOB(NETPROBE)), puis regarde le spool + cl.log/ftp.out dans le répertoire de sortie pour confirmer que ftp.out contient bien tes échanges (230, PASV, 226).
