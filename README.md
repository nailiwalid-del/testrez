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
