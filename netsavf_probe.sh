#!/QOpenSys/usr/bin/sh
#
# NETSAVF Probe for IBM i (V7R2 / V7R3, 100% natif, sans open-source PASE)
# ---------------------------------------------------------------------------
# Envoie un *SAVF IBM i vers un serveur FTP distant et produit un rapport de
# diagnostic reseau : ping (avec bit DF si dispo), route, log FTP, debit
# mesure au temps mural, et trace paquet TRCCNN (capture IP globale -> a
# filtrer dans Wireshark, le filtre TCPDTA n'existant pas sur cette release).
#
# Le transfert FTP est encapsule dans le programme CL compile FTPBATCH pour
# fiabiliser les overrides INPUT/OUTPUT (voir ftpbatch.clle).
#
# Prerequis :
#   - Shell PASE/QShell IBM i
#   - Programme CL FTPBATCH compile dans la lib indiquee par -L (def NETDIAGLIB)
#   - Commande native TRCCNN pour la trace paquet : autorite *SERVICE
#   - Autorite d'ecriture dans le repertoire IFS de sortie
#
# Securite :
#   - FTP est en clair. Outil de diagnostic / reseau de confiance uniquement.
#   - Mot de passe : preferer la variable d'env POV_FTP_PASSWORD a l'option -p
#     (argv est visible dans ps / le joblog). Pas d'espaces/sauts de ligne.
#   - La capture TRCCNN n'est PAS filtrable ici : elle contient du trafic tiers.
#     Le PCAP est un fichier sensible (chmod 600) a purger apres analyse.

set -u
umask 077

PROGRAM_NAME="netsavf_probe"
VERSION="2.0.0"

HOST=""
USER_NAME=""
PASSWORD=""
SAVF_LIB=""
SAVF_NAME=""
REMOTE_DIR=""
REMOTE_FILE=""
OUTDIR="/tmp/netsavf"
PORT="21"
PING_COUNT="20"
PING_SIZE="1472"
TRACE_MB="512"
TRACE_ENABLED="1"
KEEP_IFS_COPY="0"
REMOTE_IBMI="0"
FTP_MODE="auto"
FTPBATCH_LIB="NETDIAGLIB"

# Mot de passe : env par defaut ; -p le remplace mais declenche un avertissement.
PASSWORD_VIA_OPT="0"
if [ -n "${POV_FTP_PASSWORD:-}" ]; then
  PASSWORD="$POV_FTP_PASSWORD"
fi

usage() {
  cat <<'EOF'
Usage:
  netsavf_probe.sh -h host -u user [-p password] -l SAVFLIB -s SAVF \
    -d remote_dir [-f remote_file] [-o outdir] [-P port] [-n ping_count] \
    [-b ping_size] [-t trace_mb] [-M auto|passive|active] [-L ftpbatch_lib] \
    [-i] [-x] [-k]

Requis:
  -h  Hote/IP FTP distant.
  -u  Utilisateur FTP.
  -l  Bibliotheque IBM i contenant le save file.
  -s  Nom de l'objet save file.
  -d  Repertoire/chemin distant sur le serveur FTP.

Mot de passe (un des deux) :
  -p  Mot de passe FTP (visible dans ps -> deconseille).
  env POV_FTP_PASSWORD=...  (recommande).

Options:
  -f  Nom du fichier distant. Def : SAVF.savf
  -o  Repertoire de sortie. Def : /tmp/netsavf
  -P  Port FTP. Def : 21
  -n  Nombre de paquets ping. Def : 20
  -b  Taille du gros ping (test MTU). Def : 1472
  -t  Taille table trace TRCCNN en Mo. Def : 512
  -M  Mode FTP : auto, passive, active. Def : auto
  -L  Bibliotheque du programme FTPBATCH. Def : NETDIAGLIB
  -i  Serveur distant IBM i : envoie "quote site namefmt 1".
  -x  Desactive la trace paquet TRCCNN.
  -k  Conserve la copie IFS temporaire du SAVF.

Exemple:
  POV_FTP_PASSWORD=secret /QOpenSys/usr/bin/sh netsavf_probe.sh \
    -h 10.10.20.30 -u FTPUSER -l MYLIB -s MYSAVF \
    -d /incoming -f MYSAVF.savf -o /tmp/netsavf -L NETDIAGLIB
EOF
}

fatal()       { echo "ERROR: $*" >&2; exit 1; }
warn_stdout() { echo "WARN: $*"  >&2; }

is_number() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

upper()         { printf "%s" "$1" | tr '[:lower:]' '[:upper:]'; }
sanitize_name() { printf "%s" "$1" | sed 's/[^A-Za-z0-9_.-]/_/g'; }

# Litteral CL entre quotes avec doublage des quotes internes.
clstr() { printf "'%s'" "$(printf "%s" "$1" | sed "s/'/''/g")"; }

sed_escape_regex() { printf "%s" "$1" | sed 's/[.[\*^$()+?{}|\\/]/\\&/g'; }

json_escape() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }
jstr()        { printf '"%s"' "$(json_escape "$1")"; }
jnum()        { case "$1" in ''|*[!0-9.]*) printf 'null' ;; *) printf '%s' "$1" ;; esac; }

is_ipv4() {
  printf "%s" "$1" | awk -F. '
    NF != 4 { exit 1 }
    { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i < 0 || $i > 255) exit 1; exit 0 }'
}

resolve_ipv4() {
  if is_ipv4 "$1"; then printf "%s" "$1"; return 0; fi
  if command -v getent >/dev/null 2>&1; then
    getent hosts "$1" 2>/dev/null | awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { print $1; exit }'
    return 0
  fi
  return 1
}

num_gt() { awk -v n="$1" -v t="$2" 'BEGIN { exit !((n + 0) > (t + 0)) }'; }
num_ge() { awk -v n="$1" -v t="$2" 'BEGIN { exit !((n + 0) >= (t + 0)) }'; }

while getopts "h:u:p:l:s:d:f:o:P:n:b:t:M:L:ixk" opt; do
  case "$opt" in
    h) HOST="$OPTARG" ;;
    u) USER_NAME="$OPTARG" ;;
    p) PASSWORD="$OPTARG"; PASSWORD_VIA_OPT="1" ;;
    l) SAVF_LIB="$OPTARG" ;;
    s) SAVF_NAME="$OPTARG" ;;
    d) REMOTE_DIR="$OPTARG" ;;
    f) REMOTE_FILE="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    P) PORT="$OPTARG" ;;
    n) PING_COUNT="$OPTARG" ;;
    b) PING_SIZE="$OPTARG" ;;
    t) TRACE_MB="$OPTARG" ;;
    M) FTP_MODE="$OPTARG" ;;
    L) FTPBATCH_LIB="$OPTARG" ;;
    i) REMOTE_IBMI="1" ;;
    x) TRACE_ENABLED="0" ;;
    k) KEEP_IFS_COPY="1" ;;
    *) usage; exit 2 ;;
  esac
done

[ -n "$HOST" ]       || { usage; exit 2; }
[ -n "$USER_NAME" ]  || { usage; exit 2; }
[ -n "$PASSWORD" ]   || { echo "ERROR: mot de passe absent (option -p ou env POV_FTP_PASSWORD)." >&2; exit 2; }
[ -n "$SAVF_LIB" ]   || { usage; exit 2; }
[ -n "$SAVF_NAME" ]  || { usage; exit 2; }
[ -n "$REMOTE_DIR" ] || { usage; exit 2; }

is_number "$PORT"       || fatal "-P port doit etre numerique"
is_number "$PING_COUNT" || fatal "-n ping_count doit etre numerique"
is_number "$PING_SIZE"  || fatal "-b ping_size doit etre numerique"
is_number "$TRACE_MB"   || fatal "-t trace_mb doit etre numerique"

case "$FTP_MODE" in
  auto|passive|active) ;;
  *) fatal "-M doit valoir auto, passive ou active" ;;
esac

if printf "%s" "$PASSWORD" | grep '[[:space:]]' >/dev/null 2>&1; then
  fatal "Mot de passe avec espaces/sauts de ligne non supporte par le FTP natif batch"
fi
if printf "%s" "$REMOTE_DIR$REMOTE_FILE" | grep '[[:space:]]' >/dev/null 2>&1; then
  fatal "Le chemin/fichier distant ne doit pas contenir d'espaces/sauts de ligne"
fi

if [ "$PASSWORD_VIA_OPT" = "1" ]; then
  warn_stdout "Mot de passe passe en -p (visible dans ps / joblog). Preferer POV_FTP_PASSWORD."
fi

SAVF_LIB="$(upper "$SAVF_LIB")"
SAVF_NAME="$(upper "$SAVF_NAME")"
[ -n "$REMOTE_FILE" ] || REMOTE_FILE="${SAVF_NAME}.savf"

if command -v system >/dev/null 2>&1; then
  SYSTEM_CMD="system"
elif [ -x /QOpenSys/usr/bin/system ]; then
  SYSTEM_CMD="/QOpenSys/usr/bin/system"
else
  fatal "Utilitaire IBM i 'system' introuvable en PASE"
fi

TS="$(date '+%Y%m%d_%H%M%S' 2>/dev/null || date)"
SAFE_HOST="$(sanitize_name "$HOST")"
RUN_ID="${PROGRAM_NAME}_${SAFE_HOST}_${TS}_$$"
WORK="${OUTDIR%/}/$RUN_ID"
mkdir -p "$WORK" || fatal "Impossible de creer le repertoire de sortie : $WORK"

REPORT="$WORK/report.txt"
SUMMARY_JSON="$WORK/summary.json"
CLLOG="$WORK/cl.log"
FTPIN="$WORK/ftp.in"
FTPIN_SAFE="$WORK/ftp.in.redacted"
FTPOUT_RAW="$WORK/ftp.raw"
FTPOUT="$WORK/ftp.out"
PING_SMALL="$WORK/ping_small.out"
PING_LARGE="$WORK/ping_large.out"
TRACEROUTE_OUT="$WORK/traceroute.out"
NETSTAT_ROUTES="$WORK/netstat_routes.out"
NETSTAT_CONNS="$WORK/netstat_connections.out"
PCAP="$WORK/trccnn.pcap"
PCAP_ANALYSIS="$WORK/pcap_analysis.out"
ISSUES="$WORK/issues.tmp"
SUMMARY="$WORK/summary.tmp"

: > "$CLLOG"; : > "$ISSUES"; : > "$SUMMARY"

run_cl() {
  echo "CL> $*" >> "$CLLOG"
  "$SYSTEM_CMD" "$*" >> "$CLLOG" 2>&1
}
run_cl_to() {
  _out="$1"; shift
  echo "CL> $*" >> "$CLLOG"
  "$SYSTEM_CMD" "$*" >> "$_out" 2>&1
}
issue() {
  sev="$1"; text="$2"; evidence="$3"
  {
    printf "[%s] %s\n" "$sev" "$text"
    [ -n "$evidence" ] && printf "  Evidence: %s\n" "$evidence"
  } >> "$ISSUES"
}
info_summary() { printf "%s\n" "$*" >> "$SUMMARY"; }

# ---------------------------------------------------------------------------
# Gestion de la trace TRCCNN (start / stop garanti via traps)
# ---------------------------------------------------------------------------
cleanup_trace_started="0"
cleanup_in_progress="0"
trace_table=""
trace_win_start=""
trace_win_stop=""

stop_trace() {
  reason="$1"
  if [ "$cleanup_trace_started" = "1" ] && [ -n "$trace_table" ]; then
    [ "$cleanup_in_progress" = "1" ] && return 0
    cleanup_in_progress="1"
    [ -z "$trace_win_stop" ] && trace_win_stop="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"

    if [ "$reason" = "normal" ]; then
      echo "Arret de TRCCNN et ecriture du PCAP..."
    else
      echo "Arret de TRCCNN apres $reason, ecriture PCAP si possible..." >&2
      issue "INFO" "Nettoyage TRCCNN declenche avant la fin normale." "reason=$reason table=$trace_table"
    fi

    # NOTE V7R2/V7R3 : verifier la syntaxe exacte du dump au prompt (F4).
    # Selon la release, SET(*OFF) + OUTPUT(*STMF) ecrit le .pcap ; sinon une
    # etape SET(*FORMAT) distincte peut etre requise.
    if run_cl "TRCCNN SET(*OFF) TRCTBL($trace_table) OUTPUT(*STMF) TOSTMF($(clstr "$PCAP"))"; then
      [ -f "$PCAP" ] && chmod 600 "$PCAP" 2>/dev/null || true
      info_summary "TRCCNN PCAP: $PCAP"
    else
      issue "MAJOR" "Le PCAP TRCCNN n'a pas pu etre ecrit." "table=$trace_table ; voir cl.log ; verifier syntaxe TRCCNN au F4."
    fi

    # Toujours terminer la table apres la tentative de dump.
    run_cl "TRCCNN SET(*END) TRCTBL($trace_table)" || true
    cleanup_trace_started="0"
    cleanup_in_progress="0"
  fi
}

cleanup_exit() {
  status=$?
  trap - EXIT HUP INT QUIT TERM
  stop_trace "exit_status=$status"
  exit "$status"
}
cleanup_signal() {
  sig="$1"; code="$2"
  trap - EXIT HUP INT QUIT TERM
  stop_trace "signal $sig"
  exit "$code"
}
trap cleanup_exit EXIT
trap 'cleanup_signal HUP 129' HUP
trap 'cleanup_signal INT 130' INT
trap 'cleanup_signal QUIT 131' QUIT
trap 'cleanup_signal TERM 143' TERM

echo "Repertoire de travail : $WORK"
info_summary "Work directory: $WORK"

# ---------------------------------------------------------------------------
# 1) Copie du SAVF vers l'IFS (avant le test : hors mesure reseau)
# ---------------------------------------------------------------------------
SAVF_QSYS="/QSYS.LIB/${SAVF_LIB}.LIB/${SAVF_NAME}.FILE"
LOCAL_BASENAME="${SAVF_NAME}.savf"
LOCAL_COPY="$WORK/$LOCAL_BASENAME"

echo "Verification et copie de $SAVF_LIB/$SAVF_NAME vers l'IFS..."
if ! run_cl "CHKOBJ OBJ($SAVF_LIB/$SAVF_NAME) OBJTYPE(*FILE)"; then
  fatal "Objet $SAVF_LIB/$SAVF_NAME introuvable ou inaccessible. Voir $CLLOG"
fi
if ! run_cl "CPYTOSTMF FROMMBR($(clstr "$SAVF_QSYS")) TOSTMF($(clstr "$LOCAL_COPY")) STMFOPT(*REPLACE) CVTDTA(*NONE)"; then
  fatal "Copie du SAVF vers stream file impossible. Voir $CLLOG"
fi

LOCAL_BYTES="$(wc -c < "$LOCAL_COPY" | tr -d ' ')"
LOCAL_MIB="$(awk -v b="$LOCAL_BYTES" 'BEGIN { printf "%.2f", b / 1048576 }')"
info_summary "Local SAVF copy: $LOCAL_COPY (${LOCAL_BYTES} bytes, ${LOCAL_MIB} MiB)"

TRACE_IP="$(resolve_ipv4 "$HOST" | head -1)"
MONITOR_MATCH="${TRACE_IP:-$HOST}"

# ---------------------------------------------------------------------------
# 2) Ping (petit + gros avec bit DF si le ping le supporte)
# ---------------------------------------------------------------------------
run_ping() {
  size="$1"; out="$2"; want_df="$3"
  if command -v ping >/dev/null 2>&1; then
    df_flag=""; df_used="no"
    if [ "$want_df" = "1" ]; then
      if ping -M do -c 1 -s 1 "$HOST" >/dev/null 2>&1; then
        df_flag="-M do"; df_used="yes"
      elif ping -D -c 1 -s 1 "$HOST" >/dev/null 2>&1; then
        df_flag="-D"; df_used="yes"
      fi
    fi
    echo "PASE ping -c $PING_COUNT -s $size $df_flag $HOST" > "$out"
    ping -c "$PING_COUNT" -s "$size" $df_flag "$HOST" >> "$out" 2>&1
    rc=$?
    echo "DF_USED=$df_used" >> "$out"
    return $rc
  fi
  echo "VFYTCPCNN natif (bit DF indisponible)" > "$out"
  echo "DF_USED=no" >> "$out"
  if is_ipv4 "$HOST"; then
    run_cl_to "$out" "VFYTCPCNN RMTSYS(*INTNETADR) INTNETADR('$HOST') PKTLEN($size) NBRPKT($PING_COUNT) WAITTIME(5) MSGMODE(*VERBOSE)"
    return $?
  fi
  echo "Pas de ping PASE et le fallback natif exige une IPv4." >> "$out"
  return 1
}

echo "Ping (petit + gros/MTU)..."
run_ping "56"         "$PING_SMALL" "0" || true
run_ping "$PING_SIZE" "$PING_LARGE" "1" || true

# ---------------------------------------------------------------------------
# 3) Route
# ---------------------------------------------------------------------------
echo "Collecte des informations de route..."
if command -v traceroute >/dev/null 2>&1; then
  traceroute "$HOST" > "$TRACEROUTE_OUT" 2>&1 || true
else
  echo "traceroute PASE absent ; fallback commande CL TRACEROUTE." > "$TRACEROUTE_OUT"
  run_cl_to "$TRACEROUTE_OUT" "TRACEROUTE RMTSYS($(clstr "$HOST"))" || true
fi

if command -v netstat >/dev/null 2>&1; then
  netstat -rn > "$NETSTAT_ROUTES" 2>&1 || true
else
  run_cl_to "$NETSTAT_ROUTES" "NETSTAT OPTION(*RTE)" || true
fi

# ---------------------------------------------------------------------------
# 4) Fichier des sous-commandes FTP (+ version redigee)
# ---------------------------------------------------------------------------
cat > "$FTPIN" <<EOF
$USER_NAME $PASSWORD
verbose
debug
EOF

if [ "$FTP_MODE" = "passive" ]; then
  printf "sendpasv 1\n" >> "$FTPIN"
elif [ "$FTP_MODE" = "active" ]; then
  printf "sendpasv 0\n" >> "$FTPIN"
  printf "sendport 1\n" >> "$FTPIN"
fi
[ "$REMOTE_IBMI" = "1" ] && printf "quote site namefmt 1\n" >> "$FTPIN"

cat >> "$FTPIN" <<EOF
bin
lcd $WORK
cd $REMOTE_DIR
put $LOCAL_BASENAME $REMOTE_FILE
quit
EOF

sed '1s/.*/'"$USER_NAME"' ********/' "$FTPIN" > "$FTPIN_SAFE"

# ---------------------------------------------------------------------------
# 5) Moniteur de connexions (background, sur l'IP resolue) + TRACE + TRANSFERT
# ---------------------------------------------------------------------------
monitor_flag="$WORK/monitor.on"
monitor_pid=""
if command -v netstat >/dev/null 2>&1; then
  : > "$monitor_flag"
  (
    while [ -f "$monitor_flag" ]; do
      date
      netstat -an 2>/dev/null | grep -F "$MONITOR_MATCH" || true
      sleep 2
    done
  ) > "$NETSTAT_CONNS" 2>&1 &
  monitor_pid="$!"
else
  echo "netstat PASE absent." > "$NETSTAT_CONNS"
fi

# Trace demarree JUSTE avant le transfert (fenetre serree : capture NON filtree).
if [ "$TRACE_ENABLED" = "1" ]; then
  pid2="$(expr $$ % 100 2>/dev/null || echo 0)"
  trace_table="PV$(date '+%H%M%S' 2>/dev/null)$(printf '%02d' "$pid2")"
  trace_table="$(printf "%s" "$trace_table" | cut -c1-10)"
  echo "Demarrage de la trace TRCCNN (capture IP globale)..."
  if run_cl "TRCCNN SET(*ON) TRCTYPE(*IP) TRCTBL($trace_table) SIZE($TRACE_MB *MB)"; then
    cleanup_trace_started="1"
    trace_win_start="$(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null)"
    info_summary "TRCCNN trace table: $trace_table"
    issue "INFO" "TRCCNN sans filtre IP (TCPDTA indisponible) : capture globale, a filtrer dans Wireshark." "PCAP bruite/sensible."
  else
    issue "MAJOR" "TRCCNN n'a pas pu demarrer." "Souvent autorite *SERVICE manquante ou ASP plein. Voir cl.log."
    cleanup_trace_started="0"
  fi
else
  issue "INFO" "Trace paquet TRCCNN desactivee (-x)." ""
fi

export POV_RMTSYS="$HOST"
export POV_PORT="$PORT"
export POV_INSTMF="$FTPIN"
export POV_OUTSTMF="$FTPOUT_RAW"

echo "Transfert FTP -> $HOST:$PORT $REMOTE_DIR/$REMOTE_FILE ..."
ftp_started_epoch="$(date '+%s' 2>/dev/null || echo 0)"
if run_cl "CALL PGM($FTPBATCH_LIB/FTPBATCH)"; then
  ftp_status="command_completed"
else
  ftp_status="command_failed"
fi
ftp_ended_epoch="$(date '+%s' 2>/dev/null || echo 0)"

# Stop trace immediatement (la suite est locale, hors reseau).
stop_trace "normal"

# Stop moniteur.
rm -f "$monitor_flag"
[ -n "$monitor_pid" ] && wait "$monitor_pid" 2>/dev/null || true

# Le mot de passe est en clair dans $FTPIN : on le supprime des maintenant.
rm -f "$FTPIN"

# ---------------------------------------------------------------------------
# 6) Redaction du log FTP (FTPBATCH a ecrit FTPOUT_RAW)
# ---------------------------------------------------------------------------
if [ -s "$FTPOUT_RAW" ]; then
  pass_re="$(sed_escape_regex "$PASSWORD")"
  sed -e "s/$pass_re/********/g" \
      -e 's/[Pp][Aa][Ss][Ss][[:space:]].*/PASS ********/g' \
      "$FTPOUT_RAW" > "$FTPOUT"
  rm -f "$FTPOUT_RAW"
else
  echo "Log FTP absent ou vide. Voir cl.log." > "$FTPOUT"
  issue "MAJOR" "Le log FTP est absent (FTPBATCH n'a rien produit)." "Verifier que FTPBATCH est compile dans $FTPBATCH_LIB et l'autorite FTP. Voir cl.log."
fi

# ---------------------------------------------------------------------------
# 7) Analyse PCAP automatique (si tshark present ; sinon Wireshark manuel)
# ---------------------------------------------------------------------------
if command -v tshark >/dev/null 2>&1 && [ -s "$PCAP" ]; then
  {
    echo "tshark TCP conversations:"
    tshark -r "$PCAP" -q -z conv,tcp 2>/dev/null || true
    echo
    printf "retransmissions="; tshark -r "$PCAP" -Y "tcp.analysis.retransmission" -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' '; echo
    printf "lost_segments=";   tshark -r "$PCAP" -Y "tcp.analysis.lost_segment"   -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' '; echo
    printf "duplicate_acks=";  tshark -r "$PCAP" -Y "tcp.analysis.duplicate_ack"  -T fields -e frame.number 2>/dev/null | wc -l | tr -d ' '; echo
  } > "$PCAP_ANALYSIS"
else
  echo "tshark absent ou PCAP manquant : ouvrir le PCAP dans Wireshark (filtre fourni dans le rapport)." > "$PCAP_ANALYSIS"
fi

# ---------------------------------------------------------------------------
# 8) Parsing : pertes/RTT, port data, ligne de transfert, debits
# ---------------------------------------------------------------------------
parse_loss() {
  awk '
    /packet loss/ { for (i=1;i<=NF;i++) if ($i ~ /%/){ gsub(/[,()%]/,"",$i); print $i; exit } }
    /successful/ && /%/ { for (i=1;i<=NF;i++) if ($i ~ /%/){ gsub(/[,()%]/,"",$i); print 100-$i; exit } }
  ' "$1" | tail -1
}
parse_avg_rtt() {
  awk '
    /min\/avg\/max/ {
      for (i=1;i<=NF;i++) if ($i=="=" && (i+1)<=NF){ split($(i+1),a,"/"); print a[2]; exit }
      split($NF,a,"/"); if (a[2]!="") print a[2]
    }' "$1" | tail -1
}
parse_data_port() {
  awk '
    /227[ -].*[Pp]assive/ {
      if (match($0,/\(([0-9]+,){5}[0-9]+\)/)){ seg=substr($0,RSTART+1,RLENGTH-2); split(seg,a,","); print a[5]*256+a[6]; exit } }
    /229[ -].*[Ee]xtended/ {
      s=$0; if (sub(/.*\(\|\|\|/,"",s) && sub(/\|\).*/,"",s)){ print s; exit } }
    /PORT[ ]+([0-9]+,){5}[0-9]+/ {
      if (match($0,/([0-9]+,){5}[0-9]+/)){ seg=substr($0,RSTART,RLENGTH); split(seg,a,","); print a[5]*256+a[6]; exit } }
  ' "$1"
}

small_loss="$(parse_loss "$PING_SMALL")"
large_loss="$(parse_loss "$PING_LARGE")"
small_avg="$(parse_avg_rtt "$PING_SMALL")"
large_avg="$(parse_avg_rtt "$PING_LARGE")"
df_large="$(awk -F= '/^DF_USED=/{print $2}' "$PING_LARGE" | tail -1)"
data_port="$(parse_data_port "$FTPOUT")"

[ -n "$small_loss" ] || small_loss="unknown"
[ -n "$large_loss" ] || large_loss="unknown"
[ -n "$small_avg" ]  || small_avg="unknown"
[ -n "$large_avg" ]  || large_avg="unknown"
[ -n "$df_large" ]   || df_large="no"
[ -n "$data_port" ]  || data_port="unknown"

transfer_line="$(grep -i "bytes transferred in" "$FTPOUT" | tail -1 || true)"
ftp_errors_file="$WORK/ftp_errors.tmp"
grep -En '(^|[[:space:]])[45][0-9][0-9]([ -]|$)|timed out|timeout|refused|reset|not connected|no route|unreachable|permission denied|broken pipe|failed|cannot|425|426|530|550' "$FTPOUT" > "$ftp_errors_file" 2>/dev/null || true

if [ -n "$transfer_line" ]; then
  ftp_bytes="$(printf "%s\n" "$transfer_line" | awk '{ print $1 }')"
  ftp_secs="$(printf "%s\n" "$transfer_line"  | awk '{ print $5 }')"
  ftp_rate="$(printf "%s\n" "$transfer_line"  | awk '{ print $(NF-1) " " $NF }')"
  ftp_mbps="$(awk -v b="$ftp_bytes" -v s="$ftp_secs" 'BEGIN { if (s>0) printf "%.2f",(b*8)/(s*1000000); else print "unknown" }')"
else
  ftp_bytes="unknown"; ftp_secs="unknown"; ftp_rate="unknown"; ftp_mbps="unknown"
fi

wall_secs="unknown"
if is_number "$ftp_started_epoch" && is_number "$ftp_ended_epoch" && [ "$ftp_started_epoch" -gt 0 ] && [ "$ftp_ended_epoch" -ge "$ftp_started_epoch" ]; then
  wall_secs="$(expr "$ftp_ended_epoch" - "$ftp_started_epoch" 2>/dev/null || echo unknown)"
fi

# Debit PRIMAIRE = temps mural + taille reelle du fichier.
if [ "$wall_secs" != "unknown" ] && [ "$wall_secs" -gt 0 ]; then
  wall_mbps="$(awk -v b="$LOCAL_BYTES" -v s="$wall_secs" 'BEGIN { printf "%.2f",(b*8)/(s*1000000) }')"
else
  wall_mbps="unknown"   # transfert < 1 s : granularite date(1) insuffisante
fi

tr_hops="$(grep -E '^[[:space:]]*[0-9]+' "$TRACEROUTE_OUT" 2>/dev/null | wc -l | tr -d ' ')"
tr_timeouts="$(grep -Ec '\* \* \*|timeout|unreachable|!H|!N|!X' "$TRACEROUTE_OUT" 2>/dev/null || echo 0)"

# ---------------------------------------------------------------------------
# 9) Detection des problemes
# ---------------------------------------------------------------------------
if [ -s "$ftp_errors_file" ]; then
  first_errors="$(head -5 "$ftp_errors_file" | tr '\n' '; ')"
  issue "CRITICAL" "FTP a signale des erreurs ou symptomes de connexion." "$first_errors"
fi
if grep -Eiq '425|426|PORT|PASV|passive|data connection|cannot open data|failed to establish data' "$FTPOUT"; then
  issue "MAJOR" "Probleme possible du canal DATA FTP (firewall/NAT)." "Essayer active/passive et verifier les regles du canal data."
fi
if grep -Eiq '530|login incorrect|not logged in' "$FTPOUT"; then
  issue "CRITICAL" "Authentification FTP echouee." "Verifier user/mot de passe/restrictions du serveur distant."
fi
if grep -Eiq '550|permission denied|no such file|not found|access denied' "$FTPOUT"; then
  issue "MAJOR" "Probleme de chemin, fichier ou autorite distante." "Verifier repertoire=$REMOTE_DIR et fichier=$REMOTE_FILE."
fi
if grep -Eiq 'timed out|timeout|connection refused|no route|unreachable|connection reset' "$FTPOUT"; then
  issue "CRITICAL" "Echec de connectivite IBM i <-> service FTP distant." "Verifier route, firewall, listener distant, NAT."
fi

if [ "$small_loss" != "unknown" ] && num_gt "$small_loss" "0"; then
  issue "MAJOR" "Perte de paquets ICMP sur le petit ping." "loss=${small_loss}% avg_rtt=${small_avg}ms"
fi

# Verdict MTU UNIQUEMENT si le bit DF a reellement ete pose (sinon fragmentation masque tout).
if [ "$df_large" = "yes" ]; then
  if [ "$large_loss" != "unknown" ] && num_gt "$large_loss" "0"; then
    issue "MAJOR" "Perte sur gros paquets AVEC bit DF -> MTU black hole probable." "loss=${large_loss}% payload=${PING_SIZE} DF=on : PMTUD casse (VPN/tunnel/firewall)."
  fi
  if [ "$small_loss" != "unknown" ] && [ "$large_loss" != "unknown" ] && num_ge "$small_loss" "0" && num_gt "$large_loss" "$small_loss"; then
    issue "MAJOR" "Les gros paquets echouent plus que les petits (DF actif)." "small=${small_loss}% large=${large_loss}% : MTU/fragmentation/VPN/inspection."
  fi
else
  issue "INFO" "Test MTU non concluant (bit DF indisponible) - verdict MTU desactive." "Sans DF les gros paquets sont fragmentes et passent : pas de fausse conclusion MTU."
fi

if [ "$small_avg" != "unknown" ] && num_gt "$small_avg" "100"; then
  issue "INFO" "Latence moyenne elevee sur le petit ping." "avg_rtt=${small_avg}ms"
fi
if [ "$tr_timeouts" != "0" ]; then
  issue "INFO" "Traceroute montre des sauts silencieux/timeouts." "timeouts=$tr_timeouts. Beaucoup de routeurs jettent les sondes ; correler avec FTP/ping."
fi

# Cout de setup TCP : debit mural nettement < debit phase-data FTP.
if [ "$wall_mbps" != "unknown" ] && [ "$ftp_mbps" != "unknown" ] && num_gt "$ftp_mbps" "0" && num_gt "$wall_mbps" "0"; then
  if awk -v w="$wall_mbps" -v f="$ftp_mbps" 'BEGIN{ exit !(f > w*1.3) }'; then
    issue "INFO" "Setup de connexion couteux (debit mural << debit phase-data)." "mural=${wall_mbps} vs FTP=${ftp_mbps} Mbit/s : latence handshake/DNS/NAT."
  fi
fi

retrans="unknown"; lostseg="unknown"; dupack="unknown"
if [ -s "$PCAP_ANALYSIS" ]; then
  retrans="$(awk -F= '/^retransmissions=/{print $2}' "$PCAP_ANALYSIS" | tail -1)"
  lostseg="$(awk -F= '/^lost_segments=/{print $2}' "$PCAP_ANALYSIS" | tail -1)"
  dupack="$(awk -F= '/^duplicate_acks=/{print $2}' "$PCAP_ANALYSIS" | tail -1)"
  [ -n "$retrans" ] || retrans="unknown"
  [ -n "$lostseg" ] || lostseg="unknown"
  [ -n "$dupack" ]  || dupack="unknown"
  if [ "$retrans" != "unknown" ] && num_gt "$retrans" "0"; then
    issue "MAJOR" "Retransmissions TCP trouvees dans le PCAP." "retrans=$retrans dup_ack=$dupack lost=$lostseg"
  fi
fi

if grep -Eiq 'Transfer complete|226 ' "$FTPOUT" && [ ! -s "$ftp_errors_file" ]; then
  ftp_result="OK"
else
  ftp_result="CHECK_LOG"
fi
[ -s "$ISSUES" ] || issue "OK" "Aucun probleme reseau/FTP evident detecte automatiquement." "Confirmer via PCAP/rapport."

# Severite maximale (pour le resume machine)
if   grep -q '^\[CRITICAL\]' "$ISSUES"; then top_severity="CRITICAL"
elif grep -q '^\[MAJOR\]'    "$ISSUES"; then top_severity="MAJOR"
elif grep -q '^\[INFO\]'     "$ISSUES"; then top_severity="INFO"
else top_severity="OK"; fi
issues_count="$(grep -c '^\[' "$ISSUES" 2>/dev/null || echo 0)"

# ---------------------------------------------------------------------------
# 10) Rapport humain
# ---------------------------------------------------------------------------
{
  echo "NETSAVF PROBE REPORT"
  echo "===================="
  echo
  echo "Version : $VERSION"
  echo "Run id  : $RUN_ID"
  echo "Date    : $(date)"
  echo "SAVF source IBM i : $SAVF_LIB/$SAVF_NAME"
  echo "Copie IFS         : ${LOCAL_BYTES} octets (${LOCAL_MIB} MiB)"
  echo "Cible FTP         : $HOST ($MONITOR_MATCH):$PORT"
  echo "Chemin distant    : $REMOTE_DIR/$REMOTE_FILE"
  echo
  echo "Resume executif"
  echo "---------------"
  echo "Severite max          : $top_severity ($issues_count constat(s))"
  echo "Resultat FTP          : $ftp_result"
  echo "Statut commande FTP   : $ftp_status  (peu fiable : cf. log)"
  echo "Debit PRIMAIRE (mural): $wall_mbps Mbit/s  (temps=$wall_secs s, taille reelle)"
  echo "Debit FTP (phase-data): $ftp_mbps Mbit/s  (ligne='${transfer_line:-non trouvee}')"
  echo "Ping petit loss/avg   : ${small_loss}% / ${small_avg} ms"
  echo "Ping gros  loss/avg   : ${large_loss}% / ${large_avg} ms (DF=${df_large})"
  echo "Traceroute hops/to    : $tr_hops / $tr_timeouts"
  echo "PCAP retrans/lost/dup : ${retrans} / ${lostseg} / ${dupack}"
  echo
  echo "Constats detectes"
  echo "-----------------"
  cat "$ISSUES"
  echo
  echo "Analyse du PCAP (capture NON filtree)"
  echo "-------------------------------------"
  echo "Fenetre de capture : ${trace_win_start:-?} -> ${trace_win_stop:-?}"
  echo "Distant : $MONITOR_MATCH   Port controle : $PORT   Port data : $data_port"
  echo
  echo "Ouvrir $PCAP dans Wireshark et appliquer :"
  echo "  ip.addr == $MONITOR_MATCH && tcp"
  if [ "$data_port" != "unknown" ]; then
    echo "  ip.addr == $MONITOR_MATCH && tcp.port == $data_port     (canal DATA seul)"
  fi
  echo "  ... && (tcp.analysis.retransmission || tcp.analysis.lost_segment || tcp.analysis.duplicate_ack)"
  echo "Au besoin, borner par temps : frame.time >= \"${trace_win_start:-...}\""
  echo "NB : capture globale -> contient du trafic tiers. Fichier sensible, a purger apres analyse."
  echo
  echo "Artefacts"
  echo "---------"
  echo "Rapport            : $REPORT"
  echo "Resume machine     : $SUMMARY_JSON"
  echo "Log FTP (redige)   : $FTPOUT"
  echo "Entree FTP (redige): $FTPIN_SAFE"
  echo "Log CL             : $CLLOG"
  echo "Ping petit / gros  : $PING_SMALL / $PING_LARGE"
  echo "Traceroute         : $TRACEROUTE_OUT"
  echo "Routes / conns     : $NETSTAT_ROUTES / $NETSTAT_CONNS"
  echo "PCAP TRCCNN        : $PCAP"
  echo "Analyse PCAP auto  : $PCAP_ANALYSIS"
  echo
  echo "Guide d'interpretation"
  echo "----------------------"
  echo "- 530/auth   : compte, mot de passe, user desactive, politique FTP distante."
  echo "- 550/chemin : autorite ou chemin distant errone."
  echo "- 425/426    : canal data FTP a travers firewall/NAT (tester active/passive)."
  echo "- refused    : listener distant down ou firewall rejette le port $PORT."
  echo "- timeout/no route/unreachable : routage, drop firewall, hote down, ACL."
  echo "- petit ping OK + gros ping KO (DF actif) : MTU/fragmentation/VPN/inspection."
  echo "- Le PCAP est la preuve locale la plus forte : filtrer comme indique ci-dessus."
  echo
  echo "Limites"
  echo "-------"
  echo "- Vue cote IBM i uniquement. Pour prouver ou les paquets se perdent, capturer"
  echo "  aussi cote distant/firewall et comparer les horodatages."
  echo "- FTP en clair : ne pas transporter de secrets de production sur lien non fiable."
  echo "- Capture TRCCNN non filtree (TCPDTA absent) : bruit + donnees tierces sensibles."
} > "$REPORT"

# ---------------------------------------------------------------------------
# 11) Resume machine-lisible (JSON)
# ---------------------------------------------------------------------------
{
  printf '{\n'
  printf '  "run_id": %s,\n'          "$(jstr "$RUN_ID")"
  printf '  "host": %s,\n'            "$(jstr "$HOST")"
  printf '  "remote_ip": %s,\n'       "$(jstr "$MONITOR_MATCH")"
  printf '  "port": %s,\n'            "$(jnum "$PORT")"
  printf '  "remote_path": %s,\n'     "$(jstr "$REMOTE_DIR/$REMOTE_FILE")"
  printf '  "savf": %s,\n'            "$(jstr "$SAVF_LIB/$SAVF_NAME")"
  printf '  "bytes": %s,\n'           "$(jnum "$LOCAL_BYTES")"
  printf '  "mib": %s,\n'             "$(jnum "$LOCAL_MIB")"
  printf '  "ftp_result": %s,\n'      "$(jstr "$ftp_result")"
  printf '  "ftp_status": %s,\n'      "$(jstr "$ftp_status")"
  printf '  "wall_secs": %s,\n'       "$(jnum "$wall_secs")"
  printf '  "wall_mbps": %s,\n'       "$(jnum "$wall_mbps")"
  printf '  "ftp_mbps": %s,\n'        "$(jnum "$ftp_mbps")"
  printf '  "ping_small_loss_pct": %s,\n' "$(jnum "$small_loss")"
  printf '  "ping_large_loss_pct": %s,\n' "$(jnum "$large_loss")"
  printf '  "ping_small_avg_ms": %s,\n'   "$(jnum "$small_avg")"
  printf '  "ping_large_avg_ms": %s,\n'   "$(jnum "$large_avg")"
  printf '  "df_used_large": %s,\n'   "$(jstr "$df_large")"
  printf '  "traceroute_hops": %s,\n' "$(jnum "$tr_hops")"
  printf '  "traceroute_timeouts": %s,\n' "$(jnum "$tr_timeouts")"
  printf '  "data_port": %s,\n'       "$(jnum "$data_port")"
  printf '  "pcap_retransmissions": %s,\n' "$(jnum "$retrans")"
  printf '  "pcap_lost_segments": %s,\n'   "$(jnum "$lostseg")"
  printf '  "pcap_duplicate_acks": %s,\n'  "$(jnum "$dupack")"
  printf '  "trace_window_start": %s,\n'   "$(jstr "${trace_win_start:-}")"
  printf '  "trace_window_stop": %s,\n'    "$(jstr "${trace_win_stop:-}")"
  printf '  "top_severity": %s,\n'    "$(jstr "$top_severity")"
  printf '  "issues_count": %s,\n'    "$(jnum "$issues_count")"
  printf '  "pcap_path": %s,\n'       "$(jstr "$PCAP")"
  printf '  "report_path": %s\n'      "$(jstr "$REPORT")"
  printf '}\n'
} > "$SUMMARY_JSON"

# ---------------------------------------------------------------------------
# 12) Nettoyage final
# ---------------------------------------------------------------------------
if [ "$KEEP_IFS_COPY" != "1" ]; then
  rm -f "$LOCAL_COPY"
else
  info_summary "Copie SAVF conservee : $LOCAL_COPY"
fi
rm -f "$ftp_errors_file"
[ -f "$PCAP" ] && chmod 600 "$PCAP" 2>/dev/null || true

echo
echo "Termine."
echo "Rapport   : $REPORT"
echo "JSON      : $SUMMARY_JSON"
echo "Artefacts : $WORK"
