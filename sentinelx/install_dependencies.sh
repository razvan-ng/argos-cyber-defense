#!/usr/bin/env bash
#
# install_dependencies.sh — SentinelX Audit Suite (Argos Cyber Defense)
#
# Instal·la totes les eines i dependències necessàries per executar
# SentinelX a Ubuntu 24.04 LTS / 26.04 LTS (o derivats basats en Debian/Ubuntu).
#
# Disseny: el script MAI s'atura a la primera errada. Prova cada component
# de forma independent, en registra el resultat exacte i, al final, mostra
# un resum clar de què ha funcionat i què no —i per què—, amb un fitxer de
# log complet per a diagnòstic detallat.
#
# Ús:
#   chmod +x install_dependencies.sh
#   ./install_dependencies.sh
#
# Codi de sortida: 0 si tots els components OBLIGATORIS s'han instal·lat
# i verificat correctament; 1 si n'hi ha algun que ha fallat (es detalla al
# resum final quin i per què).

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
LOG_FILE="${SCRIPT_DIR}/install_dependencies.log"
: > "$LOG_FILE"

C_RESET="\033[0m"; C_RED="\033[1;31m"; C_GREEN="\033[1;32m"; C_YELLOW="\033[1;33m"; C_BLUE="\033[1;34m"; C_BOLD="\033[1m"

declare -A RESULTS
declare -A DETAILS

info()  { echo -e "${C_BLUE}[INFO]${C_RESET}  $1"; }
ok()    { echo -e "${C_GREEN}[ OK ]${C_RESET}  $1"; }
warn()  { echo -e "${C_YELLOW}[AVÍS]${C_RESET} $1"; }
fail()  { echo -e "${C_RED}[ERROR]${C_RESET} $1"; }

record() { RESULTS["$1"]="$2"; DETAILS["$1"]="$3"; }

# Executa una comanda, registra la sortida completa (stdout+stderr) al log
# amb capçalera identificativa, i retorna el codi de sortida real.
run_logged() {
    local desc="$1"; shift
    {
        echo ""
        echo "### ${desc} — $(date '+%Y-%m-%d %H:%M:%S')"
        echo "\$ $*"
    } >> "$LOG_FILE"
    "$@" >>"$LOG_FILE" 2>&1
    return $?
}

# Instal·la un paquet apt i el verifica amb una comanda de comprovació.
install_apt_package() {
    local step_name="$1" package="$2" verify_cmd="$3"
    info "Instal·lant '${package}'..."
    run_logged "install ${package}" $SUDO apt-get install -y "$package"
    local rc=$?
    if [[ $rc -ne 0 ]]; then
        fail "No s'ha pogut instal·lar '${package}' (apt-get ha retornat el codi ${rc})."
        record "$step_name" "FAIL" "'apt-get install -y ${package}' ha fallat (codi ${rc}). Detall exacte a ${LOG_FILE}."
        return 1
    fi
    if eval "$verify_cmd" >/dev/null 2>&1; then
        ok "'${package}' instal·lat i verificat correctament."
        record "$step_name" "OK" "Paquet: ${package}"
        return 0
    else
        fail "'${package}' s'ha instal·lat segons apt, però la verificació posterior ha fallat (${verify_cmd})."
        record "$step_name" "FAIL" "apt indica èxit, però '${verify_cmd}' no funciona. Revisa ${LOG_FILE}."
        return 1
    fi
}

echo -e "${C_BOLD}=== SentinelX Audit Suite — Instal·lador de Dependències (Ubuntu 24.04/26.04) ===${C_RESET}\n"

# ------------------------------------------------------------------ #
# 0. Comprovacions prèvies: privilegis, distribució, apt
# ------------------------------------------------------------------ #
if [[ "$(id -u)" -ne 0 ]]; then
    if ! command -v sudo >/dev/null 2>&1; then
        fail "No s'executa com a root i 'sudo' no està disponible al sistema."
        fail "Solució: executa aquest script com a root, o instal·la sudo i afegeix el teu usuari al grup 'sudo'."
        exit 1
    fi
    if ! sudo -v; then
        fail "No s'han pogut obtenir privilegis d'administrador (contrasenya sudo incorrecta o usuari sense permisos sudo)."
        exit 1
    fi
    SUDO="sudo"
else
    SUDO=""
fi

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    info "Sistema detectat: ${PRETTY_NAME:-desconegut}"
    if [[ "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *debian* ]]; then
        warn "Aquest script està pensat per a Ubuntu 24.04/26.04. S'ha detectat '${ID:-desconegut}';"
        warn "es continuarà de totes maneres, però algunes comandes podrien no funcionar igual."
    fi
else
    warn "No s'ha pogut llegir /etc/os-release; no es pot confirmar la distribució del sistema."
fi

if ! command -v apt-get >/dev/null 2>&1; then
    fail "No s'ha trobat 'apt-get'. Aquest script requereix un sistema basat en Debian/Ubuntu."
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

info "Actualitzant la llista de paquets (apt-get update)..."
if run_logged "apt-get update" $SUDO apt-get update -y; then
    ok "Llista de paquets actualitzada."
else
    warn "'apt-get update' no ha acabat correctament (revisa la connexió a Internet o els repositoris configurats)."
    warn "Es continuarà igualment: alguns paquets ja poden estar disponibles en local."
fi

# ------------------------------------------------------------------ #
# 1. Eines obligatòries de xarxa i sistema
# ------------------------------------------------------------------ #
echo -e "\n${C_BOLD}--- Eines de xarxa i sistema (obligatòries) ---${C_RESET}\n"

install_apt_package "nmap"       "nmap"          "command -v nmap"
install_apt_package "traceroute" "traceroute"    "command -v traceroute"
install_apt_package "ping"       "iputils-ping"  "command -v ping"
install_apt_package "ss"         "iproute2"      "command -v ss"
install_apt_package "netstat"    "net-tools"     "command -v netstat"
install_apt_package "git"        "git"           "command -v git"

# ------------------------------------------------------------------ #
# 2. Python i tot el necessari per a la interfície gràfica
# ------------------------------------------------------------------ #
echo -e "\n${C_BOLD}--- Python 3, entorn virtual i interfície gràfica (obligatoris) ---${C_RESET}\n"

install_apt_package "python3"         "python3"          "command -v python3"
install_apt_package "python3-venv"    "python3-venv"     "dpkg -s python3-venv"
install_apt_package "python3-pip"     "python3-pip"      "dpkg -s python3-pip"
install_apt_package "python3-tk"      "python3-tk"       "python3 -c 'import tkinter'"
install_apt_package "python3-dev"     "python3-dev"      "dpkg -s python3-dev"
install_apt_package "build-essential" "build-essential"  "dpkg -s build-essential"

# ------------------------------------------------------------------ #
# 3. Eines opcionals: tallafocs (ufw) i cerca d'exploits (exploitdb)
# ------------------------------------------------------------------ #
echo -e "\n${C_BOLD}--- Eines opcionals (l'aplicació funciona igualment sense elles) ---${C_RESET}\n"

info "Instal·lant 'ufw' (comprovació del tallafocs, opcional)..."
run_logged "install ufw" $SUDO apt-get install -y ufw
if [[ $? -eq 0 ]] && command -v ufw >/dev/null 2>&1; then
    ok "'ufw' instal·lat correctament."
    record "ufw" "OK" ""
else
    warn "No s'ha pogut instal·lar 'ufw'. És opcional: només afecta la comprovació de tallafocs a la pestanya 'Sistema Local'."
    record "ufw" "AVIS" "Instal·lació opcional fallida. Detall a ${LOG_FILE}."
fi

info "Instal·lant 'exploitdb' / 'searchsploit' (cerca d'exploits coneguts, opcional)..."
EXPLOITDB_OK=0

run_logged "install exploitdb (intent 1: apt directe)" $SUDO apt-get install -y exploitdb
if [[ $? -eq 0 ]] && command -v searchsploit >/dev/null 2>&1; then
    EXPLOITDB_OK=1
fi

if [[ $EXPLOITDB_OK -eq 0 ]]; then
    warn "Intent 1 fallit (apt directe). Provant d'habilitar el repositori 'universe'..."
    if ! command -v add-apt-repository >/dev/null 2>&1; then
        run_logged "install software-properties-common" $SUDO apt-get install -y software-properties-common
    fi
    if command -v add-apt-repository >/dev/null 2>&1; then
        run_logged "add-apt-repository universe" $SUDO add-apt-repository -y universe
        run_logged "apt-get update (post-universe)" $SUDO apt-get update -y
        run_logged "install exploitdb (intent 2: universe)" $SUDO apt-get install -y exploitdb
        if [[ $? -eq 0 ]] && command -v searchsploit >/dev/null 2>&1; then
            EXPLOITDB_OK=1
        fi
    else
        warn "'add-apt-repository' no disponible; s'omet aquest intent."
    fi
fi

if [[ $EXPLOITDB_OK -eq 0 ]]; then
    warn "Intent 2 fallit (universe). Provant la instal·lació manual oficial via git..."
    if command -v git >/dev/null 2>&1; then
        if [[ ! -d /opt/exploitdb ]]; then
            run_logged "git clone exploitdb" $SUDO git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
        fi
        if [[ -d /opt/exploitdb ]]; then
            run_logged "symlink searchsploit" $SUDO ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
            if command -v searchsploit >/dev/null 2>&1; then
                EXPLOITDB_OK=1
            fi
        fi
    else
        fail "No es pot fer la instal·lació manual d'exploitdb perquè 'git' no està disponible."
    fi
fi

if [[ $EXPLOITDB_OK -eq 1 ]]; then
    ok "'searchsploit' (exploitdb) instal·lat i disponible."
    record "exploitdb" "OK" ""
else
    warn "No s'ha pogut instal·lar exploitdb/searchsploit per cap dels tres mètodes provats"
    warn "(apt directe, apt amb 'universe', instal·lació manual via git)."
    warn "És opcional: SentinelX funcionarà igualment; només s'ometrà la cerca d'exploits coneguts."
    record "exploitdb" "AVIS" "Cap dels 3 mètodes ha funcionat. Detall exacte de cada intent a ${LOG_FILE}."
fi

# ------------------------------------------------------------------ #
# 4. Entorn virtual de Python i dependències del projecte
# ------------------------------------------------------------------ #
echo -e "\n${C_BOLD}--- Entorn virtual de Python i dependències del projecte ---${C_RESET}\n"

if [[ -x "${VENV_DIR}/bin/python3" ]]; then
    info "Ja existeix un entorn virtual vàlid a ${VENV_DIR}; es reutilitzarà."
else
    if [[ -d "$VENV_DIR" ]]; then
        warn "S'ha trobat un entorn virtual incomplet a ${VENV_DIR}; es tornarà a crear des de zero."
        rm -rf "$VENV_DIR"
    fi
    info "Creant l'entorn virtual de Python a ${VENV_DIR}..."
    if ! run_logged "python3 -m venv" python3 -m venv "$VENV_DIR"; then
        fail "No s'ha pogut crear l'entorn virtual amb 'python3 -m venv'."
    fi
fi

VENV_PY="${VENV_DIR}/bin/python3"

if [[ -x "$VENV_PY" ]]; then
    record "venv" "OK" "Ubicació: ${VENV_DIR}"

    info "Actualitzant pip dins l'entorn virtual..."
    run_logged "pip upgrade" "$VENV_PY" -m pip install --upgrade pip

    REQ_FILE="${SCRIPT_DIR}/requirements.txt"
    if [[ -f "$REQ_FILE" ]]; then
        info "Instal·lant dependències de Python des de requirements.txt..."
        if run_logged "pip install -r requirements.txt" "$VENV_PY" -m pip install -r "$REQ_FILE"; then
            ok "Totes les dependències de Python s'han instal·lat correctament."
            record "pip-requirements" "OK" "Font: ${REQ_FILE}"
        else
            fail "La instal·lació de dependències de Python (requirements.txt) ha fallat."
            record "pip-requirements" "FAIL" "Vegeu ${LOG_FILE} per l'error exacte de pip (paquet i motiu concrets)."
        fi
    else
        warn "No s'ha trobat 'requirements.txt' a ${SCRIPT_DIR}; s'instal·larà la llista bàsica de paquets."
        if run_logged "pip install (llista de reserva)" "$VENV_PY" -m pip install \
            "customtkinter>=5.2.2" "psutil>=5.9.8" "requests>=2.31.0" "reportlab>=4.0.9" "pyinstaller>=6.3.0"; then
            ok "Dependències de Python instal·lades correctament (llista de reserva)."
            record "pip-requirements" "OK" "Font: llista de reserva (sense requirements.txt)"
        else
            fail "La instal·lació de dependències de Python (llista de reserva) ha fallat."
            record "pip-requirements" "FAIL" "Vegeu ${LOG_FILE}."
        fi
    fi

    info "Verificant que Tkinter i CustomTkinter es carreguen correctament dins l'entorn virtual..."
    if run_logged "verify tkinter+customtkinter" "$VENV_PY" -c "import tkinter, customtkinter"; then
        ok "La interfície gràfica (Tkinter + CustomTkinter) es carrega correctament."
        record "gui-check" "OK" ""
    else
        fail "No s'ha pogut carregar Tkinter/CustomTkinter dins l'entorn virtual."
        record "gui-check" "FAIL" "Sol indicar que falta 'python3-tk' al sistema o que customtkinter no s'ha instal·lat. Detall a ${LOG_FILE}."
    fi
else
    fail "L'entorn virtual no s'ha pogut crear; no es poden instal·lar ni verificar les dependències de Python."
    record "venv" "FAIL" "'${VENV_DIR}/bin/python3' no existeix. Revisa que 'python3-venv' s'hagi instal·lat correctament."
    record "pip-requirements" "FAIL" "Depèn de l'entorn virtual, que no s'ha pogut crear."
    record "gui-check" "FAIL" "Depèn de l'entorn virtual, que no s'ha pogut crear."
fi

# ------------------------------------------------------------------ #
# 5. Resum final
# ------------------------------------------------------------------ #
echo -e "\n${C_BOLD}=== Resum de la instal·lació ===${C_RESET}\n"

REQUIRED_STEPS=(nmap traceroute ping ss netstat git python3 python3-venv python3-pip python3-tk python3-dev build-essential venv pip-requirements gui-check)
OPTIONAL_STEPS=(ufw exploitdb)

any_required_failed=0

printf "%-20s %-10s %s\n" "COMPONENT" "ESTAT" "DETALL"
printf '%.0s-' {1..100}; echo

for step in "${REQUIRED_STEPS[@]}"; do
    status="${RESULTS[$step]:-DESCONEGUT}"
    detail="${DETAILS[$step]:-}"
    color="$C_YELLOW"
    if [[ "$status" == "OK" ]]; then
        color="$C_GREEN"
    elif [[ "$status" == "FAIL" ]]; then
        color="$C_RED"
        any_required_failed=1
    fi
    printf "%-20s ${color}%-10s${C_RESET} %s\n" "$step" "$status" "$detail"
done

echo -e "\n--- Components opcionals ---\n"
for step in "${OPTIONAL_STEPS[@]}"; do
    status="${RESULTS[$step]:-DESCONEGUT}"
    detail="${DETAILS[$step]:-}"
    color="$C_YELLOW"
    [[ "$status" == "OK" ]] && color="$C_GREEN"
    printf "%-20s ${color}%-10s${C_RESET} %s\n" "$step" "$status" "$detail"
done

echo -e "\nLog complet i detallat de totes les comandes executades:\n  ${LOG_FILE}\n"

if [[ $any_required_failed -eq 1 ]]; then
    fail "La instal·lació NO s'ha completat correctament. Hi ha components OBLIGATORIS marcats com a FAIL."
    fail "Per a cada un, la columna DETALL indica exactament què ha fallat; el fitxer de log conté"
    fail "la sortida completa de la comanda concreta que ha donat error."
    exit 1
else
    ok "Tots els components obligatoris s'han instal·lat i verificat correctament."
    echo -e "\nPer executar SentinelX Audit Suite:\n"
    echo -e "  source \"${VENV_DIR}/bin/activate\""
    echo -e "  python main.py\n"
    exit 0
fi
