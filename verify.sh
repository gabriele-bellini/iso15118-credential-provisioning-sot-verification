#!/usr/bin/env bash
#
# verify-all.sh -- run the ISO 15118 PnC ProVerif models, log each run, and
# collect a one-line per-file verdict summary.
#
#   Usage:
#     ./verify-all.sh [file1.pv file2.pv ...]
#
#   With no arguments it processes every *.pv in the current directory (the
#   shared library *.pvl is not matched by *.pv, so it is skipped).
#
#   For each <name>.pv it
#     * runs ProVerif -- standalone, or with the shared library -- using -graph,
#     * writes combined stdout+stderr to <name>.log,
#     * prints and appends to ./verification_results.txt a line such as
#         <name>. Billing auth = false - Contract-key secrecy = false - Signature forgery resistance = false.
#
#   The verdict shown is ProVerif's own (true / false / cannot be proved); with
#   ProVerif's safety-property convention "true" means the property holds.
#
#   Run command reproduced from your setup:
#     standalone : proverif -graph analysis-<name>                       <name>.pv
#     with lib   : proverif -graph analysis-<name> -lib <LIB>            <name>.pv

set -u

SUMMARY="verification_results.txt" # collected one-line verdicts

# A .pv file is treated as dependent if it declares dependency in a comment
is_dependent() { grep -q 'Depends:' "$1"; }

# Map a ProVerif RESULT line to a human-readable property name.
# Each query carries one event that is unique to it.
prop_name() {
  q=""
  case "$1" in
    *OwnerInitiates*)        q="Seller protection" ;;
    *ContractKeyLeaked*)     q="Contract-key secrecy" ;;
    *VehicleAuthenticated*)  q="Signature forgery resistance" ;;
    *LegitAuthorize*)        q="Billing legitimated" ;;
    *Observational*)         q="Forward/Backward privacy" ;;
    *attacker_message*)      q="Impersonation Resistance" ;;
    *betweenUncompromised*)  q="Forward privacy" ;;
    *betweenCompromised*)    q="Mutual compromise security" ;;
    *fromCompromisedSk*)     q="Unilateral compromise security" ;;
    *toCompromisedSk*)       q="Partial post-compromise security" ;;
    *afterFullKeyRenewal*)   q="Backward privacy" ;;
    *attacker_scalar*)       q="Secrecy" ;;
    *dh_oper\(g,esk*)        q="Correctness" ;;
    *inj-event\(endB\(h1,h2,pkEV*)   q="eMSP Authentication of EV" ;;
    *inj-event\(endA\(h1,h2,skEV*)   q="EV Authentication of eMSP" ;;
    
    # =========================
    # Rekeying
    # =========================

    *secret\ sk_S*)            q="Seller Key Secrecy" ;;
    *secret\ ssk_EV_intended*) q="EV Key Secrecy" ;;
    *secret\ sk_B*)            q="Buyer Key Secrecy" ;;
    *secret\ sk_OEM*)          q="OEM Key Secrecy" ;;

    # Completion integrity
    *inj-event\(endB\(bought*inj-event\(beginB\(buy*)
        q="Buyer Completion Integrity" ;;

    *inj-event\(endS\(sold*inj-event\(beginS\(sell*)
        q="Seller Completion Integrity" ;;

    *inj-event\(endOEM*inj-event\(beginOEM*)
        q="OEM Completion Integrity" ;;

    *inj-event\(endEV*inj-event\(beginEV*)
        q="EV Completion Integrity" ;;

    # Ordering
    *inj-event\(endB\(bought*inj-event\(endOEM*)
        q="Buyer-OEM Ordering" ;;

    *inj-event\(endS\(sold*inj-event\(endOEM*)
        q="Seller-OEM Ordering" ;;

    *inj-event\(endOEM*inj-event\(endEV*)
        q="OEM-EV Ordering" ;;

    *inj-event\(endB\(bought*inj-event\(endEV*)
        q="Buyer-EV Ordering" ;;

    *inj-event\(endS\(sold*inj-event\(endEV*)
        q="Seller-EV Ordering" ;;

    # Authentication
    *inj-event\(endS\(sold*inj-event\(beginOEM*)
        q="Seller Authentication of OEM" ;;

    *inj-event\(endB\(bought*inj-event\(beginOEM*)
        q="Buyer Authentication of OEM" ;;

    *inj-event\(endOEM*inj-event\(beginB\(buy*)
        q="OEM Authentication of Buyer" ;;

    *inj-event\(endOEM*inj-event\(beginS\(sell*)
        q="OEM Authentication of Seller" ;;

    *inj-event\(endEV*inj-event\(beginOEM*)
        q="EV Authentication of OEM" ;;

    *inj-event\(endOEM*inj-event\(beginEV*)
        q="OEM Authentication of EV" ;;

    # Attack prevention
    *not\ event\(endS\(sold,S,B,scamPCID*)
        q="Scam Vehicle Sale Prevention" ;;

    *not\ event\(endB\(bought,B,S,scamPCID*)
        q="Scam Vehicle Purchase Prevention" ;;

    *not\ event\(endS\(sold,S,B,otherPCID*)
        q="Unowned Vehicle Sale Prevention" ;;

    *not\ event\(endB\(bought,B,S,otherPCID*)
        q="Invalid Vehicle Purchase Prevention" ;;

    *not\ event\(endS\(sold,otherS,B*)
        q="Seller Impersonation Prevention" ;;

    *not\ event\(endB\(bought,otherB,S*)
        q="Buyer Impersonation Prevention" ;;

    # Rogue OEM
    *not\ event\(beginOEM\(otherOEM*)
        q="Rogue OEM Transaction Start Prevention" ;;

    *not\ event\(endOEM\(otherOEM*)
        q="Rogue OEM Transaction Completion Prevention" ;;
    
    # Reachability (expected false)
    *not\ event\(endB\(bought\[\],B\[\],S\[\],intendedPCID*)
        q="Honest Buyer Transaction Reachability" ;;

    *not\ event\(endS\(sold\[\],S\[\],B\[\],intendedPCID*)
        q="Honest Seller Transaction Reachability" ;;

    *not\ event\(endOEM\(OEM\[\],S\[\],B\[\],intendedPCID*)
        q="Honest OEM Transaction Reachability" ;;

    *not\ event\(endEV\(intendedPCID\[\],OEM\[\]*)
        q="Honest EV Rekey Reachability" ;;
        
    # Specific vehicle abuse prevention
    *not\ event\(endS\(sold\[\],S\[\],B\[\],scamPCID*)
        q="Scam Vehicle Sale Prevention" ;;

    *not\ event\(endB\(bought\[\],B\[\],S\[\],scamPCID*)
        q="Scam Vehicle Purchase Prevention" ;;

    *not\ event\(endS\(sold\[\],S\[\],B\[\],otherPCID*)
        q="Unowned Vehicle Sale Prevention" ;;

    *not\ event\(endB\(bought\[\],B\[\],S\[\],otherPCID*)
        q="Invalid Vehicle Purchase Prevention" ;;

    *not\ event\(endS\(sold\[\],otherS\[\],B\[\],otherPCID*)
        q="Seller Impersonation Prevention" ;;

    *not\ event\(endB\(bought\[\],otherB\[\],S\[\],intendedPCID*)
        q="Buyer Impersonation Prevention" ;;

    # Race condition
    *endB\(bought*endB\(bought*N_B1*)
        q="Buyer Double Transaction Prevention" ;;
    *)  # fallback: keep the query text itself so nothing is lost
        local q="${1#RESULT }"
        q="${q% is true.}"; q="${q% is false.}"; q="${q% cannot be proved.}"
        q="${q% is true}";  q="${q% is false}"
      ;;
  esac
  echo "${q}"
}

# Extract the verdict from a `RESULT` line
# (order matters: check the no-"is" "cannot be proved" form before
# the true/false forms).
verdict() {
  case "$1" in
    *"cannot be proved"*)        echo -e "\033[33m━\033[0m" ;;
    *" is true."*|*" is true")   echo -e "\033[32m✔\033[0m" ;;
    *" is false."*|*" is false") echo -e "\033[31m✘\033[0m" ;;
    *)                           echo -e "\033[34m⯑\033[0m" ;;
  esac
}

# Initial checks
command -v proverif >/dev/null 2>&1 || { echo "error: 'proverif' not found in PATH" >&2; exit 1; }

if [ "$#" -gt 0 ]; then files=("$@"); else files=(*.pv); fi
[ -e "${files[0]:-}" ] || { echo "error: no .pv files found" >&2; exit 1; }

: > "$SUMMARY"

# Core of the script
for f in "${files[@]}"; do
  [ -f "$f" ] || { echo "skip: $f (not a file)" >&2; continue; }

  n="$(basename "${f%.*}")"             # basename without extension  (your %n)
  s="$(cat $f | grep Scenario | cut -d' ' -f 4)"             # scenario as in the comments
  log="$n.log"
  graph="analysis-$n"

  rm -rf "$graph"; mkdir -p "$graph"    # fresh graph dir (fixes the quoted-glob quirk)

  if is_dependent "$f"; then
    /usr/bin/time -f "time: %E\nmemory: %MKB" proverif -graph "$graph" -lib "$(grep "Depends:" "$f" | cut -d':' -f2)" "$f"  > "$log" 2>&1
  else
    /usr/bin/time -f "time: %E\nmemory: %MKB" proverif -graph "$graph" "$f"  > "$log" 2>&1
  fi

  # Build the verdict line from the RESULT lines, in query order,
  # de-duplicated by property name (guards against any repeated printing).
  line="$s "
  seen=" "
  while IFS= read -r r; do
    [ -z "$r" ] && continue
    name="$(prop_name "$r")"
    case "$seen" in *"::$name::"*) continue ;; esac
    seen="$seen::$name:: "
    line="$line $name = $(verdict "$r") -"
  done < <(grep '^RESULT' "$log" | grep -v '^RESULT (')
  line="${line% -}"

  # add the trailing period, or flag a missing-results run (likely a ProVerif error)
  if [ "$line" = "$n." ]; then
    line="$n. (no results -- see $log)"
  else
    line="$line."
  fi

  printf '%s\n' "$line" | tee -a "$SUMMARY"
done

# Extra info that depends on file names.
echo
echo "logs: <name>.log    graphs: analysis-<name>/    summary: $SUMMARY"
