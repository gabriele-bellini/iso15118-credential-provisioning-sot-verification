# ISO-15118 Credentials Lifecycle Formal Verification and Ownership Transfer

![Formally verified with ProVerif](https://img.shields.io/badge/ProVerif-2.05-005f73)

# Installation of ProVerif

We expect that ProVerif is installed according to the [official ProVerif installation guidelines](https://bblanche.gitlabpages.inria.fr/proverif/install.html), and the `proverif` binary is available.

> All this work is tested with results reported. Tests have been performed in Ubuntu 26.04.


## Formal verification

### Park-and-Charge (PnC) scenarios with Ownership transfer

| Scenario | TPM | Rekey | Revoke | Entropy |
|:---:|:---:|:---:|:---:|:---:|
| N1 | - | - | - | - |
| N2 | - | ✓ | ✓ | - |
| N3 | - | ✓ | - | - |
| N4 | - | ✓ | ✓ | - |
| T1 | ✓ | ✓ | ✓ | - |
| T2 | ✓ | ✓ | - | - |
| T3 | ✓ | - | - | low |
| T4 | ✓ | - | - | high |

N4 is the same as N2, until the EV is left unattended (e.g., servicing, etc)


| Scenario | TPM | Billing contract revocation |
|:---:|:---:|:---:|
| NK | - | - |
| NR | - | ✓ |
| TK | ✓ | - |
| TR | ✓ | ✓ |


```bash
(
  cd pnc_ownership_transfer_scenarios
  ../verify.sh [nr][rk]*.pv # Buyer protection
  ../verify.sh [nt][t_]*.pv # Seller protection
)
```

Results are expected to be:

```
N1:  Billing legitimated = ✘ - Contract-key secrecy = ✘ - Signature forgery resistance = ✘.
T4:  Billing legitimated = ✔ - Contract-key secrecy = ✔ - Signature forgery resistance = ✔.
T3:  Billing legitimated = ✔ - Contract-key secrecy = ✔ - Signature forgery resistance = ✘.
N3:  Billing legitimated = ✘ - Contract-key secrecy = ✘ - Signature forgery resistance = ✘.
N2:  Billing legitimated = ✔ - Contract-key secrecy = ✔ - Signature forgery resistance = ✔.
N4:  Billing legitimated = ✘ - Contract-key secrecy = ✘ - Signature forgery resistance = ✘.
T2:  Billing legitimated = ✔ - Contract-key secrecy = ✔ - Signature forgery resistance = ✔.
T1:  Billing legitimated = ✔ - Contract-key secrecy = ✔ - Signature forgery resistance = ✔.

NK:  Seller protection = ✘ - Billing legitimated = ✔.
NR:  Seller protection = ✔ - Billing legitimated = ✔.
TK:  Seller protection = ✘ - Billing legitimated = ✔.
TR:  Seller protection = ✔ - Billing legitimated = ✔.
```

#### Buyer protection notes
Generally, the TPM gives more security as expected.
In N2, we have signature forgery resistance after rekeying as expected, but N4 shows that they can be stolen again and the attack raises back.

If low-entropy material gets signed, the attck to the TPM used as a signing oracle emerges.

> **Note** This attack is *not* preventable; every revision of the ISO-15118 shall consider this attack all the time, and avoid any low-entropy data signed.


#### Seller protection notes

Billing is always legitimated, as the EV is always techincally legitimated to perform operations, regardless of ownership.

### ISO Install certification protocol

```bash
(
  cd iso_certificate_install_verification
  ../verify.sh *.pv
)
```

Results are expected to be:

```
EV-Certificate-Install-Protocol:  Secrecy = ✔ - Correctness = ✔ - eMSP Authentication of EV = ✘ - EV Authentication of eMSP = ✔.
```

The protocol does not meet eMSP Authentication of EV.

### Credentials provisioning

```bash
(
  cd credential_provisioning
  ../verify.sh dh-[fb]*.pv
  ../verify.sh dh-var-[fb]*.pv
)
```

Results are expected to be:

```
(e2,s2)-backward-secrecy-leak-sA-sB:  Forward/Backward privacy = ━.
(e2,s2)-backward-secrecy-leak-sA:  Forward/Backward privacy = ✔.
(e2,s2)-backward-secrecy-leak-sB:  Forward/Backward privacy = ━.
(e2,s2)-forward-secrecy-leak-sA-sB:  Forward/Backward privacy = ━.
(e2,s2)-forward-secrecy-leak-sA:  Forward/Backward privacy = ━.
(e2,s2)-forward-secrecy-leak-sB:  Forward/Backward privacy = ━.

(e2,s2)-variant-backward-secrecy-leak-sA-sB:  Forward/Backward privacy = ✔.
(e2,s2)-variant-backward-secrecy-leak-sA:  Forward/Backward privacy = ✔.
(e2,s2)-variant-backward-secrecy-leak-sB:  Forward/Backward privacy = ✔.
(e2,s2)-variant-forward-secrecy-leak-sA-sB:  Forward/Backward privacy = ✔.
(e2,s2)-variant-forward-secrecy-leak-sA:  Forward/Backward privacy = ✔.
(e2,s2)-variant-forward-secrecy-leak-sB:  Forward/Backward privacy = ✔.
```

Our solution is provably providing strong forward/backward privacy in every case of key leakage.

#### TPM as a signature oracle

```bash
(
  cd credential_provisioning
  ../verify.sh *e2s2-tpm*.pv
  ../verify.sh *e2s2-var-tpm*.pv
)
```

Results are expected to be:

```
(e2,s2)-tpm-oracle:  Impersonation Resistance = ✘ - Forward privacy = ✔ - Unilateral compromise security = ✘ - Partial post-compromise security = ✔ - Mutual compromise security = ✘ - Backward privacy = ✔.

(e2,s2)-variant-tpm-oracle:  Impersonation Resistance = ✔ - Forward privacy = ✔ - Unilateral compromise security = ✔ - Partial post-compromise security = ✔ - Mutual compromise security = ✔ - Backward privacy = ✔.
```

If we naively proposed the NIST (e2,s2) protocol as TLS implements it, we could not have some properties.
The results show that our variant is more appropriate for the ownership transfer scenario under study, where we can protect from Impersonation and other similar attacks.

### Rekeying

```bash
(
  cd proposed_ownership_transfer_protocol
  ../verify.sh *.pv
)
```

Results are expected to be:

```
Rekeying:  Seller Key Secrecy = ✔ - EV Key Secrecy = ✔ - Buyer Key Secrecy = ✔ - OEM Key Secrecy = ✔ - Buyer Completion Integrity = ✔ - Seller Completion Integrity = ✔ - OEM Completion Integrity = ✔ - EV Completion Integrity = ✔ - Buyer-OEM Ordering = ✔ - Seller-OEM Ordering = ✔ - OEM-EV Ordering = ✔ - Buyer-EV Ordering = ✔ - Seller-EV Ordering = ✔ - Seller Authentication of OEM = ✔ - Buyer Authentication of OEM = ✔ - OEM Authentication of Buyer = ✔ - OEM Authentication of Seller = ✔ - EV Authentication of OEM = ✔ - OEM Authentication of EV = ✔ - Scam Vehicle Sale Prevention = ✔ - Scam Vehicle Purchase Prevention = ✔ - Unowned Vehicle Sale Prevention = ✔ - Invalid Vehicle Purchase Prevention = ✔ - Seller Impersonation Prevention = ✔ - Buyer Impersonation Prevention = ✔ - Rogue OEM Transaction Start Prevention = ✔ - Rogue OEM Transaction Completion Prevention = ✔ - Honest Buyer Transaction Reachability = ✘ - Honest Seller Transaction Reachability = ✘ - Honest OEM Transaction Reachability = ✘ - Honest EV Rekey Reachability = ✘ - Buyer Double Transaction Prevention = ✘.
```

Double transaction from the buyers is not prevented but it deos not cause any damage or desync with the OEM.
