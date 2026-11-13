# P25 Roaming Registration — Design

Date: 2026-11-13
Branch: `dev/roaming`
Scope: sub-project 1 (LOC_REG_RSP Site ID fix) and sub-project 2 (roaming unit
registration and WUID management) of the P25 roaming effort.

## 1. Background

A P25 subscriber unit (SU) is uniquely identified by its SUID: WACN ID, System ID,
and 24-bit Unit ID. A roaming SU registers using its Home System identity
(TIA-102.AABC-D §2.3.18; TIA-102.AABD-B §6.4.1). The registering RFSS validates
the SU and allocates a locally significant Working Unit ID (WUID). A Home SU uses
its Unit ID as its WUID; a foreign SU (different WACN ID and/or System ID) "shall"
receive a WUID from an operator-controlled pool of IDs that cannot be Home Unit IDs
(AABD §6.2). Foreign WUIDs are recovered through de-registration or the WUID
validity timer (AABD §6.6).

The U_REG_RSP carries the SU's SUID (System ID + Source ID) and the assigned WUID
(Source Address). The abbreviated TSBK format applies only when the SU's WACN ID
matches the site's; otherwise the extended alternate multi-block format is required
(AABC §6.2.21).

### Current dvmhost behavior

- `ControlSignaling::writeRF_TSDU_U_Reg_Rsp()` denies any U_REG_REQ whose System
  ID differs from the site's, using REG_DENY. REG_DENY means "not allowed at this
  location" and drives the SU into control channel hunting (AABD §5.4.4(c),
  §5.4.5(c), §6.4.1.1). REG_REFUSED is the code for "not allowed on this system";
  see §4 for why roaming admission failures nevertheless keep REG_DENY.
- The WACN ID in U_REG_REQ is decoded but never checked.
- `IOSP_U_REG::encode()` always writes the site System ID, and the WUID always
  equals the Unit ID. No WUID pool or SUID-to-WUID mapping exists.
- `OSP_LOC_REG_RSP::encode()` writes `sysId()` into the 8-bit Site ID field
  (AABC §6.2.23, Figure 6.2.23-1).

### Sub-project map (for context; only 1 and 2 are in scope)

1. LOC_REG_RSP Site ID fix.
2. Roaming unit registration and WUID management (host).
3. Host RF/network identity translation (WUID ↔ SUID) for voice, data, grants.
4. FNE SUID-aware registration, ACL, routing, and operation store.
5. Roaming group affiliation (foreign SGID/WGID handling, AABD §6.7).
6. Adjacent site table keyed by System ID + RFSS ID + Site ID.

## 2. Sub-project 1 — LOC_REG_RSP Site ID

- `src/common/p25/lc/tsbk/OSP_LOC_REG_RSP.cpp`: write `s_siteData.siteId()` into
  the Site ID field instead of `s_siteData.sysId()`.
- Verify the remaining shifts against Figure 6.2.23-1: octet 2 holds 6 reserved
  bits and RV in bits 1–0; octets 3–4 Group Address; octet 5 RFSS ID; octet 6 Site
  ID; octets 7–9 Target Address.
- Test: Catch2 known-answer case in `tests/p25/`, tags `[p25][tsbk]`, using site
  data with distinct RFSS ID, Site ID, and System ID values. Expected octets 2–9 are
  derived by hand from Figure 6.2.23-1, not from a round trip.
- Delivered as a separate commit before sub-project 2.

## 3. Sub-project 2 — Components

### 3.1 `p25::lookups::P25WuidLookup` (new)

Location: `src/host/p25/lookups/P25WuidLookup.h/.cpp`.

- Holds the inclusive WUID pool range and bidirectional SUID ↔ WUID maps.
- Nested, fully documented `SUID` structure: `netId` (20-bit WACN ID), `sysId`
  (12-bit System ID), `unitId` (24-bit Unit ID).
- API:
  - `allocate(const SUID&)` — returns the existing WUID for a re-registering SUID;
    otherwise the lowest free pool WUID; `0` when the pool is exhausted.
  - `release(uint32_t wuid)` — frees a pool WUID; unknown WUIDs are ignored.
  - `findBySuid(const SUID&)`, `findByWuid(uint32_t)` — lookups in each direction.
  - `isPoolWuid(uint32_t)` — range test used by every service path to identify a
    roaming unit.
- Mutex-protected; REST and network callbacks run on other threads.
- No protocol or RF dependencies; unit-tested directly.

### 3.2 U_REG_RSP codec

- `IOSP_U_REG::encode()` writes the TSBK's `m_sysId` into the System ID field
  instead of `s_siteData.sysId()`. Source ID remains `m_dstId` (SU Unit ID); Source
  Address remains `m_srcId` (WUID). For a Home SU the caller sets System ID = site
  System ID and WUID = Unit ID, so encoded bytes are unchanged.
- New `MBT_OSP_U_REG_RSP` (alternate multi-block, AABC §6.2.21.2, Figure 6.2.21-2):
  header carries Source Address (WUID) and the WACN ID upper bits; the data block
  carries WACN ID lower bits, System ID, Source ID, and RV. Included from
  `TSBKFactory.h` with the other MBT headers; no factory decode case is added
  because the host never receives this outbound message. In this scope it is only
  used to deny SUs with a different WACN ID.
- The Source Address for a denied response with no WUID is `$000000` ("No one",
  TIA-102.BAAC-C).

### 3.3 Registration logic (`ControlSignaling`)

`writeRF_TSDU_U_Reg_Rsp(uint32_t srcId, uint32_t sysId)` becomes
`writeRF_TSDU_U_Reg_Rsp(const lookups::P25WuidLookup::SUID& suid)`, taking the
requesting SUID. It classifies the request, allocates a WUID when required, and
selects the response code and format (§4).

The ISP_AUTH_RESP success path continues to produce a Home SU response; roaming SUs
never receive AUTH_DMD (§4).

### 3.4 Configuration (`p25::Control`)

Loads and validates `allowRoaming`, `roamingSysIds`, `roamingWuidStart`, and
`roamingWuidEnd` (§6), and owns the `P25WuidLookup` instance beside
`m_affiliations`.

## 4. Registration flow

The ACK_RSP_FNE behavior is unchanged. All checks complete before any registration,
affiliation, or WUID state is mutated.

1. **Different WACN ID** — extended-format U_REG_RSP (`MBT_OSP_U_REG_RSP`) with
   REG_DENY.
2. **Same System ID (Home SU)** — existing path: RID ACL, `requireLLAForReg`, and
   automatic inhibit; WUID = Unit ID. Addition: a Home Unit ID inside the roaming
   pool is answered with REG_REFUSED and a logged configuration-conflict reason
   (pool IDs cannot be Home Unit IDs, AABD §6.2).
3. **Different System ID, same WACN ID (roaming SU)**:
   1. `allowRoaming` false → REG_DENY. This preserves the current response.
   2. `roamingSysIds` non-empty and not containing the System ID → REG_DENY.
   3. `requireLLAForReg` is not evaluated for roaming SUs. No AUTH_DMD is sent.
   4. The RID ACL is not evaluated and automatic inhibit is never applied to
      roaming SUs; the Unit ID belongs to another system's numbering space.
   5. `allocate(suid)` returns 0 (pool exhausted) → REG_DENY, allowing the SU to
      try another site.
   6. Otherwise → REG_ACCEPT. Record with `m_affiliations->unitReg(wuid)` (starts
      the existing WUID validity timer and satisfies `verifyReg`). Do not announce
      the registration to the network. The response carries the Home System ID,
      the Unit ID as Source ID, and the WUID as Source Address.
4. **Re-registration** of the same SUID returns the same WUID and restarts its
   timer.

### Deny versus refuse

Strictly, an SU whose home system may not register on this system is a REG_REFUSED
case (AABD §6.4.1.1 d). However, an SU receiving REG_REFUSED "may go to the 'Invalid
ID' state and discontinue further registration attempts" and "shall await further
user input" (AABD §6.4.1.2 e), while REG_DENY makes the SU record the site as denied
and return to control channel hunting (AABD §6.4.1.2 b), eventually reaching its home
system without user action. Because only SUs already provisioned to accept this
WACN/System ID ever register here (AABD §5.4.5), a refused SU could be left on a
system that will not serve it. To avoid stranding public-safety SUs, every roaming
admission failure (foreign WACN, roaming disabled, System ID not permitted, pool
exhausted) uses REG_DENY. REG_REFUSED is used only for a Home SU whose Unit ID lies in
the roaming pool, which is a local provisioning error.

Each outcome logs the WACN ID, System ID, Unit ID, assigned WUID (when present), and
reason. Activity log entries extend the existing "unit registration request from
%u" vocabulary with the SUID.

The emergency ("E") bit continues to be handled as it is today.

## 5. Roaming SU services before sub-project 3

A roaming SU is identified by `isPoolWuid(srcId)`, checked before any grant,
affiliation, or network state changes.

| Request | Behavior |
| --- | --- |
| GRP_AFF_REQ | Processed with local talkgroup validation and recorded locally; network affiliation announcement suppressed. The group's Home System ID is logged and otherwise ignored (sub-project 5). |
| LOC_REG_REQ | Processed as today; restarts the WUID validity timer (AABD §6.6.1). |
| U_DE_REG_REQ | Acknowledged; WUID released; network de-registration announcement suppressed. |
| Group voice, unit-to-unit voice, unit-to-unit answer, telephone interconnect | DENY_RSP, `DENY_SYS_UNSUPPORTED_SVC`. |
| Data channel / SNDCP requests | DENY_RSP, `DENY_SYS_UNSUPPORTED_SVC`. |
| Status update, message update, call alert, extended function | DENY_RSP, `DENY_SYS_UNSUPPORTED_SVC`. |
| Emergency alarm | Acknowledged normally; logged as a warning and activity-log entry with SUID, WUID, and site. Not forwarded to the network until sub-project 3. |
| ACK, status query, group affiliation query, authentication, and radio monitor responses | Ignored (logged at verbose). |

GRP_AFF_REQ, LOC_REG_REQ, and U_DE_REG_REQ from a roaming SU restart its WUID
validity timer.

Denials log the reason "roaming unit service not supported (requires roaming
translation)".

Defensive guard: RF voice and data paths do not write a pool `srcId` to the network.

A request carrying an unassigned pool WUID is answered with U_REG_CMD (AABD §6.6.1).
This check precedes the table above, so the ignored responses also receive U_REG_CMD
when sent from an unassigned WUID. Only U_REG_REQ bypasses the roaming service policy.

### WUID release

`P25AffiliationLookup` already invokes the unit de-registration callback for
U_DE_REG_REQ, WUID validity timer expiry, and REST-forced de-registration.
`p25::Control` handles that callback in the private `processUnitDereg()`: when
`isPoolWuid(srcId)`, call `m_wuidLookup->release(srcId)` and suppress the network
de-registration announcement. The pool is in-memory only; a restart clears it and
roaming SUs re-register.

## 6. Configuration

New keys directly under `protocols.p25` of `configs/config.example.yml` (beside the
existing registration keys read via `p25Protocol[...]`), placed after
`requireLLAForReg`:

```yaml
        # Flag indicating whether SUs homed to other systems within this WACN may register here.
        #   Roaming SUs are assigned a WUID from the pool below. They are not LLA-authenticated,
        #   even when requireLLAForReg is enabled; admission relies on WACN and roamingSysIds.
        allowRoaming: false
        # Home System IDs permitted to roam here (hex strings). Empty permits any System ID in this WACN.
        roamingSysIds: []
        # Inclusive WUID pool assigned to roaming SUs (decimal). Must not overlap any home unit ID.
        roamingWuidStart: 0
        roamingWuidEnd: 0
```

Startup validation when `allowRoaming` is true:

- `0 < roamingWuidStart <= roamingWuidEnd`, and `roamingWuidEnd` below the reserved
  special WUID range (e.g. `WUID_FNE`).
- Each `roamingSysIds` entry is a valid 12-bit value and differs from the site
  System ID.
- Any validation error is logged and roaming is disabled; there is no permissive
  fallback.
- A warning is logged if the enabled RID ACL contains entries inside the pool.
- The startup banner logs the roaming configuration.

Planning must confirm whether `tools/dvmcfggen` templates this configuration block
and update it if so. `configs/schema` currently covers only talkgroup rules. The AI/
LLM notice in the example configuration is preserved.

## 7. Documentation

Add a roaming registration section to the dvmhost technical documentation covering:
the SUID/WUID model, admission order, interim service denials and emergency
handling, pool provisioning requirements, and the lack of LLA for roaming SUs.

## 8. Testing

- LOC_REG_RSP known-answer test (§2).
- U_REG_RSP abbreviated-format known-answer tests with Home System ID, Unit ID, and
  WUID; Home SU regression proving unchanged bytes.
- `MBT_OSP_U_REG_RSP` known-answer test for header and data block (Figure 6.2.21-2).
- `P25WuidLookup`: lowest-free allocation, re-registration idempotence, exhaustion,
  single-ID pool, release and reuse, unknown release, bidirectional lookup, and
  pool boundaries (start, end, start − 1, end + 1).
- Registration flow via `tests/p25/HostControl_Tests.cpp`: Home accept; Home Unit ID
  in pool refused; different WACN extended DENY; roaming disabled DENY; System ID
  not in list DENY; empty list accept; roaming accept with
  `requireLLAForReg` enabled and no AUTH_DMD; pool exhaustion DENY;
  re-registration retains WUID; de-registration and timer expiry release the WUID.
- Interim services: GRP_AFF accepted locally without network announcement; voice
  grant request denied with `DENY_SYS_UNSUPPORTED_SVC`; no pool WUID written to the
  network; emergency alarm acknowledged and logged but not forwarded; unassigned
  pool WUID triggers U_REG_CMD.

Verification: `cmake --build build -j2`, `./build/dvmtests '[p25]'`, then the full
suite. Over-the-air validation with a Motorola APX on a live control channel is
performed by the operator; it cannot be exercised from the development environment.

## 9. Out of scope

- WUID ↔ SUID translation on RF/network paths (sub-project 3).
- FNE SUID awareness, roaming SU ACL, and routing (sub-project 4).
- Foreign group (SGID/WGID) handling (sub-project 5).
- Adjacent site table key (sub-project 6).
- Accepting SUs from a different WACN.
- ROAM_ADDR_CMD roaming address stack procedures (AABD Annex E, informative).
- LLA for roaming SUs.
- Emergency registration procedures beyond current behavior (AABD §11.3.5).
