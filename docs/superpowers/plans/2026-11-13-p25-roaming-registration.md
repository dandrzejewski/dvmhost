# P25 Roaming Registration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct the LOC_REG_RSP Site ID field and let dvmhost register P25 SUs homed to another System ID in the same WACN by assigning them WUIDs from an operator-configured pool, per TIA-102.AABD-B §6.2 and TIA-102.AABC-D §6.2.21.

**Architecture:** A new host lookup, `p25::lookups::P25WuidLookup`, owns the WUID pool and the SUID ↔ WUID maps. `ControlSignaling::writeRF_TSDU_U_Reg_Rsp()` classifies each U_REG_REQ (foreign WACN, home, roaming) and answers with the abbreviated `IOSP_U_REG` (now able to carry the SU's Home System ID) or the new extended `MBT_OSP_U_REG_RSP`. A single gate early in RF TSBK processing keeps roaming SUs local until host identity translation (sub-project 3) exists.

**Tech Stack:** C++ (project house style per `AGENTS.md`), CMake (globbed sources with `CONFIGURE_DEPENDS`), Catch2 (`build/dvmtests`), yaml-cpp-style `yaml::Node` configuration.

**Spec:** `docs/superpowers/specs/2026-11-13-p25-roaming-registration-design.md`

## Global Constraints

- Follow `AGENTS.md` in full: four-space indentation, function/namespace braces on the next line, class/control braces on the same line, `nullptr`, unsigned literal suffixes (`0U`, `0xFFU`), fixed-width integer types for protocol fields, `m_` member prefix.
- Every new/changed header declaration gets full Doxygen (`@brief`, `@param` per named parameter, `@returns` for non-void). Nested structures get `@brief`, `@ingroup`, and per-field docs. Non-nested classes get the `Class Declaration` banner.
- Implementation definitions use a short `/* ... */` comment above each definition, matching neighboring files.
- New files keep the SPDX line and project header block. Copyright line for new files: `Copyright (C) 2026 David Andrzejewski` (git author of this branch); do not modify existing copyright lines.
- Never log keys or secret material. Log reasons with WACN ID, System ID, Unit ID, and WUID where present.
- Configuration keys live directly under `protocols.p25` (read via `p25Protocol[...]` in `src/host/p25/Control.cpp:239`): `allowRoaming` (bool, default `false`), `roamingSysIds` (list of hex strings, default empty), `roamingWuidStart` (decimal, default `0`), `roamingWuidEnd` (decimal, default `0`).
- Roaming is fully inert unless `allowRoaming` is true and the pool validated: `P25WuidLookup::isPoolWuid()` returns `false` when no pool is configured.
- The "no unit" Source Address used when no WUID is assigned is `$000000` (TIA-102.BAAC-C, Standard Source and Destination ID Values, "No one").
- Response codes (`p25::defines::ResponseCode`): `ACCEPT = 0x00U`, `FAIL = 0x01U`, `DENY = 0x02U`, `REFUSED = 0x03U`.
- Every roaming admission failure (foreign WACN, roaming disabled, System ID not permitted, pool exhausted) answers REG_DENY so the SU returns to control channel hunting (AABD §6.4.1.2 b). REG_REFUSED is used only for a Home SU whose Unit ID lies in the roaming pool. Rationale: spec §4 "Deny versus refuse".
- Build: `cmake --build build -j2`. Tests: `./build/dvmtests '<tags>' --reporter compact`.
- Do not mass-format files. Preserve unrelated code.

## File Structure

| File | Responsibility |
| --- | --- |
| `src/common/p25/lc/tsbk/OSP_LOC_REG_RSP.cpp` (modify) | Write Site ID instead of System ID. |
| `src/common/p25/lc/tsbk/IOSP_U_REG.h/.cpp` (modify) | Response System ID from new `SUIDSysId` property (0 = site System ID). |
| `src/common/p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.h/.cpp` (create) | Extended-format U_REG_RSP encoder (AABC §6.2.21.2). |
| `src/common/p25/lc/tsbk/TSBKFactory.h` (modify) | Include the new MBT header with its siblings. |
| `src/host/p25/lookups/P25WuidLookup.h/.cpp` (create) | WUID pool, SUID ↔ WUID maps; no protocol knowledge. |
| `src/host/p25/Control.h/.cpp` (modify) | Own the lookup, load/validate roaming config, release WUIDs on de-registration. |
| `src/host/p25/packet/ControlSignaling.h/.cpp` (modify) | Registration classification; roaming service gate; network suppression. |
| `src/host/p25/packet/Voice.cpp`, `src/host/p25/packet/Data.cpp` (modify) | Defensive guard: never write a pool WUID to the network. |
| `tests/host/HostTestHooks.h/.cpp` (modify) | Test accessors for site data, roaming config, WUID lookup. |
| `tests/p25/TSBK_Registration_Tests.cpp` (create) | Known-answer codec tests. |
| `tests/p25/P25WuidLookup_Tests.cpp` (create) | Lookup unit tests. |
| `tests/p25/HostControl_Tests.cpp` (modify) | Registration flow and roaming gate tests. |
| `configs/config.example.yml` (modify) | New keys with comments. |
| `docs/P25 Roaming Registration.md` (create) | Operator/technical documentation. |

---

### Task 1: LOC_REG_RSP Site ID correction

**Files:**
- Modify: `src/common/p25/lc/tsbk/OSP_LOC_REG_RSP.cpp:53`
- Create: `tests/p25/TSBK_Registration_Tests.cpp`

**Interfaces:**
- Consumes: existing `OSP_LOC_REG_RSP`, `TSBK::setSiteData`, `SiteData(netId, sysId, rfssId, siteId, lra, channelId, channelNo, serviceClass, lto)`.
- Produces: test file `tests/p25/TSBK_Registration_Tests.cpp` with `TEST_CASE("TSBK registration responses", "[p25][tsbk][registration]")`, extended by Tasks 2 and 3.

Expected bytes derive from TIA-102.AABC-D Figure 6.2.23-1: octet 2 = 6 reserved bits + RV (bits 1–0); octets 3–4 Group Address; octet 5 RFSS ID; octet 6 Site ID; octets 7–9 Target Address. With RV = DENY (`%10`), group `$ABCD`, RFSS `$12`, Site `$34`, System ID `$2A5`, target `$0F4240`: octets 2–9 = `02 AB CD 12 34 0F 42 40`. The defect writes `$A5` (low byte of System ID) into octet 6.

- [ ] **Step 1: Write the failing test**

Create `tests/p25/TSBK_Registration_Tests.cpp`:

```cpp
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Test Suite
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "host/Defines.h"
#include "common/p25/lc/tsbk/OSP_LOC_REG_RSP.h"
#include "common/p25/lc/tsbk/IOSP_U_REG.h"
#include "common/p25/lc/tsbk/TSBKFactory.h"
#include "common/p25/data/DataHeader.h"
#include "common/p25/P25Defines.h"
#include "common/p25/SiteData.h"

using namespace p25;
using namespace p25::defines;
using namespace p25::lc;
using namespace p25::lc::tsbk;

#include <catch2/catch_test_macros.hpp>
#include <cstring>

TEST_CASE("TSBK registration responses", "[p25][tsbk][registration]") {
    // known-answer vectors are derived by hand from TIA-102.AABC-D figures, not from round trips
    const SiteData previousSiteData = TSBK::getSiteData();
    TSBK::setSiteData(SiteData(0xBB800U, 0x2A5U, 0x12U, 0x34U, 0x01U, 1U, 1U, 0x00U, 0));

    SECTION("LOC_REG_RSP_Known_Bytes_Figure_6_2_23_1") {
        OSP_LOC_REG_RSP osp;
        osp.setResponse(ResponseCode::DENY);
        osp.setDstId(0xABCDU);
        osp.setSrcId(0x0F4240U);

        uint8_t raw[P25_TSBK_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        osp.encode(raw, true, true);

        const uint8_t expected[8U] = { 0x02U, 0xABU, 0xCDU, 0x12U, 0x34U, 0x0FU, 0x42U, 0x40U };
        CHECK((raw[0U] & 0x3FU) == TSBKO::OSP_LOC_REG_RSP);
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("octet " << (i + 2U));
            CHECK(raw[i + 2U] == expected[i]);
        }
    }

    TSBK::setSiteData(previousSiteData);
}
```

If `TSBKO::OSP_LOC_REG_RSP` is not the constant name, find it with `grep -n "LOC_REG_RSP" src/common/p25/P25Defines.h` and use that exact name (opcode `%101011` = `0x2BU`).

- [ ] **Step 2: Build and run to verify it fails**

Run: `cmake --build build -j2 && ./build/dvmtests '[p25][tsbk][registration]' --reporter compact`
Expected: FAIL on `octet 6` (`0xA5 == 0x34`).

- [ ] **Step 3: Fix the encoder**

In `src/common/p25/lc/tsbk/OSP_LOC_REG_RSP.cpp`, replace:

```cpp
    tsbkValue = (tsbkValue << 8) + s_siteData.sysId();                              // Site ID
```

with:

```cpp
    tsbkValue = (tsbkValue << 8) + s_siteData.siteId();                             // Site ID
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cmake --build build -j2 && ./build/dvmtests '[p25][tsbk]' --reporter compact`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/common/p25/lc/tsbk/OSP_LOC_REG_RSP.cpp tests/p25/TSBK_Registration_Tests.cpp
git commit -m "correct LOC_REG_RSP to encode the Site ID instead of the System ID per TIA-102.AABC-D 6.2.23, add known-answer test;"
```

---

### Task 2: U_REG_RSP carries the SU's Home System ID

**Files:**
- Modify: `src/common/p25/lc/tsbk/IOSP_U_REG.h`, `src/common/p25/lc/tsbk/IOSP_U_REG.cpp`
- Test: `tests/p25/TSBK_Registration_Tests.cpp`

**Interfaces:**
- Produces: `IOSP_U_REG::setSUIDSysId(uint32_t)` / `getSUIDSysId()` (property `suidSysId`, default `0U`; `0U` means "use site System ID"). Encoding: System ID field ← `suidSysId` or site System ID; Source ID ← `m_dstId` (SU Unit ID); Source Address ← `m_srcId` (WUID).

Expected bytes (Figure 6.2.21-1: octet 2 = 2 reserved bits, RV bits 5–4, System ID b11–b8 bits 3–0; octet 3 System ID b7–b0; octets 4–6 Source ID; octets 7–9 Source Address):
- Roaming vector: RV = DENY, Home System ID `$2A5`, Source ID `$0F4240`, Source Address `$7A1200` → `22 A5 0F 42 40 7A 12 00`.
- Home regression: RV = ACCEPT, `suidSysId` unset, site System ID `$2A5` (from the test site data), Source ID = Source Address = `$0003E9` → `02 A5 00 03 E9 00 03 E9`.

- [ ] **Step 1: Write the failing tests**

Append inside the `TEST_CASE` in `tests/p25/TSBK_Registration_Tests.cpp` (before `TSBK::setSiteData(previousSiteData);`):

```cpp
    SECTION("U_REG_RSP_Abbreviated_Roaming_Known_Bytes_Figure_6_2_21_1") {
        IOSP_U_REG iosp;
        iosp.setResponse(ResponseCode::DENY);
        iosp.setSUIDSysId(0x2A5U);
        iosp.setDstId(0x0F4240U);                                                   // Source ID (SUID Unit ID)
        iosp.setSrcId(0x7A1200U);                                                   // Source Address (WUID)

        uint8_t raw[P25_TSBK_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        iosp.encode(raw, true, true);

        const uint8_t expected[8U] = { 0x22U, 0xA5U, 0x0FU, 0x42U, 0x40U, 0x7AU, 0x12U, 0x00U };
        CHECK((raw[0U] & 0x3FU) == TSBKO::IOSP_U_REG);
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("octet " << (i + 2U));
            CHECK(raw[i + 2U] == expected[i]);
        }
    }

    SECTION("U_REG_RSP_Abbreviated_Home_Unchanged") {
        IOSP_U_REG iosp;
        iosp.setResponse(ResponseCode::ACCEPT);
        iosp.setDstId(1001U);
        iosp.setSrcId(1001U);

        uint8_t raw[P25_TSBK_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        iosp.encode(raw, true, true);

        const uint8_t expected[8U] = { 0x02U, 0xA5U, 0x00U, 0x03U, 0xE9U, 0x00U, 0x03U, 0xE9U };
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("octet " << (i + 2U));
            CHECK(raw[i + 2U] == expected[i]);
        }
    }
```

- [ ] **Step 2: Build to verify it fails**

Run: `cmake --build build -j2`
Expected: compile error, `setSUIDSysId` is not a member of `IOSP_U_REG`.

- [ ] **Step 3: Add the property**

In `src/common/p25/lc/tsbk/IOSP_U_REG.h`, after the `toString` declaration and before `};`, add:

```cpp

            public:
                /**
                 * @brief SUID System ID echoed in a Unit Registration Response (12-bit).
                 *  A value of 0 encodes the site System ID (Home SU).
                 */
                DECLARE_PROPERTY(uint32_t, suidSysId, SUIDSysId);
```

In `src/common/p25/lc/tsbk/IOSP_U_REG.cpp`, change the constructor to:

```cpp
IOSP_U_REG::IOSP_U_REG() : TSBK(),
    m_suidSysId(0U)
{
    m_lco = TSBKO::IOSP_U_REG;
}
```

and in `encode()` replace:

```cpp
    tsbkValue = (tsbkValue << 12) + s_siteData.sysId();                             // System ID
```

with:

```cpp
    // the System ID is that of the SU's SUID (TIA-102.AABC-D 6.2.21.1); a Home SU uses the site System ID
    const uint32_t sysId = (m_suidSysId != 0U) ? m_suidSysId : s_siteData.sysId();
    tsbkValue = (tsbkValue << 12) + (sysId & 0xFFFU);                               // System ID
```

- [ ] **Step 4: Run tests**

Run: `cmake --build build -j2 && ./build/dvmtests '[p25][tsbk]' --reporter compact`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/common/p25/lc/tsbk/IOSP_U_REG.h src/common/p25/lc/tsbk/IOSP_U_REG.cpp tests/p25/TSBK_Registration_Tests.cpp
git commit -m "allow U_REG_RSP to carry the SU's home System ID per TIA-102.AABC-D 6.2.21.1, add known-answer tests;"
```

---

### Task 3: Extended-format U_REG_RSP (`MBT_OSP_U_REG_RSP`)

**Files:**
- Create: `src/common/p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.h`, `src/common/p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.cpp`
- Modify: `src/common/p25/lc/tsbk/TSBKFactory.h` (add include next to `MBT_OSP_NET_STS_BCAST.h`)
- Test: `tests/p25/TSBK_Registration_Tests.cpp`

**Interfaces:**
- Produces: `p25::lc::tsbk::MBT_OSP_U_REG_RSP : public AMBT` with `setSUIDNetId(uint32_t)`, `setSUIDSysId(uint32_t)`, and base `setSrcId` (Source Address), `setDstId` (Source ID), `setResponse` (RV), `setMFId`. `encodeMBT(data::DataHeader&, uint8_t*)` produces the alternate MBT. `decodeMBT` is an outbound-only stub returning `false`.

Expected (Figure 6.2.21-2): WACN `$12345`, System ID `$2A5`, Source ID `$0F4240`, Source Address `$000000`, RV = DENY:
- Header: LLId (Source Address) `0x000000`; AMBT opcode `0x2C`; field 8 = WACN b19–b12 = `0x12`; field 9 = WACN b11–b4 = `0x34`; blocks to follow `1`; format AMBT; SAP trunking control; outbound.
- Data block octets 0–7: `52 A5 0F 42 40 02 00 00` (octet 0 = WACN b3–b0 `5` << 4 | System ID b11–b8 `2`; octet 5 RV in bits 1–0).

- [ ] **Step 1: Write the failing test**

Add `#include "common/p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.h"` to the include block of `tests/p25/TSBK_Registration_Tests.cpp`, and append inside the `TEST_CASE`:

```cpp
    SECTION("U_REG_RSP_Extended_Known_Bytes_Figure_6_2_21_2") {
        MBT_OSP_U_REG_RSP osp;
        osp.setResponse(ResponseCode::DENY);
        osp.setSUIDNetId(0x12345U);
        osp.setSUIDSysId(0x2A5U);
        osp.setDstId(0x0F4240U);                                                    // Source ID (SUID Unit ID)
        osp.setSrcId(0x000000U);                                                    // Source Address ("No one")

        data::DataHeader header;
        uint8_t raw[P25_PDU_UNCONFIRMED_LENGTH_BYTES];
        ::memset(raw, 0x00U, sizeof(raw));
        osp.encodeMBT(header, raw);

        CHECK(header.getFormat() == PDUFormatType::AMBT);
        CHECK(header.getSAP() == PDUSAP::TRUNK_CTRL);
        CHECK(header.getOutbound());
        CHECK(header.getBlocksToFollow() == 1U);
        CHECK(header.getLLId() == 0x000000U);
        CHECK(header.getAMBTOpcode() == TSBKO::IOSP_U_REG);
        CHECK(header.getAMBTField8() == 0x12U);
        CHECK(header.getAMBTField9() == 0x34U);

        const uint8_t expected[8U] = { 0x52U, 0xA5U, 0x0FU, 0x42U, 0x40U, 0x02U, 0x00U, 0x00U };
        for (uint32_t i = 0U; i < 8U; i++) {
            INFO("data octet " << i);
            CHECK(raw[i] == expected[i]);
        }
    }
```

- [ ] **Step 2: Build to verify it fails**

Run: `cmake --build build -j2`
Expected: compile error, `MBT_OSP_U_REG_RSP.h` not found.

- [ ] **Step 3: Create the header**

`src/common/p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.h`:

```cpp
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Common Library
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
/**
 * @file MBT_OSP_U_REG_RSP.h
 * @ingroup p25_ambt
 * @file MBT_OSP_U_REG_RSP.cpp
 * @ingroup p25_ambt
 */
#if !defined(__P25_LC_TSBK__MBT_OSP_U_REG_RSP_H__)
#define  __P25_LC_TSBK__MBT_OSP_U_REG_RSP_H__

#include "common/Defines.h"
#include "common/p25/lc/AMBT.h"

namespace p25
{
    namespace lc
    {
        namespace tsbk
        {
            // ---------------------------------------------------------------------------
            //  Class Declaration
            // ---------------------------------------------------------------------------

            /**
             * @brief Implements U REG RSP - Unit Registration Response (Extended Format, TIA-102.AABC-D 6.2.21.2).
             *  Used when the WACN ID of the source unit does not match the WACN ID of the site.
             *  In this release it is only used to deny such SUs.
             * @ingroup p25_ambt
             */
            class DVM_COMMON_API MBT_OSP_U_REG_RSP : public AMBT {
            public:
                /**
                 * @brief Initializes a new instance of the MBT_OSP_U_REG_RSP class.
                 */
                MBT_OSP_U_REG_RSP();

                /**
                 * @brief Decode a alternate trunking signalling block.
                 *  This message is outbound-only; decoding is not supported.
                 * @param[in] dataHeader P25 PDU data header
                 * @param[in] blocks P25 PDU data blocks
                 * @returns bool Always false.
                 */
                bool decodeMBT(const data::DataHeader& dataHeader, const data::DataBlock* blocks) override;
                /**
                 * @brief Encode a alternate trunking signalling block.
                 * @param[out] dataHeader P25 PDU data header
                 * @param[out] pduUserData P25 PDU user data
                 */
                void encodeMBT(data::DataHeader& dataHeader, uint8_t* pduUserData) override;

                /**
                 * @brief Returns a string that represents the current AMBT.
                 * @param isp Flag indicating whether the string should describe the inbound form.
                 * @returns std::string String representation of the AMBT.
                 */
                std::string toString(bool isp = false) override;

            public:
                /**
                 * @brief SUID WACN ID of the registering SU (20-bit).
                 */
                DECLARE_PROPERTY(uint32_t, suidNetId, SUIDNetId);
                /**
                 * @brief SUID System ID of the registering SU (12-bit).
                 */
                DECLARE_PROPERTY(uint32_t, suidSysId, SUIDSysId);
            };
        } // namespace tsbk
    } // namespace lc
} // namespace p25

#endif // __P25_LC_TSBK__MBT_OSP_U_REG_RSP_H__
```

- [ ] **Step 4: Create the implementation**

`src/common/p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.cpp`:

```cpp
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Common Library
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "Defines.h"
#include "p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.h"

using namespace p25;
using namespace p25::defines;
using namespace p25::lc;
using namespace p25::lc::tsbk;

#include <cassert>

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Initializes a new instance of the MBT_OSP_U_REG_RSP class. */

MBT_OSP_U_REG_RSP::MBT_OSP_U_REG_RSP() : AMBT(),
    m_suidNetId(0U),
    m_suidSysId(0U)
{
    m_lco = TSBKO::IOSP_U_REG;
}

/* Decode a alternate trunking signalling block. */

bool MBT_OSP_U_REG_RSP::decodeMBT(const data::DataHeader& dataHeader, const data::DataBlock* blocks)
{
    assert(blocks != nullptr);

    // outbound-only message
    return false;
}

/* Encode a alternate trunking signalling block. */

void MBT_OSP_U_REG_RSP::encodeMBT(data::DataHeader& dataHeader, uint8_t* pduUserData)
{
    assert(pduUserData != nullptr);

    // header octets 8 and 9 carry the upper 16 bits of the SUID WACN ID (TIA-102.AABC-D Figure 6.2.21-2)
    dataHeader.setAMBTField8((m_suidNetId >> 12) & 0xFFU);                          // WACN ID (b19-b12)
    dataHeader.setAMBTField9((m_suidNetId >> 4) & 0xFFU);                           // WACN ID (b11-b4)

    /** Block 1 */
    pduUserData[0U] = (uint8_t)(((m_suidNetId & 0x0FU) << 4) +                      // WACN ID (b3-b0)
        ((m_suidSysId >> 8) & 0x0FU));                                              // System ID (b11-b8)
    pduUserData[1U] = (uint8_t)(m_suidSysId & 0xFFU);                               // System ID (b7-b0)
    SET_UINT24(m_dstId, pduUserData, 2U);                                           // Source ID (SUID Unit ID)
    pduUserData[5U] = m_response & 0x03U;                                           // Registration Value

    AMBT::encode(dataHeader, pduUserData);
}

/* Returns a string that represents the current AMBT. */

std::string MBT_OSP_U_REG_RSP::toString(bool isp)
{
    return std::string("TSBKO, IOSP_U_REG (Unit Registration Response - Extended)");
}
```

`AMBT::encode()` sets the LLId from `m_srcId` (Source Address), the AMBT opcode, format, SAP, outbound flag, blocks to follow, and the packet CRC.

In `src/common/p25/lc/tsbk/TSBKFactory.h`, add after the `MBT_OSP_NET_STS_BCAST.h` include:

```cpp
#include "common/p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.h"
```

No factory decode case is added; the host never receives this outbound message.

- [ ] **Step 5: Run tests**

Run: `cmake --build build -j2 && ./build/dvmtests '[p25][tsbk]' --reporter compact`
Expected: all pass. If `CHECK(header.getOutbound())` fails, confirm `AMBT::encode()` sets `setOutbound(true)` (it does in `src/common/p25/lc/AMBT.cpp`) and that the test calls `encodeMBT`, not `encode`.

- [ ] **Step 6: Commit**

```bash
git add src/common/p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.h src/common/p25/lc/tsbk/mbt/MBT_OSP_U_REG_RSP.cpp src/common/p25/lc/tsbk/TSBKFactory.h tests/p25/TSBK_Registration_Tests.cpp
git commit -m "add extended format U_REG_RSP alternate MBT per TIA-102.AABC-D 6.2.21.2, add known-answer test;"
```

---

### Task 4: `P25WuidLookup`

**Files:**
- Create: `src/host/p25/lookups/P25WuidLookup.h`, `src/host/p25/lookups/P25WuidLookup.cpp`
- Create: `tests/p25/P25WuidLookup_Tests.cpp`

**Interfaces:**
- Produces (namespace `p25::lookups`):
  - `struct P25WuidLookup::SUID { uint32_t netId; uint32_t sysId; uint32_t unitId; }`
  - `P25WuidLookup()`
  - `static bool validRange(uint32_t start, uint32_t end)` — true when `0 < start <= end < WUID_FNE`.
  - `bool setPool(uint32_t start, uint32_t end)` — validates, clears all assignments, returns false (pool disabled) on invalid input.
  - `void clear()` — removes the pool and all assignments.
  - `bool enabled() const`
  - `uint32_t poolStart() const`, `uint32_t poolEnd() const`
  - `uint32_t allocate(const SUID& suid)` — existing WUID for the SUID, else lowest free, else `0U`.
  - `bool release(uint32_t wuid)` — true if an assignment was removed.
  - `bool findBySuid(const SUID& suid, uint32_t& wuid) const`
  - `bool findByWuid(uint32_t wuid, SUID& suid) const`
  - `bool isPoolWuid(uint32_t wuid) const` — false when no pool is configured.
  - `uint32_t count() const`

- [ ] **Step 1: Write the failing tests**

`tests/p25/P25WuidLookup_Tests.cpp`:

```cpp
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Test Suite
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "host/Defines.h"
#include "common/p25/P25Defines.h"
#include "host/p25/lookups/P25WuidLookup.h"

#include <catch2/catch_test_macros.hpp>

using namespace p25::lookups;

namespace {
    P25WuidLookup::SUID suid(uint32_t sysId, uint32_t unitId)
    {
        P25WuidLookup::SUID ret;
        ret.netId = 0xBB800U;
        ret.sysId = sysId;
        ret.unitId = unitId;
        return ret;
    }
}

TEST_CASE("P25 WUID lookup range validation", "[p25][roaming][wuid]") {
    CHECK_FALSE(P25WuidLookup::validRange(0U, 10U));
    CHECK_FALSE(P25WuidLookup::validRange(20U, 10U));
    CHECK_FALSE(P25WuidLookup::validRange(100U, p25::defines::WUID_FNE));
    CHECK(P25WuidLookup::validRange(100U, 100U));
    CHECK(P25WuidLookup::validRange(1U, p25::defines::WUID_FNE - 1U));
}

TEST_CASE("P25 WUID lookup is inert without a pool", "[p25][roaming][wuid]") {
    P25WuidLookup lookup;
    CHECK_FALSE(lookup.enabled());
    CHECK_FALSE(lookup.isPoolWuid(0U));
    CHECK_FALSE(lookup.isPoolWuid(9000000U));
    CHECK(lookup.allocate(suid(0x002U, 1001U)) == 0U);
    CHECK_FALSE(lookup.setPool(0U, 10U));
    CHECK_FALSE(lookup.enabled());
}

TEST_CASE("P25 WUID lookup allocation", "[p25][roaming][wuid]") {
    P25WuidLookup lookup;
    REQUIRE(lookup.setPool(9000000U, 9000002U));

    SECTION("Boundaries") {
        CHECK_FALSE(lookup.isPoolWuid(8999999U));
        CHECK(lookup.isPoolWuid(9000000U));
        CHECK(lookup.isPoolWuid(9000002U));
        CHECK_FALSE(lookup.isPoolWuid(9000003U));
    }

    SECTION("Lowest_Free_And_Reregistration") {
        CHECK(lookup.allocate(suid(0x002U, 1001U)) == 9000000U);
        CHECK(lookup.allocate(suid(0x003U, 1001U)) == 9000001U);
        CHECK(lookup.allocate(suid(0x002U, 1001U)) == 9000000U);
        CHECK(lookup.count() == 2U);
    }

    SECTION("Exhaustion_And_Reuse") {
        CHECK(lookup.allocate(suid(0x002U, 1U)) == 9000000U);
        CHECK(lookup.allocate(suid(0x002U, 2U)) == 9000001U);
        CHECK(lookup.allocate(suid(0x002U, 3U)) == 9000002U);
        CHECK(lookup.allocate(suid(0x002U, 4U)) == 0U);

        CHECK(lookup.release(9000001U));
        CHECK_FALSE(lookup.release(9000001U));
        CHECK(lookup.allocate(suid(0x002U, 4U)) == 9000001U);
    }

    SECTION("Bidirectional_Lookup") {
        const uint32_t wuid = lookup.allocate(suid(0x2A5U, 0x0F4240U));
        REQUIRE(wuid == 9000000U);

        uint32_t found = 0U;
        CHECK(lookup.findBySuid(suid(0x2A5U, 0x0F4240U), found));
        CHECK(found == wuid);
        CHECK_FALSE(lookup.findBySuid(suid(0x2A6U, 0x0F4240U), found));

        P25WuidLookup::SUID back;
        REQUIRE(lookup.findByWuid(wuid, back));
        CHECK(back.netId == 0xBB800U);
        CHECK(back.sysId == 0x2A5U);
        CHECK(back.unitId == 0x0F4240U);
        CHECK_FALSE(lookup.findByWuid(9000001U, back));
    }

    SECTION("Release_Unknown_And_Clear") {
        CHECK_FALSE(lookup.release(1234U));
        lookup.allocate(suid(0x002U, 1U));
        lookup.clear();
        CHECK_FALSE(lookup.enabled());
        CHECK(lookup.count() == 0U);
    }
}

TEST_CASE("P25 WUID lookup single-ID pool", "[p25][roaming][wuid]") {
    P25WuidLookup lookup;
    REQUIRE(lookup.setPool(500U, 500U));
    CHECK(lookup.allocate(suid(0x002U, 1U)) == 500U);
    CHECK(lookup.allocate(suid(0x002U, 2U)) == 0U);
}
```

- [ ] **Step 2: Build to verify it fails**

Run: `cmake --build build -j2`
Expected: compile error, `host/p25/lookups/P25WuidLookup.h` not found. If the test cannot find `host/...` includes, check how `tests/p25/HostControl_Tests.cpp` includes `host/p25/Control.h` and match its include form.

- [ ] **Step 3: Create the header**

`src/host/p25/lookups/P25WuidLookup.h`:

```cpp
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Modem Host Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
/**
 * @file P25WuidLookup.h
 * @ingroup host_lookups
 * @file P25WuidLookup.cpp
 * @ingroup host_lookups
 */
#if !defined(__P25_WUID_LOOKUP_H__)
#define __P25_WUID_LOOKUP_H__

#include "Defines.h"

#include <map>
#include <mutex>

namespace p25
{
    namespace lookups
    {
        // ---------------------------------------------------------------------------
        //  Class Declaration
        // ---------------------------------------------------------------------------

        /**
         * @brief Implements the Working Unit ID (WUID) pool assigned to roaming subscriber units.
         *  Per TIA-102.AABD-B 6.2, a foreign SU (different WACN ID and/or System ID) is assigned a WUID
         *  from an operator-controlled pool that cannot be the Unit ID portion of a Home SUID.
         * @ingroup host_lookups
         */
        class HOST_SW_API P25WuidLookup {
        public:
            /**
             * @brief Subscriber Unit ID (SUID) of a registering subscriber unit.
             * @ingroup host_lookups
             */
            struct SUID {
                uint32_t netId;     //!< WACN ID (20-bit).
                uint32_t sysId;     //!< System ID (12-bit).
                uint32_t unitId;    //!< Unit ID (24-bit).
            };

            /**
             * @brief Initializes a new instance of the P25WuidLookup class.
             */
            P25WuidLookup();

            /**
             * @brief Validates a WUID pool range.
             * @param start First WUID of the pool (inclusive).
             * @param end Last WUID of the pool (inclusive).
             * @returns bool True if 0 < start <= end and end is below the reserved WUID range; otherwise, false.
             */
            static bool validRange(uint32_t start, uint32_t end);

            /**
             * @brief Configures the WUID pool and clears all assignments.
             * @param start First WUID of the pool (inclusive).
             * @param end Last WUID of the pool (inclusive).
             * @returns bool True if the pool was configured; false if the range is invalid (pool disabled).
             */
            bool setPool(uint32_t start, uint32_t end);
            /**
             * @brief Removes the pool and all assignments.
             */
            void clear();

            /**
             * @brief Gets whether a WUID pool is configured.
             * @returns bool True if a pool is configured; otherwise, false.
             */
            bool enabled() const;
            /**
             * @brief Gets the first WUID of the pool.
             * @returns uint32_t First WUID, or 0 if no pool is configured.
             */
            uint32_t poolStart() const;
            /**
             * @brief Gets the last WUID of the pool.
             * @returns uint32_t Last WUID, or 0 if no pool is configured.
             */
            uint32_t poolEnd() const;

            /**
             * @brief Allocates a WUID for a roaming SU.
             * @param suid SUID of the registering SU.
             * @returns uint32_t The SU's existing WUID, the lowest free pool WUID, or 0 if the pool is exhausted or disabled.
             */
            uint32_t allocate(const SUID& suid);
            /**
             * @brief Releases an assigned WUID.
             * @param wuid WUID to release.
             * @returns bool True if an assignment was removed; otherwise, false.
             */
            bool release(uint32_t wuid);

            /**
             * @brief Finds the WUID assigned to an SUID.
             * @param suid SUID to look up.
             * @param[out] wuid Assigned WUID when found.
             * @returns bool True if the SUID has an assigned WUID; otherwise, false.
             */
            bool findBySuid(const SUID& suid, uint32_t& wuid) const;
            /**
             * @brief Finds the SUID assigned to a WUID.
             * @param wuid WUID to look up.
             * @param[out] suid Assigned SUID when found.
             * @returns bool True if the WUID is assigned; otherwise, false.
             */
            bool findByWuid(uint32_t wuid, SUID& suid) const;

            /**
             * @brief Determines whether a WUID lies within the configured pool.
             * @param wuid WUID to test.
             * @returns bool True if a pool is configured and the WUID lies within it; otherwise, false.
             */
            bool isPoolWuid(uint32_t wuid) const;
            /**
             * @brief Gets the number of assigned WUIDs.
             * @returns uint32_t Number of assigned WUIDs.
             */
            uint32_t count() const;

        private:
            mutable std::mutex m_mutex;
            uint32_t m_start;
            uint32_t m_end;
            std::map<uint64_t, uint32_t> m_bySuid;
            std::map<uint32_t, SUID> m_byWuid;

            /**
             * @brief Packs an SUID into a 56-bit map key.
             * @param suid SUID to pack.
             * @returns uint64_t Packed key (WACN ID, System ID, Unit ID).
             */
            static uint64_t key(const SUID& suid);
        };
    } // namespace lookups
} // namespace p25

#endif // __P25_WUID_LOOKUP_H__
```

- [ ] **Step 4: Create the implementation**

`src/host/p25/lookups/P25WuidLookup.cpp`:

```cpp
// SPDX-License-Identifier: GPL-2.0-only
/*
 * Digital Voice Modem - Modem Host Software
 * GPLv2 Open Source. Use is subject to license terms.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 *  Copyright (C) 2026 David Andrzejewski
 *
 */
#include "Defines.h"
#include "common/p25/P25Defines.h"
#include "p25/lookups/P25WuidLookup.h"

using namespace p25;
using namespace p25::defines;
using namespace p25::lookups;

// ---------------------------------------------------------------------------
//  Public Class Members
// ---------------------------------------------------------------------------

/* Initializes a new instance of the P25WuidLookup class. */

P25WuidLookup::P25WuidLookup() :
    m_mutex(),
    m_start(0U),
    m_end(0U),
    m_bySuid(),
    m_byWuid()
{
    /* stub */
}

/* Validates a WUID pool range. */

bool P25WuidLookup::validRange(uint32_t start, uint32_t end)
{
    // $000000 is "No one" (TIA-102.BAAC-C); WUID_FNE and above are reserved special WUIDs
    return (start > 0U) && (start <= end) && (end < WUID_FNE);
}

/* Configures the WUID pool and clears all assignments. */

bool P25WuidLookup::setPool(uint32_t start, uint32_t end)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_bySuid.clear();
    m_byWuid.clear();

    if (!validRange(start, end)) {
        m_start = 0U;
        m_end = 0U;
        return false;
    }

    m_start = start;
    m_end = end;
    return true;
}

/* Removes the pool and all assignments. */

void P25WuidLookup::clear()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_bySuid.clear();
    m_byWuid.clear();
    m_start = 0U;
    m_end = 0U;
}

/* Gets whether a WUID pool is configured. */

bool P25WuidLookup::enabled() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_start != 0U;
}

/* Gets the first WUID of the pool. */

uint32_t P25WuidLookup::poolStart() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_start;
}

/* Gets the last WUID of the pool. */

uint32_t P25WuidLookup::poolEnd() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_end;
}

/* Allocates a WUID for a roaming SU. */

uint32_t P25WuidLookup::allocate(const SUID& suid)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_start == 0U) {
        return 0U;
    }

    // re-registration retains the existing WUID
    auto existing = m_bySuid.find(key(suid));
    if (existing != m_bySuid.end()) {
        return existing->second;
    }

    // walk the ordered assignments for the lowest gap in the pool
    uint32_t candidate = m_start;
    for (const auto& entry : m_byWuid) {
        if (entry.first == candidate) {
            candidate++;
        }
        else if (entry.first > candidate) {
            break;
        }
    }

    if (candidate > m_end) {
        return 0U;
    }

    m_bySuid[key(suid)] = candidate;
    m_byWuid[candidate] = suid;
    return candidate;
}

/* Releases an assigned WUID. */

bool P25WuidLookup::release(uint32_t wuid)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_byWuid.find(wuid);
    if (it == m_byWuid.end()) {
        return false;
    }

    m_bySuid.erase(key(it->second));
    m_byWuid.erase(it);
    return true;
}

/* Finds the WUID assigned to an SUID. */

bool P25WuidLookup::findBySuid(const SUID& suid, uint32_t& wuid) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_bySuid.find(key(suid));
    if (it == m_bySuid.end()) {
        return false;
    }

    wuid = it->second;
    return true;
}

/* Finds the SUID assigned to a WUID. */

bool P25WuidLookup::findByWuid(uint32_t wuid, SUID& suid) const
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto it = m_byWuid.find(wuid);
    if (it == m_byWuid.end()) {
        return false;
    }

    suid = it->second;
    return true;
}

/* Determines whether a WUID lies within the configured pool. */

bool P25WuidLookup::isPoolWuid(uint32_t wuid) const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return (m_start != 0U) && (wuid >= m_start) && (wuid <= m_end);
}

/* Gets the number of assigned WUIDs. */

uint32_t P25WuidLookup::count() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return (uint32_t)m_byWuid.size();
}

// ---------------------------------------------------------------------------
//  Private Class Members
// ---------------------------------------------------------------------------

/* Packs an SUID into a 56-bit map key. */

uint64_t P25WuidLookup::key(const SUID& suid)
{
    return ((uint64_t)(suid.netId & 0xFFFFFU) << 36) +
        ((uint64_t)(suid.sysId & 0xFFFU) << 24) +
        (uint64_t)(suid.unitId & 0xFFFFFFU);
}
```

Check the include of `P25Defines.h` against how `src/host/p25/lookups/P25AffiliationLookup.cpp` includes common headers, and match it.

- [ ] **Step 5: Run tests**

Run: `cmake --build build -j2 && ./build/dvmtests '[p25][roaming][wuid]' --reporter compact`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/host/p25/lookups/P25WuidLookup.h src/host/p25/lookups/P25WuidLookup.cpp tests/p25/P25WuidLookup_Tests.cpp
git commit -m "add P25 WUID pool lookup for roaming subscriber units per TIA-102.AABD-B 6.2, add unit tests;"
```

---

### Task 5: Roaming configuration and WUID ownership in `p25::Control`

**Files:**
- Modify: `src/host/p25/Control.h`, `src/host/p25/Control.cpp`
- Modify: `tests/host/HostTestHooks.h`, `tests/host/HostTestHooks.cpp`
- Modify: `configs/config.example.yml`
- Test: `tests/p25/HostControl_Tests.cpp`

**Interfaces:**
- Consumes: `P25WuidLookup` (Task 4).
- Produces:
  - `p25::Control` private members: `bool m_allowRoaming; std::vector<uint32_t> m_roamingSysIds;` (after `m_ackTSBKRequests`) and `lookups::P25WuidLookup* m_wuidLookup;` (after `m_affiliations`).
  - Private `bool p25::Control::configureRoaming(bool allow, const std::vector<uint32_t>& sysIds, uint32_t wuidStart, uint32_t wuidEnd);` — validates; on any error logs it, disables roaming, clears the pool, returns false.
  - Test hooks: `HostTestHooks::p25SetSiteData(p25::Control&, const p25::SiteData&)`, `HostTestHooks::p25ConfigureRoaming(p25::Control&, bool allow, const std::vector<uint32_t>& sysIds, uint32_t wuidStart, uint32_t wuidEnd)` returning `bool`, `HostTestHooks::p25WuidLookup(p25::Control&)` returning `p25::lookups::P25WuidLookup*`, `HostTestHooks::p25IsUnitReg(const p25::Control&, uint32_t)` returning `bool`, `HostTestHooks::p25UnitDereg(p25::Control&, uint32_t srcId, bool automatic)`.

- [ ] **Step 1: Write the failing tests**

Add to `tests/p25/HostControl_Tests.cpp` (after the existing test cases; add `#include "common/p25/lc/TSBK.h"` and `#include "host/p25/lookups/P25WuidLookup.h"` to the includes if not already present):

```cpp
TEST_CASE("P25 roaming configuration rejects invalid settings", "[p25][host][roaming][config]")
{
    P25HostHarness harness;
    const p25::SiteData previous = p25::lc::TSBK::getSiteData();
    HostTestHooks::p25SetSiteData(*harness.m_control, p25::SiteData(0xBB800U, 0x001U, 1U, 1U, 1U, 1U, 1U, 0x00U, 0));

    CHECK_FALSE(HostTestHooks::p25ConfigureRoaming(*harness.m_control, true, {}, 0U, 0U));
    CHECK_FALSE(HostTestHooks::p25WuidLookup(*harness.m_control)->enabled());
    CHECK_FALSE(HostTestHooks::p25ConfigureRoaming(*harness.m_control, true, {}, 200U, 100U));
    CHECK_FALSE(HostTestHooks::p25ConfigureRoaming(*harness.m_control, true, { 0x001U }, 9000000U, 9000010U));
    CHECK_FALSE(HostTestHooks::p25ConfigureRoaming(*harness.m_control, true, { 0x1000U }, 9000000U, 9000010U));
    CHECK(HostTestHooks::p25ConfigureRoaming(*harness.m_control, true, { 0x002U }, 9000000U, 9000010U));
    CHECK(HostTestHooks::p25WuidLookup(*harness.m_control)->enabled());
    CHECK(HostTestHooks::p25ConfigureRoaming(*harness.m_control, false, {}, 0U, 0U));
    CHECK_FALSE(HostTestHooks::p25WuidLookup(*harness.m_control)->enabled());

    p25::lc::TSBK::setSiteData(previous);
}

TEST_CASE("P25 roaming WUID is released on de-registration", "[p25][host][roaming][wuid]")
{
    P25HostHarness harness;
    const p25::SiteData previous = p25::lc::TSBK::getSiteData();
    HostTestHooks::p25SetSiteData(*harness.m_control, p25::SiteData(0xBB800U, 0x001U, 1U, 1U, 1U, 1U, 1U, 0x00U, 0));
    REQUIRE(HostTestHooks::p25ConfigureRoaming(*harness.m_control, true, {}, 9000000U, 9000010U));

    p25::lookups::P25WuidLookup* lookup = HostTestHooks::p25WuidLookup(*harness.m_control);
    p25::lookups::P25WuidLookup::SUID suid = { 0xBB800U, 0x002U, 1001U };
    const uint32_t wuid = lookup->allocate(suid);
    REQUIRE(wuid == 9000000U);
    HostTestHooks::p25RegisterUnit(*harness.m_control, wuid);

    HostTestHooks::p25UnitDereg(*harness.m_control, wuid, true);
    CHECK_FALSE(HostTestHooks::p25IsUnitReg(*harness.m_control, wuid));
    CHECK(lookup->count() == 0U);

    p25::lc::TSBK::setSiteData(previous);
}
```

- [ ] **Step 2: Build to verify it fails**

Run: `cmake --build build -j2`
Expected: compile errors for the missing hooks.

- [ ] **Step 3: Add members and the private method to `Control.h`**

Add `#include "p25/lookups/P25WuidLookup.h"` directly after `#include "p25/lookups/P25AffiliationLookup.h"` (line 46). Add `#include <vector>` to the standard include group if it is not already included.

Immediately after `bool m_ackTSBKRequests;` add:

```cpp
        bool m_allowRoaming;
        std::vector<uint32_t> m_roamingSysIds;
```

Immediately after `lookups::P25AffiliationLookup* m_affiliations;` add:

```cpp
        lookups::P25WuidLookup* m_wuidLookup;
```

In the private member-function section (after all private data members, per `AGENTS.md`), add:

```cpp
        /**
         * @brief Configures roaming unit registration and the roaming WUID pool.
         *  Any validation error is logged and leaves roaming disabled; there is no permissive fallback.
         * @param allow Flag indicating whether SUs homed to other System IDs in this WACN may register.
         * @param sysIds Home System IDs permitted to roam here; empty permits any System ID in this WACN.
         * @param wuidStart First WUID of the roaming pool (inclusive).
         * @param wuidEnd Last WUID of the roaming pool (inclusive).
         * @returns bool True if the configuration was applied (including disabling roaming); false on validation error.
         */
        bool configureRoaming(bool allow, const std::vector<uint32_t>& sysIds, uint32_t wuidStart, uint32_t wuidEnd);
```

- [ ] **Step 4: Initialize, construct, destroy in `Control.cpp`**

After `m_ackTSBKRequests(true),` add (confirm the next initializer matches the next declared member):

```cpp
    m_allowRoaming(false),
    m_roamingSysIds(),
```

After `m_affiliations(nullptr),` add:

```cpp
    m_wuidLookup(nullptr),
```

After `m_affiliations = new lookups::P25AffiliationLookup(this, chLookup, verbose);` (line 159) add:

```cpp
    m_wuidLookup = new lookups::P25WuidLookup();
```

Next to `delete m_affiliations;` (line 193) add:

```cpp
        delete m_wuidLookup;
```

(keep it inside the same condition/block as the affiliation delete).

- [ ] **Step 5: Implement `configureRoaming`**

Add near the other private `Control` members in `Control.cpp`:

```cpp
/* Configures roaming unit registration and the roaming WUID pool. */

bool Control::configureRoaming(bool allow, const std::vector<uint32_t>& sysIds, uint32_t wuidStart, uint32_t wuidEnd)
{
    m_allowRoaming = false;
    m_roamingSysIds.clear();
    m_wuidLookup->clear();

    if (!allow) {
        return true;
    }

    if (!lookups::P25WuidLookup::validRange(wuidStart, wuidEnd)) {
        LogError(LOG_P25, "Roaming disabled, invalid roaming WUID pool, roamingWuidStart = %u, roamingWuidEnd = %u", wuidStart, wuidEnd);
        return false;
    }

    for (uint32_t sysId : sysIds) {
        if (sysId == 0U || sysId > 0xFFFU) {
            LogError(LOG_P25, "Roaming disabled, invalid roaming System ID $%X", sysId);
            return false;
        }

        if (sysId == m_siteData.sysId()) {
            LogError(LOG_P25, "Roaming disabled, roaming System ID $%03X is this site's System ID", sysId);
            return false;
        }
    }

    // a home Unit ID inside the pool would collide with roaming WUIDs (TIA-102.AABD-B 6.2)
    if (m_ridLookup != nullptr && m_ridLookup->getACL()) {
        for (const auto& entry : m_ridLookup->table()) {
            if (entry.first >= wuidStart && entry.first <= wuidEnd) {
                LogWarning(LOG_P25, "Roaming WUID pool overlaps RID ACL entry %u; home Unit IDs must not be assigned from the roaming pool", entry.first);
            }
        }
    }

    m_wuidLookup->setPool(wuidStart, wuidEnd);
    m_roamingSysIds = sysIds;
    m_allowRoaming = true;
    return true;
}
```

- [ ] **Step 6: Load configuration in `setOptions`**

Directly after `m_affiliations->setDisableUnitRegTimeout(disableUnitRegTimeout);` add:

```cpp
    bool allowRoaming = p25Protocol["allowRoaming"].as<bool>(false);
    std::vector<uint32_t> roamingSysIds;
    yaml::Node roamingSysIdList = p25Protocol["roamingSysIds"];
    for (size_t i = 0; i < roamingSysIdList.size(); i++) {
        roamingSysIds.push_back((uint32_t)::strtoul(roamingSysIdList[i].as<std::string>("0").c_str(), NULL, 16));
    }
    uint32_t roamingWuidStart = p25Protocol["roamingWuidStart"].as<uint32_t>(0U);
    uint32_t roamingWuidEnd = p25Protocol["roamingWuidEnd"].as<uint32_t>(0U);
    configureRoaming(allowRoaming, roamingSysIds, roamingWuidStart, roamingWuidEnd);
```

Before writing this, find how `setOptions` already parses hex strings (search `strtoul` in `src/host/p25/Control.cpp` and `src/host/Host.Config.cpp`) and how YAML sequences are iterated elsewhere (search `.size(); i++` near `yaml::Node` usage). Match that existing idiom exactly, including `nullptr` vs `NULL` as the surrounding code uses for `strtoul`.

Next to the existing startup banner lines (`LogInfo("    Require LLA for Registration: ...")`, line 537) add:

```cpp
        LogInfo("    Allow Roaming: %s", m_allowRoaming ? "yes" : "no");
        if (m_allowRoaming) {
            LogInfo("    Roaming WUID Pool: %u - %u", m_wuidLookup->poolStart(), m_wuidLookup->poolEnd());
            if (m_roamingSysIds.empty()) {
                LogInfo("    Roaming System IDs: any in WACN $%05X", m_siteData.netId());
            }
            else {
                for (uint32_t sysId : m_roamingSysIds) {
                    LogInfo("    Roaming System ID: $%03X", sysId);
                }
            }
        }
```

- [ ] **Step 7: Release WUIDs in the de-registration callback**

Replace the callback body at `Control.cpp:465` so it reads:

```cpp
    m_affiliations->setUnitDeregCallback([=](uint32_t srcId, bool automatic) {
        // roaming SU WUIDs are local only and return to the pool (TIA-102.AABD-B 6.6.1)
        const bool roaming = m_wuidLookup->isPoolWuid(srcId);
        if (roaming) {
            m_wuidLookup->release(srcId);
        }

        if (m_network != nullptr && !roaming)
            m_network->announceUnitDeregistration(srcId);

        // fire off a U_REG_CMD to get the SU to re-affiliate
        if (m_enableControl && automatic) {
            m_control->writeRF_TSDU_U_Reg_Cmd(srcId);
        }
    });
```

- [ ] **Step 8: Add test hooks**

In `tests/host/HostTestHooks.h`, in the P25 section (near `p25RegisterUnit`), add declarations with full Doxygen:

```cpp
    /**
     * @brief Sets P25 site data on the controller and the TSBK/LC encoders.
     * @param control P25 controller.
     * @param siteData Site data to apply.
     */
    static void p25SetSiteData(p25::Control& control, const p25::SiteData& siteData);
    /**
     * @brief Configures P25 roaming registration and enables control signaling.
     * @param control P25 controller.
     * @param allow Flag indicating whether roaming registration is allowed.
     * @param sysIds Permitted home System IDs (empty permits any in the WACN).
     * @param wuidStart First roaming WUID (inclusive).
     * @param wuidEnd Last roaming WUID (inclusive).
     * @returns bool True if the configuration was applied; otherwise, false.
     */
    static bool p25ConfigureRoaming(p25::Control& control, bool allow, const std::vector<uint32_t>& sysIds,
        uint32_t wuidStart, uint32_t wuidEnd);
    /**
     * @brief Gets the P25 roaming WUID lookup.
     * @param control P25 controller.
     * @returns p25::lookups::P25WuidLookup* WUID lookup.
     */
    static p25::lookups::P25WuidLookup* p25WuidLookup(p25::Control& control);
    /**
     * @brief Determines whether a unit is registered.
     * @param control P25 controller.
     * @param srcId Unit or working unit ID.
     * @returns bool True if registered; otherwise, false.
     */
    static bool p25IsUnitReg(const p25::Control& control, uint32_t srcId);
    /**
     * @brief De-registers a unit through the affiliation table.
     * @param control P25 controller.
     * @param srcId Unit or working unit ID.
     * @param automatic Flag indicating timer-driven de-registration.
     */
    static void p25UnitDereg(p25::Control& control, uint32_t srcId, bool automatic);
```

Add any forward declarations/includes the header needs following its existing pattern (`p25::SiteData`, `p25::lookups::P25WuidLookup`, `<vector>`).

In `tests/host/HostTestHooks.cpp`:

```cpp
/* Sets P25 site data on the controller and the TSBK/LC encoders. */

void HostTestHooks::p25SetSiteData(p25::Control& control, const p25::SiteData& siteData)
{
    control.m_siteData = siteData;
    p25::lc::LC::setSiteData(siteData);
    p25::lc::TSBK::setSiteData(siteData);
}

/* Configures P25 roaming registration and enables control signaling. */

bool HostTestHooks::p25ConfigureRoaming(p25::Control& control, bool allow, const std::vector<uint32_t>& sysIds,
    uint32_t wuidStart, uint32_t wuidEnd)
{
    control.m_enableControl = true;
    return control.configureRoaming(allow, sysIds, wuidStart, wuidEnd);
}

/* Gets the P25 roaming WUID lookup. */

p25::lookups::P25WuidLookup* HostTestHooks::p25WuidLookup(p25::Control& control)
{
    return control.m_wuidLookup;
}

/* Determines whether a unit is registered. */

bool HostTestHooks::p25IsUnitReg(const p25::Control& control, uint32_t srcId)
{
    return control.m_affiliations->isUnitReg(srcId);
}

/* De-registers a unit through the affiliation table. */

void HostTestHooks::p25UnitDereg(p25::Control& control, uint32_t srcId, bool automatic)
{
    control.m_affiliations->unitDereg(srcId, automatic);
}
```

Confirm the `unitDereg` parameter list (`srcId, automatic, log`) in `src/common/lookups/AffiliationLookup.h` and whether `P25AffiliationLookup` overrides it.

- [ ] **Step 9: Example configuration**

In `configs/config.example.yml`, directly after the `requireLLAForReg: false` line (inside `protocols.p25`, same indentation), add:

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

Validate: `python3 -c "import yaml,sys; yaml.safe_load(open('configs/config.example.yml'))" && echo OK`
Expected: `OK`. Check `tools/dvmcfggen/templates.py` loads the example config rather than templating these keys (`grep -n "config.example" tools/dvmcfggen/*.py`); if it builds the p25 block itself, add the four keys with the same defaults.

- [ ] **Step 10: Run tests**

Run: `cmake --build build -j2 && ./build/dvmtests '[p25][host]' --reporter compact`
Expected: all pass, including the two new cases.

- [ ] **Step 11: Commit**

```bash
git add src/host/p25/Control.h src/host/p25/Control.cpp tests/host/HostTestHooks.h tests/host/HostTestHooks.cpp tests/p25/HostControl_Tests.cpp configs/config.example.yml
git commit -m "add P25 roaming configuration and WUID pool ownership, release roaming WUIDs on de-registration without network announcement;"
```

---

### Task 6: Registration classification

**Files:**
- Modify: `src/host/p25/packet/ControlSignaling.h:504`, `src/host/p25/packet/ControlSignaling.cpp` (IOSP_U_REG case ~885–906, ISP_AUTH_RESP success ~972, `writeRF_TSDU_U_Reg_Rsp` ~3665–3712)
- Test: `tests/p25/HostControl_Tests.cpp`

**Interfaces:**
- Consumes: `IOSP_U_REG::setSUIDSysId` (Task 2), `MBT_OSP_U_REG_RSP` (Task 3), `P25WuidLookup` (Task 4), `Control::m_allowRoaming`, `m_roamingSysIds`, `m_wuidLookup` (Task 5).
- Produces: `void ControlSignaling::writeRF_TSDU_U_Reg_Rsp(const lookups::P25WuidLookup::SUID& suid);` replacing `writeRF_TSDU_U_Reg_Rsp(uint32_t srcId, uint32_t sysId)`.

- [ ] **Step 1: Write the failing tests**

Add helpers to the anonymous namespace in `tests/p25/HostControl_Tests.cpp` (near `buildUUVchRequest`):

```cpp
/**
 * @brief Builds an independently encoded U_REG_REQ ISP TSBK (TIA-102.AABC-D Figure 6.1.16-1).
 * @param netId SUID WACN ID.
 * @param sysId SUID System ID.
 * @param unitId SUID Unit ID.
 * @param raw The buffer to store the constructed TSBK.
 */
void buildUnitRegRequest(uint32_t netId, uint32_t sysId, uint32_t unitId, uint8_t* raw)
{
    ::memset(raw, 0x00U, p25::defines::P25_TSBK_LENGTH_BYTES);
    raw[0U] = 0x80U | p25::defines::TSBKO::IOSP_U_REG;
    raw[1U] = p25::defines::MFG_STANDARD;
    raw[2U] = 0x00U;                                                                // Capabilities
    raw[3U] = (netId >> 12) & 0xFFU;                                                // WACN ID (b19-b12)
    raw[4U] = (netId >> 4) & 0xFFU;                                                 // WACN ID (b11-b4)
    raw[5U] = (uint8_t)(((netId & 0x0FU) << 4) + ((sysId >> 8) & 0x0FU));           // WACN ID (b3-b0), System ID (b11-b8)
    raw[6U] = sysId & 0xFFU;                                                        // System ID (b7-b0)
    SET_UINT24(unitId, raw, 7U);                                                    // Source ID
    edac::CRC::addCCITT162(raw, p25::defines::P25_TSBK_LENGTH_BYTES);
}

/**
 * @brief Drains queued RF frames and returns the raw bytes of the last TSDU with the given LCO.
 * @param control P25 controller.
 * @param lco TSBK LCO to match.
 * @param[out] raw Raw TSBK bytes when found.
 * @param[out] pduSeen Set true if a non-TSDU (PDU) frame was drained.
 * @returns bool True if a matching TSDU was found; otherwise, false.
 */
bool drainForTSBK(p25::Control& control, uint8_t lco, uint8_t* raw, bool& pduSeen)
{
    bool found = false;
    pduSeen = false;

    uint8_t frame[4096U];
    uint32_t len = 0U;
    while ((len = control.getFrame(frame)) > 0U) {
        if (len != p25::defines::P25_TSDU_FRAME_LENGTH_BYTES + 2U) {
            pduSeen = true;
            continue;
        }

        std::unique_ptr<p25::lc::TSBK> tsbk = p25::lc::tsbk::TSBKFactory::createTSBK(frame + 2U);
        if (tsbk == nullptr || tsbk->getLCO() != lco || tsbk->getDecodedRaw() == nullptr) {
            continue;
        }

        ::memcpy(raw, tsbk->getDecodedRaw(), p25::defines::P25_TSBK_LENGTH_BYTES);
        found = true;
    }

    return found;
}
```

Before relying on `drainForTSBK`, confirm `getFrame` returns `0U` when empty and verify the frame buffer size bound used by other tests (search `getFrame(` usages); adjust the buffer to the largest P25 frame constant if one exists (for example `P25_PDU_FRAME_LENGTH_BYTES`). Add `#include "common/p25/lc/tsbk/TSBKFactory.h"` if not present.

Add a fixture helper and the test cases:

```cpp
/**
 * @brief Prepares a trunking harness on WACN $BB800 / System $001 with a roaming pool.
 * @param harness Harness to configure.
 * @param allow Flag indicating whether roaming is allowed.
 * @param sysIds Permitted home System IDs.
 * @param wuidEnd Last WUID of the pool (first is 9000000).
 */
void prepareRoaming(P25HostHarness& harness, bool allow, const std::vector<uint32_t>& sysIds, uint32_t wuidEnd = 9000010U)
{
    HostTestHooks::p25SetSiteData(*harness.m_control, p25::SiteData(0xBB800U, 0x001U, 1U, 1U, 1U, 1U, 1U, 0x00U, 0));
    REQUIRE(HostTestHooks::p25ConfigureRoaming(*harness.m_control, allow, sysIds, 9000000U, wuidEnd));
}
```

(`P25HostHarness` is declared after the anonymous namespace; place `prepareRoaming` after the `P25HostHarness` class as a `static` free function.)

```cpp
TEST_CASE("P25 roaming registration outcomes", "[p25][host][roaming][registration]")
{
    const p25::SiteData previous = p25::lc::TSBK::getSiteData();
    P25HostHarness harness;
    uint8_t raw[p25::defines::P25_TSBK_LENGTH_BYTES];
    uint8_t rsp[p25::defines::P25_TSBK_LENGTH_BYTES];
    bool pduSeen = false;

    SECTION("Home_SU_Accepted_With_Unit_ID_As_WUID") {
        prepareRoaming(harness, true, {});
        buildUnitRegRequest(0xBB800U, 0x001U, 1001U, raw);
        REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
        REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_U_REG, rsp, pduSeen));
        CHECK(((rsp[2U] >> 4) & 0x03U) == p25::defines::ResponseCode::ACCEPT);
        CHECK(GET_UINT24(rsp, 7U) == 1001U);
        CHECK(HostTestHooks::p25IsUnitReg(*harness.m_control, 1001U));
    }

    SECTION("Home_Unit_ID_In_Pool_Refused") {
        prepareRoaming(harness, true, {});
        buildUnitRegRequest(0xBB800U, 0x001U, 9000005U, raw);
        REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
        REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_U_REG, rsp, pduSeen));
        CHECK(((rsp[2U] >> 4) & 0x03U) == p25::defines::ResponseCode::REFUSED);
        CHECK_FALSE(HostTestHooks::p25IsUnitReg(*harness.m_control, 9000005U));
    }

    SECTION("Foreign_WACN_Denied_With_Extended_Format") {
        prepareRoaming(harness, true, {});
        buildUnitRegRequest(0x12345U, 0x001U, 1001U, raw);
        REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
        CHECK_FALSE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_U_REG, rsp, pduSeen));
        CHECK(pduSeen);
        CHECK_FALSE(HostTestHooks::p25IsUnitReg(*harness.m_control, 1001U));
    }

    SECTION("Roaming_Disabled_Denied") {
        prepareRoaming(harness, false, {});
        buildUnitRegRequest(0xBB800U, 0x002U, 1001U, raw);
        REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
        REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_U_REG, rsp, pduSeen));
        CHECK(((rsp[2U] >> 4) & 0x03U) == p25::defines::ResponseCode::DENY);
        CHECK(((((uint32_t)rsp[2U] & 0x0FU) << 8) | rsp[3U]) == 0x002U);
        CHECK(GET_UINT24(rsp, 4U) == 1001U);
        CHECK(GET_UINT24(rsp, 7U) == 0U);
    }

    SECTION("System_ID_Not_Listed_Denied") {
        prepareRoaming(harness, true, { 0x003U });
        buildUnitRegRequest(0xBB800U, 0x002U, 1001U, raw);
        REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
        REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_U_REG, rsp, pduSeen));
        CHECK(((rsp[2U] >> 4) & 0x03U) == p25::defines::ResponseCode::DENY);
    }

    SECTION("Roaming_Accepted_With_Pool_WUID_And_Home_System_ID") {
        prepareRoaming(harness, true, {});
        buildUnitRegRequest(0xBB800U, 0x002U, 1001U, raw);
        REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
        REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_U_REG, rsp, pduSeen));
        CHECK(((rsp[2U] >> 4) & 0x03U) == p25::defines::ResponseCode::ACCEPT);
        CHECK(((((uint32_t)rsp[2U] & 0x0FU) << 8) | rsp[3U]) == 0x002U);
        CHECK(GET_UINT24(rsp, 4U) == 1001U);
        CHECK(GET_UINT24(rsp, 7U) == 9000000U);
        CHECK(HostTestHooks::p25IsUnitReg(*harness.m_control, 9000000U));
        CHECK_FALSE(HostTestHooks::p25IsUnitReg(*harness.m_control, 1001U));

        // re-registration retains the WUID
        REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
        REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_U_REG, rsp, pduSeen));
        CHECK(GET_UINT24(rsp, 7U) == 9000000U);
        CHECK(HostTestHooks::p25WuidLookup(*harness.m_control)->count() == 1U);
    }

    SECTION("Roaming_Ignores_LLA_Requirement") {
        prepareRoaming(harness, true, {});
        HostTestHooks::p25SetRequireLLAForReg(*harness.m_control, true);
        buildUnitRegRequest(0xBB800U, 0x002U, 1001U, raw);
        REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
        REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_U_REG, rsp, pduSeen));
        CHECK(((rsp[2U] >> 4) & 0x03U) == p25::defines::ResponseCode::ACCEPT);
        CHECK_FALSE(pduSeen);                                                       // no AUTH_DMD (AMBT)
    }

    SECTION("Pool_Exhaustion_Denied") {
        prepareRoaming(harness, true, {}, 9000000U);
        buildUnitRegRequest(0xBB800U, 0x002U, 1001U, raw);
        REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
        REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_U_REG, rsp, pduSeen));
        buildUnitRegRequest(0xBB800U, 0x002U, 1002U, raw);
        REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
        REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_U_REG, rsp, pduSeen));
        CHECK(((rsp[2U] >> 4) & 0x03U) == p25::defines::ResponseCode::DENY);
        CHECK(GET_UINT24(rsp, 7U) == 0U);
    }

    p25::lc::TSBK::setSiteData(previous);
}
```

Add the hook used above to `tests/host/HostTestHooks.h/.cpp` (documented like the others):

```cpp
/* Sets whether LLA is required before unit registration. */

void HostTestHooks::p25SetRequireLLAForReg(p25::Control& control, bool required)
{
    control.m_control->m_requireLLAForReg = required;
}
```

- [ ] **Step 2: Build and run to verify failure**

Run: `cmake --build build -j2 && ./build/dvmtests '[p25][host][roaming][registration]' --reporter compact`
Expected: FAIL (roaming accept is denied; foreign WACN is accepted; a home Unit ID inside the pool is accepted).

- [ ] **Step 3: Change the declaration**

In `src/host/p25/packet/ControlSignaling.h`, add `#include "p25/lookups/P25WuidLookup.h"` with the other project includes, and replace the `writeRF_TSDU_U_Reg_Rsp(uint32_t srcId, uint32_t sysId)` declaration and its Doxygen with:

```cpp
            /**
             * @brief Helper to write a unit registration response packet.
             *  Classifies the request as foreign WACN, Home SU, or roaming SU (TIA-102.AABD-B 6.2, 6.4.1.1).
             * @param suid SUID (WACN ID, System ID, Unit ID) from the unit registration request.
             */
            void writeRF_TSDU_U_Reg_Rsp(const lookups::P25WuidLookup::SUID& suid);
```

- [ ] **Step 4: Update the callers**

In the `IOSP_U_REG` case, replace `writeRF_TSDU_U_Reg_Rsp(srcId, tsbk->getSysId());` with:

```cpp
                    lookups::P25WuidLookup::SUID suid = { tsbk->getNetId(), tsbk->getSysId(), srcId };
                    writeRF_TSDU_U_Reg_Rsp(suid);
```

and make the LLA branch apply to Home SUs only — replace:

```cpp
                if (m_requireLLAForReg) {
                    writeRF_TSDU_Auth_Dmd(srcId);
                }
                else {
```

with:

```cpp
                // roaming SUs are not LLA-authenticated; LLA keys are indexed by Home Unit ID
                const bool homeSU = (tsbk->getNetId() == m_p25->m_siteData.netId()) &&
                    (tsbk->getSysId() == m_p25->m_siteData.sysId());
                if (m_requireLLAForReg && homeSU) {
                    writeRF_TSDU_Auth_Dmd(srcId);
                }
                else {
```

In the `ISP_AUTH_RESP` success path, replace `writeRF_TSDU_U_Reg_Rsp(srcId, m_p25->m_siteData.sysId());` with:

```cpp
                        lookups::P25WuidLookup::SUID suid = { m_p25->m_siteData.netId(), m_p25->m_siteData.sysId(), srcId };
                        writeRF_TSDU_U_Reg_Rsp(suid);
```

- [ ] **Step 5: Replace `writeRF_TSDU_U_Reg_Rsp`**

Replace the whole function (`/* Helper to write a unit registration response packet. */` through its closing brace) with:

```cpp
/* Helper to write a unit registration response packet. */

void ControlSignaling::writeRF_TSDU_U_Reg_Rsp(const lookups::P25WuidLookup::SUID& suid)
{
    const uint32_t unitId = suid.unitId;

    /*
    ** Roaming admission failures answer REG_DENY rather than REG_REFUSED. REG_REFUSED may place the SU
    ** in the "Invalid ID" state awaiting user input (TIA-102.AABD-B 6.4.1.2 e), stranding a roaming SU on
    ** a system that will not serve it; REG_DENY returns it to control channel hunting (6.4.1.2 b).
    */

    // a SU from another WACN requires the extended format response (TIA-102.AABC-D 6.2.21.2)
    if (suid.netId != m_p25->m_siteData.netId()) {
        std::unique_ptr<MBT_OSP_U_REG_RSP> osp = std::make_unique<MBT_OSP_U_REG_RSP>();
        osp->setMFId(transactionMFId(unitId, unitId, TSBKO::IOSP_U_REG, m_lastMFID));
        osp->setSUIDNetId(suid.netId);
        osp->setSUIDSysId(suid.sysId);
        osp->setDstId(unitId);
        osp->setSrcId(0U);                                                          // "No one" (TIA-102.BAAC-C), no WUID assigned
        osp->setResponse(ResponseCode::DENY);

        LogWarning(LOG_RF, P25_TSDU_STR ", %s denial, WACN rejection, netId = $%05X, sysId = $%03X, unitId = %u",
            osp->toString().c_str(), suid.netId, suid.sysId, unitId);
        ::ActivityLogEx(LOG_P25, true, "unit registration request from %u ($%05X.$%03X) denied, foreign WACN", unitId, suid.netId, suid.sysId);

        writeRF_TSDU_AMBT(osp.get(), true);
        return;
    }

    std::unique_ptr<IOSP_U_REG> iosp = std::make_unique<IOSP_U_REG>();
    iosp->setMFId(transactionMFId(unitId, unitId, TSBKO::IOSP_U_REG, m_lastMFID));
    iosp->setResponse(ResponseCode::ACCEPT);
    iosp->setSUIDSysId(suid.sysId);
    iosp->setDstId(unitId);                                                         // Source ID (SUID Unit ID)

    // roaming SU -- same WACN, different home System ID (TIA-102.AABD-B 6.2)
    if (suid.sysId != m_p25->m_siteData.sysId()) {
        uint32_t wuid = 0U;
        const char* reason = nullptr;

        if (!m_p25->m_allowRoaming) {
            iosp->setResponse(ResponseCode::DENY);
            reason = "roaming disabled";
        }
        else if (!m_p25->m_roamingSysIds.empty() &&
            std::find(m_p25->m_roamingSysIds.begin(), m_p25->m_roamingSysIds.end(), suid.sysId) == m_p25->m_roamingSysIds.end()) {
            iosp->setResponse(ResponseCode::DENY);
            reason = "home System ID not permitted";
        }
        else {
            wuid = m_p25->m_wuidLookup->allocate(suid);
            if (wuid == 0U) {
                // no WUID can be assigned, so REG_FAIL is not possible; REG_DENY lets the SU try another site
                iosp->setResponse(ResponseCode::DENY);
                reason = "roaming WUID pool exhausted";
            }
        }

        iosp->setSrcId(wuid);                                                       // Source Address (WUID, or "No one")

        if (iosp->getResponse() != ResponseCode::ACCEPT) {
            LogWarning(LOG_RF, P25_TSDU_STR ", %s denial, %s, netId = $%05X, sysId = $%03X, unitId = %u",
                iosp->toString().c_str(), reason, suid.netId, suid.sysId, unitId);
            ::ActivityLogEx(LOG_P25, true, "unit registration request from %u ($%05X.$%03X) denied, %s", unitId, suid.netId, suid.sysId, reason);
        }
        else {
            if (m_verbose) {
                LogInfoEx(LOG_RF, P25_TSDU_STR ", %s, roaming, netId = $%05X, sysId = $%03X, unitId = %u, wuid = %u",
                    iosp->toString().c_str(), suid.netId, suid.sysId, unitId, wuid);
            }

            ::ActivityLogEx(LOG_P25, true, "unit registration request from %u ($%05X.$%03X), roaming, wuid = %u", unitId, suid.netId, suid.sysId, wuid);

            // the WUID is local until roaming identity translation exists; it is not announced to the network
            if (m_p25->m_affiliations->isUnitReg(wuid)) {
                m_p25->m_affiliations->touchUnitRegTimer(wuid);
            }
            else {
                m_p25->m_affiliations->unitReg(wuid);
            }
        }

        writeRF_TSDU_SBF_Imm(iosp.get(), true);
        return;
    }

    // Home SU -- the WUID is the Unit ID (TIA-102.AABD-B 6.2)
    iosp->setSrcId(unitId);

    // a home Unit ID inside the roaming pool would collide with roaming WUIDs
    if (m_p25->m_wuidLookup->isPoolWuid(unitId)) {
        LogWarning(LOG_RF, P25_TSDU_STR ", %s denial, home unit ID inside roaming WUID pool, unitId = %u", iosp->toString().c_str(), unitId);
        ::ActivityLogEx(LOG_P25, true, "unit registration request from %u refused, unit ID conflicts with roaming WUID pool", unitId);
        iosp->setResponse(ResponseCode::REFUSED);
        writeRF_TSDU_SBF_Imm(iosp.get(), true);
        return;
    }

    // validate the source RID
    if (!acl::AccessControl::validateSrcId(unitId)) {
        LogWarning(LOG_RF, P25_TSDU_STR ", %s denial, RID rejection, srcId = %u", iosp->toString().c_str(), unitId);
        ::ActivityLogEx(LOG_P25, true, "unit registration request from %u denied", unitId);
        iosp->setResponse(ResponseCode::REFUSED);
    }

    if (iosp->getResponse() == ResponseCode::ACCEPT) {
        if (m_verbose) {
            LogInfoEx(LOG_RF, P25_TSDU_STR ", %s, srcId = %u, sysId = $%03X", iosp->toString().c_str(), unitId, suid.sysId);
        }

        ::ActivityLogEx(LOG_P25, true, "unit registration request from %u", unitId);

        // update dynamic unit registration table
        if (!m_p25->m_affiliations->isUnitReg(unitId)) {
            m_p25->m_affiliations->unitReg(unitId);
        }

        if (m_p25->m_network != nullptr)
            m_p25->m_network->announceUnitRegistration(unitId);
    }

    writeRF_TSDU_SBF_Imm(iosp.get(), true);

    // validate the source RID
    if (!acl::AccessControl::validateSrcId(unitId)) {
        denialInhibit(unitId); // inhibit source radio automatically
    }
}
```

Ensure `ControlSignaling.cpp` includes `common/p25/lc/tsbk/TSBKFactory.h` (it already uses MBT types such as `MBT_OSP_AUTH_DMD`) and `<algorithm>` for `std::find` (add to its standard include group if missing).

- [ ] **Step 6: Run tests**

Run: `cmake --build build -j2 && ./build/dvmtests '[p25][host]' --reporter compact`
Expected: all pass. Then run `./build/dvmtests '[p25]' --reporter compact` to confirm no regressions (the removed SYSID-rejection branch is replaced by the roaming classification).

- [ ] **Step 7: Commit**

```bash
git add src/host/p25/packet/ControlSignaling.h src/host/p25/packet/ControlSignaling.cpp tests/host/HostTestHooks.h tests/host/HostTestHooks.cpp tests/p25/HostControl_Tests.cpp
git commit -m "classify P25 unit registrations as home, roaming or foreign WACN; assign roaming WUIDs from the pool, deny foreign WACN with the extended response, keep REG_DENY for disallowed systems so roaming SUs return to hunting per TIA-102.AABD-B 6.4.1.2;"
```

---

### Task 7: Roaming service gate and network suppression

**Files:**
- Modify: `src/host/p25/packet/ControlSignaling.h`, `src/host/p25/packet/ControlSignaling.cpp`
- Modify: `src/host/p25/packet/Voice.cpp` (`Voice::writeNetwork` ~1484; grant-demand block ~400–412)
- Modify: `src/host/p25/packet/Data.cpp` (`Data::writeNetwork` ~1003)
- Test: `tests/p25/HostControl_Tests.cpp`

**Interfaces:**
- Consumes: Tasks 4–6.
- Produces:
  - `bool ControlSignaling::processRoamingUnit(lc::TSBK* tsbk, uint32_t srcId, uint32_t dstId, bool& handled);` — returns true when the TSBK may continue to the normal switch; sets `handled` when the gate fully processed (answered/ignored) it.
  - `writeRF_TSDU_Deny(..., bool noNet = false)` — new trailing parameter.

Gate policy (checked only when `m_p25->m_wuidLookup->isPoolWuid(srcId)` and the LCO is not `IOSP_U_REG`, whose Source ID is a SUID Unit ID, not a WUID):

| LCO | Action |
| --- | --- |
| any, WUID not assigned (`findByWuid` false) or not registered | `writeRF_TSDU_U_Reg_Cmd(srcId)`; handled (AABD §6.6.1) |
| `IOSP_GRP_AFF`, `ISP_LOC_REG_REQ`, `ISP_U_DEREG_REQ` | `touchUnitRegTimer(srcId)`; continue to switch (helpers suppress network) |
| `ISP_EMERG_ALRM_REQ` | `writeRF_TSDU_ACK_FNE(srcId, ISP_EMERG_ALRM_REQ, false, true)`; warning + activity log with SUID, WUID, site; handled; not forwarded |
| `IOSP_ACK_RSP`, `ISP_STS_Q_RSP`, `ISP_GRP_AFF_Q_RSP`, `ISP_AUTH_RESP`, `IOSP_RAD_MON` | responses: log at verbose, ignore; handled |
| everything else | `writeRF_TSDU_Deny(srcId, WUID_FNE, ReasonCode::DENY_SYS_UNSUPPORTED_SVC, lco, false, false, true)`; warning "roaming unit service not supported (requires roaming translation)"; handled |

- [ ] **Step 1: Write the failing tests**

Add to `tests/p25/HostControl_Tests.cpp` (reuse `buildUnitRegRequest`, `drainForTSBK`, `prepareRoaming`, existing `buildUUVchRequest`, `buildEmergencyAlarmRequest`). Add a builder for group affiliation:

```cpp
/**
 * @brief Builds an independently encoded abbreviated GRP_AFF_REQ ISP TSBK (TIA-102.AABC-D Figure 6.1.9-1).
 * @param srcId Source Address (WUID).
 * @param sysId Group home System ID.
 * @param groupId Group ID.
 * @param raw The buffer to store the constructed TSBK.
 */
void buildGroupAffRequest(uint32_t srcId, uint32_t sysId, uint16_t groupId, uint8_t* raw)
{
    ::memset(raw, 0x00U, p25::defines::P25_TSBK_LENGTH_BYTES);
    raw[0U] = 0x80U | p25::defines::TSBKO::IOSP_GRP_AFF;
    raw[1U] = p25::defines::MFG_STANDARD;
    raw[3U] = (sysId >> 8) & 0x0FU;                                                 // System ID (b11-b8)
    raw[4U] = sysId & 0xFFU;                                                        // System ID (b7-b0)
    raw[5U] = (groupId >> 8) & 0xFFU;                                               // Group ID
    raw[6U] = groupId & 0xFFU;
    SET_UINT24(srcId, raw, 7U);                                                     // Source Address
    edac::CRC::addCCITT162(raw, p25::defines::P25_TSBK_LENGTH_BYTES);
}
```

Cross-check the byte layout against `IOSP_GRP_AFF::decode()` (`m_sysId = (tsbkValue >> 40) & 0xFFFU; m_dstId = (tsbkValue >> 24) & 0xFFFFU;`) — octets 3–4 hold System ID, octets 5–6 Group ID, octets 7–9 Source Address.

```cpp
TEST_CASE("P25 roaming unit services before identity translation", "[p25][host][roaming][services]")
{
    const p25::SiteData previous = p25::lc::TSBK::getSiteData();
    const uint16_t localPort = reserveLoopbackPort();
    REQUIRE(localPort != 0U);
    P25HostHarness harness(true, true, localPort);
    harness.network()->activateForTest();
    prepareRoaming(harness, true, {});

    uint8_t raw[p25::defines::P25_TSBK_LENGTH_BYTES];
    uint8_t rsp[p25::defines::P25_TSBK_LENGTH_BYTES];
    bool pduSeen = false;

    // register a roaming SU; it receives WUID 9000000
    buildUnitRegRequest(0xBB800U, 0x002U, 1001U, raw);
    REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
    REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_U_REG, rsp, pduSeen));
    REQUIRE(GET_UINT24(rsp, 7U) == 9000000U);
    const uint32_t tsduBefore = harness.network()->tsduWriteCount();

    SECTION("Group_Affiliation_Local_Only") {
        HostTestHooks::p25SetIgnoreAffiliationCheck(*harness.m_control, true);
        buildGroupAffRequest(9000000U, 0x002U, 2001U, raw);
        REQUIRE(HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw));
        REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_GRP_AFF, rsp, pduSeen));
        CHECK(harness.network()->tsduWriteCount() == tsduBefore);
    }

    SECTION("Voice_Request_Denied_Unsupported") {
        buildUUVchRequest(9000000U, 1002U, raw);
        HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw);
        REQUIRE(drainForTSBK(*harness.m_control, p25::defines::TSBKO::OSP_DENY_RSP, rsp, pduSeen));
        CHECK(rsp[3U] == p25::defines::ReasonCode::DENY_SYS_UNSUPPORTED_SVC);
        CHECK(harness.network()->tsduWriteCount() == tsduBefore);
    }

    SECTION("Emergency_Alarm_Acknowledged_Not_Forwarded") {
        buildEmergencyAlarmRequest(9000000U, 2001U, 0x00U, 0x00U, raw);
        HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw);
        CHECK(drainForTSBK(*harness.m_control, p25::defines::TSBKO::IOSP_ACK_RSP, rsp, pduSeen));
        CHECK(harness.network()->tsduWriteCount() == tsduBefore);
    }

    SECTION("Unassigned_Pool_WUID_Commanded_To_Register") {
        buildUUVchRequest(9000005U, 1002U, raw);
        HostTestHooks::p25ProcessRawTSBK(*harness.m_control, raw);
        CHECK(drainForTSBK(*harness.m_control, p25::defines::TSBKO::OSP_U_REG_CMD, rsp, pduSeen));
    }

    p25::lc::TSBK::setSiteData(previous);
}
```

Before relying on these assertions:
- Verify `rsp[3U]` is the DENY_RSP reason octet by reading `OSP_DENY_RSP::encode()`; use the octet index it actually writes the reason to.
- Verify the ACK_RSP_FNE LCO constant name (`grep -n "ACK_RSP" src/common/p25/P25Defines.h`) and the U_REG_CMD constant name (`grep -n "U_REG_CMD" src/common/p25/P25Defines.h`).
- Verify the network harness path: `P25HostHarness(true, true, localPort)` plus `activateForTest()` is how the existing "radio-check responses are forwarded" test (line ~678) observes network TSDUs; mirror that setup exactly.
- Add `HostTestHooks::p25SetIgnoreAffiliationCheck(p25::Control&, bool)` setting `control.m_ignoreAffiliationCheck`, documented like the other hooks, only if the group affiliation response otherwise depends on TG configuration in the harness.

- [ ] **Step 2: Build and run to verify failure**

Run: `cmake --build build -j2 && ./build/dvmtests '[p25][host][roaming][services]' --reporter compact`
Expected: FAIL (voice request is processed normally; network writes increase).

- [ ] **Step 3: Add the deny `noNet` parameter**

In `ControlSignaling.h`, extend the `writeRF_TSDU_Deny` declaration and its Doxygen:

```cpp
             * @param noNet Flag indicating the deny response must not be mirrored to the network.
             */
            void writeRF_TSDU_Deny(uint32_t srcId, uint32_t dstId, uint8_t reason, uint8_t service, bool grp = false, bool aiv = false, bool noNet = false);
```

In `ControlSignaling.cpp`, update the definition signature and replace the final `writeRF_TSDU_SBF_Imm(osp.get(), false);` with `writeRF_TSDU_SBF_Imm(osp.get(), noNet);`. Also pass `noNet` to the ACK fallback: `writeRF_TSDU_ACK_FNE(srcId, service, aiv, noNet, false);` — confirm the ACK_FNE parameter order (`dstId, service, extended, noNetwork, ...`) from its declaration at `ControlSignaling.h:474` first.

- [ ] **Step 4: Declare and implement the gate**

In `ControlSignaling.h`, in the private member-function section, add:

```cpp
            /**
             * @brief Applies the roaming SU service policy to an inbound TSBK from a pool WUID.
             *  Until roaming identity translation exists, roaming SUs are served locally only and
             *  nothing carrying a pool WUID is written to the network.
             * @param tsbk Inbound TSBK.
             * @param srcId Source address (WUID) of the TSBK.
             * @param dstId Destination address of the TSBK.
             * @param[out] handled Set true when the gate fully processed the TSBK.
             * @returns bool True if the TSBK may continue to normal processing; otherwise, false.
             */
            bool processRoamingUnit(lc::TSBK* tsbk, uint32_t srcId, uint32_t dstId, bool& handled);
```

In `ControlSignaling.cpp` add (near the other private helpers):

```cpp
/* Applies the roaming SU service policy to an inbound TSBK from a pool WUID. */

bool ControlSignaling::processRoamingUnit(lc::TSBK* tsbk, uint32_t srcId, uint32_t dstId, bool& handled)
{
    assert(tsbk != nullptr);
    handled = false;

    const uint8_t lco = tsbk->getLCO();

    // an unassigned or expired WUID must re-register (TIA-102.AABD-B 6.6.1)
    lookups::P25WuidLookup::SUID suid;
    if (!m_p25->m_wuidLookup->findByWuid(srcId, suid) || !m_p25->m_affiliations->isUnitReg(srcId)) {
        LogWarning(LOG_RF, P25_TSDU_STR ", %s, unassigned roaming WUID, srcId = %u", tsbk->toString(true).c_str(), srcId);
        writeRF_TSDU_U_Reg_Cmd(srcId);
        handled = true;
        return false;
    }

    switch (lco) {
    case TSBKO::IOSP_GRP_AFF:
    case TSBKO::ISP_LOC_REG_REQ:
    case TSBKO::ISP_U_DEREG_REQ:
        m_p25->m_affiliations->touchUnitRegTimer(srcId);
        return true;

    case TSBKO::ISP_EMERG_ALRM_REQ:
        LogWarning(LOG_RF, P25_TSDU_STR ", %s, roaming unit emergency alarm, not forwarded (requires roaming translation), netId = $%05X, sysId = $%03X, unitId = %u, wuid = %u, siteId = $%02X",
            tsbk->toString(true).c_str(), suid.netId, suid.sysId, suid.unitId, srcId, m_p25->m_siteData.siteId());
        ::ActivityLogEx(LOG_P25, true, "emergency alarm request from roaming unit %u ($%05X.$%03X), wuid = %u, site $%02X, not forwarded",
            suid.unitId, suid.netId, suid.sysId, srcId, m_p25->m_siteData.siteId());
        writeRF_TSDU_ACK_FNE(srcId, TSBKO::ISP_EMERG_ALRM_REQ, false, true);
        handled = true;
        return false;

    case TSBKO::IOSP_ACK_RSP:
    case TSBKO::ISP_STS_Q_RSP:
    case TSBKO::ISP_GRP_AFF_Q_RSP:
    case TSBKO::ISP_AUTH_RESP:
    case TSBKO::IOSP_RAD_MON:
        if (m_verbose) {
            LogInfoEx(LOG_RF, P25_TSDU_STR ", %s, roaming unit response ignored, srcId = %u", tsbk->toString(true).c_str(), srcId);
        }
        handled = true;
        return false;

    default:
        LogWarning(LOG_RF, P25_TSDU_STR ", %s denial, roaming unit service not supported (requires roaming translation), netId = $%05X, sysId = $%03X, unitId = %u, wuid = %u, dstId = %u",
            tsbk->toString(true).c_str(), suid.netId, suid.sysId, suid.unitId, srcId, dstId);
        writeRF_TSDU_Deny(srcId, WUID_FNE, ReasonCode::DENY_SYS_UNSUPPORTED_SVC, lco, false, false, true);
        handled = true;
        return false;
    }
}
```

Confirm each `TSBKO::` constant above exists exactly as spelled (`grep -n "ISP_STS_Q_RSP\|ISP_GRP_AFF_Q_RSP\|ISP_AUTH_RESP\|IOSP_RAD_MON\|ISP_U_DEREG_REQ\|ISP_LOC_REG_REQ" src/common/p25/P25Defines.h`).

In `ControlSignaling::process()`, directly after `m_lastMFID = tsbk->getMFId();` (line ~234, RF path) add:

```cpp

        // roaming SUs are served locally until roaming identity translation exists
        if (tsbk->getLCO() != TSBKO::IOSP_U_REG && m_p25->m_wuidLookup->isPoolWuid(srcId)) {
            bool handled = false;
            if (!processRoamingUnit(tsbk.get(), srcId, dstId, handled)) {
                if (!m_p25->m_ccRunning) {
                    m_p25->writeRF_Nulls();
                }

                m_inbound = false;
                m_p25->m_rfState = prevRfState;
                return handled;
            }
        }
```

Confirm `m_inbound` is set to `true` earlier in this path (match the exit sequence at the end of the RF branch exactly).

- [ ] **Step 5: Suppress network effects in the allowed helpers**

In `writeRF_TSDU_Grp_Aff_Rsp`, after `bool noNet = false;` add:

```cpp
    // roaming SUs (pool WUIDs) are local only; they are not in the RID ACL and are not announced
    const bool roaming = m_p25->m_wuidLookup->isPoolWuid(srcId);
    if (roaming) {
        noNet = true;
    }
```

Then:
- Change the first RID check `if (!acl::AccessControl::validateSrcId(srcId)) {` to `if (!roaming && !acl::AccessControl::validateSrcId(srcId)) {`.
- Change the MFG_MOT DVRS block condition `if (!m_p25->m_affiliations->isUnitReg(srcId) && m_lastMFID == MFG_MOT) {` to `if (!roaming && !m_p25->m_affiliations->isUnitReg(srcId) && m_lastMFID == MFG_MOT) {`.
- Every `if (... && m_p25->m_network != nullptr) m_p25->m_network->announceGroupAffiliationRemoval(srcId);` and `if (m_p25->m_network != nullptr) m_p25->m_network->announceGroupAffiliation(srcId, dstId);` in this function gains `!roaming &&` in its condition.
- Every `writeRF_TSDU_Deny(srcId, WUID_FNE, ..., TSBKO::IOSP_GRP_AFF)` in this function becomes `writeRF_TSDU_Deny(srcId, WUID_FNE, ..., TSBKO::IOSP_GRP_AFF, false, false, roaming)`.
- Confirm the function's final RF write uses `noNet` (e.g. `writeRF_TSDU_SBF_Imm(iosp.get(), noNet)`); if it passes a literal, change it to `noNet`.

Log the group's home System ID for roaming SUs: in the `IOSP_GRP_AFF` case in `process()`, before `writeRF_TSDU_Grp_Aff_Rsp(srcId, dstId)`, add:

```cpp
                if (m_p25->m_wuidLookup->isPoolWuid(srcId)) {
                    LogInfoEx(LOG_RF, P25_TSDU_STR ", %s, roaming unit, group sysId = $%03X (foreign groups not translated), srcId = %u, dstId = %u",
                        tsbk->toString(true).c_str(), tsbk->getSysId(), srcId, dstId);
                }
```

In `writeRF_TSDU_Loc_Reg_Rsp`, apply the same pattern: declare `const bool roaming = m_p25->m_wuidLookup->isPoolWuid(srcId);`, set `noNet = true` when roaming, skip RID ACL validation when roaming, and add `!roaming &&` to the `announceGroupAffiliation` condition. (Read the full function first; it uses `noNet` and `writeRF_TSDU_SBF_Imm(osp.get(), noNet)`.)

In `writeRF_TSDU_U_Dereg_Ack`, replace `writeRF_TSDU_SBF_Imm(osp.get(), false);` with:

```cpp
        // roaming SU WUIDs are local only
        writeRF_TSDU_SBF_Imm(osp.get(), m_p25->m_wuidLookup->isPoolWuid(srcId));
```

Note: `unitDereg` here fires the Task 5 callback, which releases the WUID; read `isPoolWuid` (a range test) rather than `findByWuid`, so the order does not matter.

- [ ] **Step 6: Defensive guards in Voice and Data**

In `Voice::writeNetwork` (`Voice.cpp` ~1484), after the `m_network == nullptr` check add:

```cpp
    // roaming SU WUIDs are local only until roaming identity translation exists
    if (m_p25->m_wuidLookup->isPoolWuid(m_rfLC.getSrcId()))
        return;
```

In the RF grant-demand block (`Voice.cpp` ~400–412), change `if (m_p25->m_network != nullptr) {` to `if (m_p25->m_network != nullptr && !m_p25->m_wuidLookup->isPoolWuid(srcId)) {` (confirm the local variable is named `srcId` there).

In `Data::writeNetwork` (`Data.cpp` ~1003), after the `m_network == nullptr` check add:

```cpp
    // roaming SU WUIDs are local only until roaming identity translation exists
    if (m_p25->m_wuidLookup->isPoolWuid(m_rfAssembler->dataHeader.getLLId()))
        return;
```

Confirm `Voice` and `Data` access `m_p25->m_wuidLookup` via the existing `friend` declarations in `Control.h` (lines 296–305).

- [ ] **Step 7: Run tests**

Run: `cmake --build build -j2 && ./build/dvmtests '[p25][host]' --reporter compact`
Expected: all pass.
Then: `./build/dvmtests '[p25]' --reporter compact` and `./build/dvmtests --reporter compact`
Expected: all pass. Expected negative-test log lines are not failures; check the reported result.

- [ ] **Step 8: Commit**

```bash
git add src/host/p25/packet/ControlSignaling.h src/host/p25/packet/ControlSignaling.cpp src/host/p25/packet/Voice.cpp src/host/p25/packet/Data.cpp tests/host/HostTestHooks.h tests/host/HostTestHooks.cpp tests/p25/HostControl_Tests.cpp
git commit -m "serve roaming P25 units locally until identity translation exists; deny unsupported services, acknowledge and log emergency alarms without forwarding, command re-registration for unassigned WUIDs, and never write pool WUIDs to the network;"
```

---

### Task 8: Documentation and spec correction

**Files:**
- Create: `docs/P25 Roaming Registration.md`
- Modify: `docs/superpowers/specs/2026-11-13-p25-roaming-registration-design.md`

- [ ] **Step 1: Confirm the spec matches the implementation**

The spec was corrected during planning (configuration path, factory note, "No one" Source Address, ignored responses, REG_DENY policy). Re-read it against the implemented behavior; fix any divergence found during Tasks 1–7.

- [ ] **Step 2: Write the documentation**

Create `docs/P25 Roaming Registration.md`:

```markdown
# P25 Roaming Registration

This note describes how `dvmhost` registers P25 subscriber units (SUs) homed to another
System ID within the same WACN.

## Identity model

A P25 SU is identified by its SUID: WACN ID, System ID, and 24-bit Unit ID. A roaming SU
registers with its Home System identity (TIA-102.AABD-B 6.4.1). The registering site assigns
a locally significant Working Unit ID (WUID):

- A Home SU (same WACN ID and System ID as the site) uses its Unit ID as its WUID.
- A roaming SU (same WACN ID, different System ID) receives a WUID from the configured
  roaming pool (TIA-102.AABD-B 6.2).
- An SU from a different WACN is denied with the extended-format Unit Registration Response
  (TIA-102.AABC-D 6.2.21.2).

## Configuration (`protocols.p25`)

| Key | Default | Meaning |
| --- | --- | --- |
| `allowRoaming` | `false` | Allow SUs homed to other System IDs in this WACN to register. |
| `roamingSysIds` | `[]` | Home System IDs (hex strings) permitted to roam here; empty permits any System ID in this WACN. |
| `roamingWuidStart` | `0` | First WUID of the roaming pool (decimal, inclusive). |
| `roamingWuidEnd` | `0` | Last WUID of the roaming pool (decimal, inclusive). |

The pool must satisfy `0 < roamingWuidStart <= roamingWuidEnd` and lie below the reserved
special WUIDs. Every `roamingSysIds` entry must be a 12-bit value other than the site System ID.
Any error is logged and roaming stays disabled. A warning is logged if RID ACL entries fall
inside the pool; pool WUIDs must never be assigned to home radios, and a home SU whose Unit ID
lies inside the pool is refused.

## Admission order

1. Different WACN ID: REG_DENY (extended format).
2. Home SU: existing behavior (RID ACL, `requireLLAForReg`, automatic inhibit). A home Unit ID
   inside the roaming pool is answered with REG_REFUSED.
3. Roaming SU:
   - `allowRoaming` false: REG_DENY.
   - System ID not in a non-empty `roamingSysIds`: REG_DENY.
   - Pool exhausted: REG_DENY.
   - Otherwise REG_ACCEPT with the SU's Home System ID, Unit ID, and assigned WUID.

Roaming SUs are not checked against the RID ACL, are never automatically inhibited, and are not
LLA-authenticated even when `requireLLAForReg` is enabled. Admission relies only on the WACN ID
and `roamingSysIds`.

Roaming admission failures deliberately use REG_DENY rather than REG_REFUSED. An SU receiving
REG_REFUSED may enter the "Invalid ID" state and wait for user input (TIA-102.AABD-B 6.4.1.2),
which could strand a public-safety radio on a system that will not serve it. REG_DENY makes the
SU mark the site as denied and resume control channel hunting, so it finds its home system
without user action.

## Current limitations

Roaming SUs are served locally only until roaming identity translation is implemented:

- Group affiliation, location registration, and de-registration are processed locally and are
  not announced to the network.
- Voice, data, unit-to-unit, telephone interconnect, status, message, call alert, and extended
  function requests are denied with `DENY_SYS_UNSUPPORTED_SVC`.
- Emergency alarms are acknowledged and logged (warning and activity log with SUID, WUID, and
  site) but are not forwarded to the network.
- A request from an unassigned pool WUID is answered with a Unit Registration Command.

WUIDs are released on de-registration and WUID validity expiry (`wuidValidity`). The pool is held
in memory; a restart clears it and roaming SUs re-register.

## Subscriber programming

An SU must accept the site's WACN ID and System ID before it transmits on the control channel
(TIA-102.AABD-B 5.4.5). For Motorola APX radios this typically requires an intra-WACN roaming
coverage type, the site control channels in the radio's control channel list, and a NAC/System ID
combination that satisfies the radio's NAC validation setting.
```

- [ ] **Step 3: Full verification**

Run: `cmake --build build -j2 && ./build/dvmtests --reporter compact`
Expected: all tests pass. Record the summary line.

Run: `python3 -c "import yaml; yaml.safe_load(open('configs/config.example.yml'))" && echo OK`
Expected: `OK`.

Run: `git diff --check master...HEAD`
Expected: no whitespace errors.

- [ ] **Step 4: Commit**

```bash
git add "docs/P25 Roaming Registration.md" docs/superpowers/specs/2026-11-13-p25-roaming-registration-design.md
git commit -m "document P25 roaming registration and correct design spec configuration path and interim service details;"
```

---

## Out of Scope

WUID ↔ SUID translation on RF/network paths, FNE SUID awareness, foreign group handling, adjacent site table keying, foreign-WACN acceptance, ROAM_ADDR_CMD, LLA for roaming SUs, and emergency registration procedures (AABD §11.3.5) remain for later sub-projects.

Over-the-air validation with a Motorola APX on a live control channel is performed by the operator.
