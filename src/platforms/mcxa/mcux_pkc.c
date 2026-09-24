/*
 *     Copyright 2026 NXP
 *     All rights reserved.
 *
 *     SPDX-License-Identifier: BSD-3-Clause
 */

#include "mcux_pkc.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/* The PKC fetches the UPTRT (the index operand table a FUP program refers to)
 * from the caller's CPU work area, which is an automatic (stack) buffer, so the
 * RAM holding it must have execute permission (XEN) enabled. The stack location
 * is not fixed: it depends on the linker layout and, under TF-M, on the secure
 * data region placed by region_defs.h, so no single bank can be selected at
 * build time that is guaranteed to cover it.
 *
 * NOTE: this makes the whole System RAM executable for the lifetime of the
 * device, which is a deliberate trade of exposure for simplicity - data pages
 * (.data, .bss, heap, DMA and communication buffers) become valid execution
 * targets, so code-injection attacks no longer need an executable-memory
 * primitive. Under TF-M the MPU still marks secure RAM execute-never
 * (MPU_ARMV8M_XN_EXEC_NEVER) at isolation levels 2 and 3, which keeps a second
 * barrier in place; bare-metal builds that configure no MPU have none.
 *
 * An integrator who knows where the stack is placed in their application can
 * and should narrow this down: replace PKC_SRAM_XEN_ALL_MASK /
 * PKC_SRAM_XEN_DP_ALL_MASK with only the bank(s) the stack actually occupies
 * (for example SYSCON_SRAM_XEN_RAMC_XEN_MASK alone for the default bare-metal
 * layout, where the stack lives in RAM C3 at 0x20038000 - 0x2003BFFF). That
 * keeps the executable window as small as the application allows. Once the
 * final bank set is established, the permissions can also be sealed by setting
 * SYSCON_SRAM_XEN_LOCK_MASK. */

/* Execute permission for every implemented RAM bank in SYSCON->SRAM_XEN. */
#define PKC_SRAM_XEN_ALL_MASK                                          \
    (SYSCON_SRAM_XEN_RAMX0_XEN_MASK | SYSCON_SRAM_XEN_RAMX1_XEN_MASK | \
     SYSCON_SRAM_XEN_RAMA0_XEN_MASK | SYSCON_SRAM_XEN_RAMA1_XEN_MASK | \
     SYSCON_SRAM_XEN_RAMB_XEN_MASK | SYSCON_SRAM_XEN_RAMC_XEN_MASK)

/* Same bank set for the Glikey-protected duplicate SYSCON->SRAM_XEN_DP. */
#define PKC_SRAM_XEN_DP_ALL_MASK                                             \
    (SYSCON_SRAM_XEN_DP_RAMX0_XEN_MASK | SYSCON_SRAM_XEN_DP_RAMX1_XEN_MASK | \
     SYSCON_SRAM_XEN_DP_RAMA0_XEN_MASK | SYSCON_SRAM_XEN_DP_RAMA1_XEN_MASK | \
     SYSCON_SRAM_XEN_DP_RAMB_XEN_MASK | SYSCON_SRAM_XEN_DP_RAMC_XEN_MASK)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
/*******************************************************************************
 * Code
 ******************************************************************************/
static status_t GlikeyWriteEnable(GLIKEY_Type *base, uint8_t idx)
{
    if (kStatus_Success != GLIKEY_StartEnable(base, idx))
    {
        return kStatus_Fail;
    }
    if (kStatus_Success != GLIKEY_ContinueEnable(base, GLIKEY_CODEWORD_STEP1))
    {
        return kStatus_Fail;
    }
    if (kStatus_Success != GLIKEY_ContinueEnable(base, GLIKEY_CODEWORD_STEP2))
    {
        return kStatus_Fail;
    }
    if (kStatus_Success != GLIKEY_ContinueEnable(base, GLIKEY_CODEWORD_STEP3))
    {
        return kStatus_Fail;
    }
    if (kStatus_Success != GLIKEY_ContinueEnable(base, GLIKEY_CODEWORD_STEP_EN))
    {
        return kStatus_Fail;
    }

    return kStatus_Success;
}
/*!
 * brief PKC Init after power down.
 *
 * This function enables RAM interleave, RAM execute permission, clocks, zeroize the PKC RAM and reset PKC peripheral.
 *
 * param base PKC peripheral address.
 *
 * return kStatus_Success upon success, kStatus_Fail otherwise
 */
status_t PKC_PowerDownWakeupInit(PKC_Type *base)
{
    status_t status = kStatus_Fail;

    status = PKC_InitNoZeroize(PKC0);
    if (status != kStatus_Success)
    {
        return status;
    }

    /* Zeroize the PKC RAM */
    for (uint32_t i = 0; i < PKC_RAM_SIZE / sizeof(uint32_t); i++)
    {
        ((uint32_t *)PKC_RAM_ADDR)[i] = 0x0;
    }

    return kStatus_Success;
}

/*!
 * brief PKC Init after power down.
 *
 * This function enables RAM interleave, RAM execute permission, clocks and reset PKC peripheral.
 *
 * param base PKC peripheral address.
 *
 * return kStatus_Success upon success, kStatus_Fail otherwise
 */
status_t PKC_InitNoZeroize(PKC_Type *base)
{
    status_t status = kStatus_Fail;
    /* Turn on PKC RAM inteleaving. This setting is need for PKC L0 memory access. */
#if defined(SYSCON_RAM_INTERLEAVE_INTERLEAVE_MASK) && SYSCON_RAM_INTERLEAVE_INTERLEAVE_MASK
    SYSCON->RAM_INTERLEAVE |= SYSCON_RAM_INTERLEAVE_INTERLEAVE_MASK;
#endif

    /* Reset PKC */
    RESET_ReleasePeripheralReset(kPKC0_RST_SHIFT_RSTn);
    /* Enable PKC clock */
    CLOCK_EnableClock(kCLOCK_GatePKC0);

    /* By default SRAM has R/W enabled, execute permission is disabled. Enable
     * execute permission for every RAM bank so the PKC can fetch its FUP
     * program regardless of where the linker or TF-M placed the stack that
     * holds the UPTRT. See PKC_SRAM_XEN_ALL_MASK for the exposure trade-off and
     * for how an integrator can narrow this to the stack's bank(s). */
    SYSCON->SRAM_XEN |= PKC_SRAM_XEN_ALL_MASK;

    /* SRAM_XEN is duplicated by SRAM_XEN_DP which is protected by Glikey, SRAM_XEN_DP is protected by Glikey, enable
     * write, and write same value as in SRAM_XEN register */
    status = GLIKEY_SyncReset(GLIKEY0);
    if (status != kStatus_Success)
    {
        return status;
    }

    /* Move Glikey FSM to write enable */
    status = GlikeyWriteEnable(GLIKEY0, 2u);
    if (status != kStatus_Success)
    {
        return status;
    }

    /* Write the same bank set into SRAM_XEN_DP */
    SYSCON->SRAM_XEN_DP |= PKC_SRAM_XEN_DP_ALL_MASK;

    /* End of write enable */
    status = GLIKEY_EndOperation(GLIKEY0);
    if (status != kStatus_Success)
    {
        return status;
    }

    return kStatus_Success;
}
