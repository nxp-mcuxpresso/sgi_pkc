/*--------------------------------------------------------------------------*/
/* Copyright 2025 NXP                                                       */
/*                                                                          */
/* NXP Proprietary. This software is owned or controlled by NXP and may     */
/* only be used strictly in accordance with the applicable license terms.   */
/* By expressly accepting such terms or by downloading, installing,         */
/* activating and/or otherwise using the software, you are agreeing that    */
/* you have read, and that you agree to comply with and are bound by, such  */
/* license terms. If you do not agree to be bound by the applicable license */
/* terms, then you may not retain, install, activate or otherwise use the   */
/* software.                                                                */
/*--------------------------------------------------------------------------*/

#include <mcuxClHash.h>
#include <internal/mcuxClHash_Internal.h>

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_processedLength_add)
void mcuxClHash_processedLength_add(uint32_t *pLen128, uint32_t addLen)
{
    if(pLen128[0] > (UINT32_MAX - addLen))
    {
        if(pLen128[1] > (UINT32_MAX - 1u))
        {
            if(pLen128[2] > (UINT32_MAX - 1u))
            {
                pLen128[3]++;
            }
            pLen128[2]++;
        }
        pLen128[1]++;
    }
    pLen128[0] += addLen;
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_processedLength_cmp)
int mcuxClHash_processedLength_cmp(uint32_t *pLen128, uint32_t cmpLenLow32)
{
    if((pLen128[3] != 0u) || (pLen128[2] != 0u) || (pLen128[1] != 0u))
    {
        return 1;
    }
    return (pLen128[0] > cmpLenLow32)   ? 1 :
            (pLen128[0] == cmpLenLow32) ? 0 : -1;
}

MCUX_CSSL_FP_FUNCTION_DEF(mcuxClHash_processedLength_toBits)
void mcuxClHash_processedLength_toBits(uint32_t *pLen128)
{
  pLen128[3] = (pLen128[3] << 3u) | (pLen128[2] >> 29u);
  pLen128[2] = (pLen128[2] << 3u) | (pLen128[1] >> 29u);
  pLen128[1] = (pLen128[1] << 3u) | (pLen128[0] >> 29u);
  pLen128[0] = pLen128[0] << 3u;
}
