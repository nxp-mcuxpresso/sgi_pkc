#---------------------------------------------
# Copyright 2026 NXP.
# SPDX-License-Identifier: BSD-3-Clause
#---------------------------------------------
if(CONFIG_SGI_PKC)

# Set base path for the SGI PKC component
set(SGI_PKC_BASE ${CMAKE_CURRENT_LIST_DIR}/../)

# Create single zephyr library for all SGI PKC components
zephyr_library()

# Common include directories - always added and visible globally
zephyr_include_directories(
    ${SGI_PKC_BASE}/includes
    ${SGI_PKC_BASE}/src/inc
    ${SGI_PKC_BASE}/src/compiler
)

# Platform MCXA
if(CONFIG_SGI_PKC_PLATFORM_MCXA)    
    zephyr_include_directories(
        ${SGI_PKC_BASE}/includes/platform/mcxa
    )

endif()

# Platform MCXL
if(CONFIG_SGI_PKC_PLATFORM_MCXL)
    zephyr_include_directories(
        ${SGI_PKC_BASE}/includes/platform/mcxl
    )
endif()

# Core component
if(CONFIG_SGI_PKC_CORE)
    zephyr_include_directories(${SGI_PKC_BASE}/src/comps/mcuxClCore/inc)
endif()

# AEAD component
if(CONFIG_SGI_PKC_AEAD)
    file(GLOB_RECURSE AEAD_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClAead/src/*.c)
    if(AEAD_SOURCES)
        zephyr_library_sources(${AEAD_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClAead/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClAead/inc/internal
    )
endif()

# AEAD Modes component
if(CONFIG_SGI_PKC_AEAD_MODES)
    file(GLOB_RECURSE AEAD_MODES_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClAeadModes/src/*.c)
    if(AEAD_MODES_SOURCES)
        zephyr_library_sources(${AEAD_MODES_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClAeadModes/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClAeadModes/inc/internal
    )
endif()

# AES component
if(CONFIG_SGI_PKC_AES)
    file(GLOB_RECURSE AES_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClAes/src/*.c)
    if(AES_SOURCES)
        zephyr_library_sources(${AES_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClAes/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClAes/inc/internal
    )
endif()

# Buffer component
if(CONFIG_SGI_PKC_BUFFER)
    file(GLOB_RECURSE BUFFER_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClBuffer/src/*.c)
    if(BUFFER_SOURCES)
        zephyr_library_sources(${BUFFER_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClBuffer/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClBuffer/inc/internal
    )
endif()

# Cipher component
if(CONFIG_SGI_PKC_CIPHER)
    file(GLOB_RECURSE CIPHER_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClCipher/src/*.c)
    if(CIPHER_SOURCES)
        zephyr_library_sources(${CIPHER_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClCipher/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClCipher/inc/internal
    )
endif()

# Cipher Modes component
if(CONFIG_SGI_PKC_CIPHER_MODES)
    file(GLOB_RECURSE CIPHER_MODES_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClCipherModes/src/*.c)
    if(CIPHER_MODES_SOURCES)
        zephyr_library_sources(${CIPHER_MODES_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClCipherModes/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClCipherModes/inc/internal
    )
endif()

# CRC component
if(CONFIG_SGI_PKC_CRC)
    file(GLOB_RECURSE CRC_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClCrc/src/*.c)
    if(CRC_SOURCES)
        zephyr_library_sources(${CRC_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClCrc/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClCrc/inc/internal
    )
endif()

# DMA component
if(CONFIG_SGI_PKC_DMA)
    file(GLOB_RECURSE DMA_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClDma/src/*.c)
    if(DMA_SOURCES)
        zephyr_library_sources(${DMA_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClDma/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClDma/inc/internal
    )
endif()

# ECC component
if(CONFIG_SGI_PKC_ECC)
    file(GLOB_RECURSE ECC_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClEcc/src/*.c)
    if(ECC_SOURCES)
        zephyr_library_sources(${ECC_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClEcc/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClEcc/inc/internal
    )
endif()

# FFDH component
if(CONFIG_SGI_PKC_FFDH)
    file(GLOB_RECURSE FFDH_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClFfdh/src/*.c)
    if(FFDH_SOURCES)
        zephyr_library_sources(${FFDH_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClFfdh/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClFfdh/inc/internal
    )
endif()

# Glikey component
if(CONFIG_SGI_PKC_GLIKEY)
    file(GLOB_RECURSE GLIKEY_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClGlikey/src/*.c)
    if(GLIKEY_SOURCES)
        zephyr_library_sources(${GLIKEY_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClGlikey/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClGlikey/inc/internal
    )
endif()

# Hash component
if(CONFIG_SGI_PKC_HASH)
    file(GLOB_RECURSE HASH_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClHash/src/*.c)
    if(HASH_SOURCES)
        zephyr_library_sources(${HASH_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClHash/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClHash/inc/internal
    )
endif()

# Hash Modes component
if(CONFIG_SGI_PKC_HASHMODES)
    file(GLOB_RECURSE HASHMODES_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClHashModes/src/*.c)
    if(HASHMODES_SOURCES)
        zephyr_library_sources(${HASHMODES_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClHashModes/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClHashModes/inc/internal
    )
endif()

# HMAC component
if(CONFIG_SGI_PKC_HMAC)
    file(GLOB_RECURSE HMAC_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClHmac/src/*.c)
    if(HMAC_SOURCES)
        zephyr_library_sources(${HMAC_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClHmac/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClHmac/inc/internal
    )
endif()

# Key component
if(CONFIG_SGI_PKC_KEY)
    file(GLOB_RECURSE KEY_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClKey/src/*.c)
    if(KEY_SOURCES)
        zephyr_library_sources(${KEY_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClKey/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClKey/inc/internal
    )
endif()

# MAC component
if(CONFIG_SGI_PKC_MAC)
    file(GLOB_RECURSE MAC_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClMac/src/*.c)
    if(MAC_SOURCES)
        zephyr_library_sources(${MAC_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClMac/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClMac/inc/internal
    )
endif()

# MAC Modes component
if(CONFIG_SGI_PKC_MAC_MODES)
    file(GLOB_RECURSE MAC_MODES_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClMacModes/src/*.c)
    if(MAC_MODES_SOURCES)
        zephyr_library_sources(${MAC_MODES_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClMacModes/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClMacModes/inc/internal
    )
endif()

# Math component
if(CONFIG_SGI_PKC_MATH)
    file(GLOB_RECURSE MATH_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClMath/src/*.c)
    if(MATH_SOURCES)
        zephyr_library_sources(${MATH_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClMath/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClMath/inc/internal
    )
endif()

# Memory component
if(CONFIG_SGI_PKC_MEMORY)
    file(GLOB_RECURSE MEMORY_C_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClMemory/src/*.c)
    file(GLOB_RECURSE CSSL_MEMORY_C_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxCsslMemory/src/*.c)
    file(GLOB_RECURSE CSSL_MEMORY_ASM_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxCsslMemory/src/asm/*.S)
    
    set(MEMORY_SOURCES ${MEMORY_C_SOURCES} ${CSSL_MEMORY_C_SOURCES} ${CSSL_MEMORY_ASM_SOURCES})
    if(MEMORY_SOURCES)
        zephyr_library_sources(${MEMORY_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClMemory/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClMemory/inc/internal
        ${SGI_PKC_BASE}/src/comps/mcuxCsslMemory/inc
        ${SGI_PKC_BASE}/src/comps/mcuxCsslMemory/inc/internal
    )
endif()

# Padding component
if(CONFIG_SGI_PKC_PADDING)
    file(GLOB_RECURSE PADDING_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClPadding/src/*.c)
    if(PADDING_SOURCES)
        zephyr_library_sources(${PADDING_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClPadding/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClPadding/inc/internal
    )
endif()

# PKC component
if(CONFIG_SGI_PKC_PKC)
    file(GLOB_RECURSE PKC_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClPkc/src/*.c)
    if(PKC_SOURCES)
        zephyr_library_sources(${PKC_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClPkc/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClPkc/inc/internal
    )
endif()

# PRNG component
if(CONFIG_SGI_PKC_PRNG)
    file(GLOB_RECURSE PRNG_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClPrng/src/*.c)
    if(PRNG_SOURCES)
        zephyr_library_sources(${PRNG_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClPrng/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClPrng/inc/internal
    )
endif()

# Random component
if(CONFIG_SGI_PKC_RANDOM)
    file(GLOB_RECURSE RANDOM_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClRandom/src/*.c)
    if(RANDOM_SOURCES)
        zephyr_library_sources(${RANDOM_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClRandom/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClRandom/inc/internal
    )
endif()

# Random Modes component
if(CONFIG_SGI_PKC_RANDOM_MODES)
    file(GLOB_RECURSE RANDOM_MODES_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClRandomModes/src/*.c)
    if(RANDOM_MODES_SOURCES)
        zephyr_library_sources(${RANDOM_MODES_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClRandomModes/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClRandomModes/inc/internal
    )
endif()

# Resource component
if(CONFIG_SGI_PKC_RESOURCE)
    file(GLOB_RECURSE RESOURCE_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClResource/src/*.c)
    if(RESOURCE_SOURCES)
        zephyr_library_sources(${RESOURCE_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClResource/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClResource/inc/internal
    )
endif()

# RSA component
if(CONFIG_SGI_PKC_RSA)
    file(GLOB_RECURSE RSA_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClRsa/src/*.c)
    if(RSA_SOURCES)
        zephyr_library_sources(${RSA_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClRsa/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClRsa/inc/internal
    )
endif()

# Session component
if(CONFIG_SGI_PKC_SESSION)
    file(GLOB_RECURSE SESSION_C_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClSession/src/*.c)
    file(GLOB_RECURSE SESSION_ASM_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClSession/src/asm/*.S)
    
    set(SESSION_SOURCES ${SESSION_C_SOURCES} ${SESSION_ASM_SOURCES})
    if(SESSION_SOURCES)
        zephyr_library_sources(${SESSION_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClSession/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClSession/inc/internal
    )
endif()

# SGI component
if(CONFIG_SGI_PKC_SGI)
    file(GLOB_RECURSE SGI_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClSgi/src/*.c)
    if(SGI_SOURCES)
        zephyr_library_sources(${SGI_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClSgi/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClSgi/inc/internal
    )
endif()

# Signature component
if(CONFIG_SGI_PKC_SIGNATURE)
    file(GLOB_RECURSE SIGNATURE_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClSignature/src/*.c)
    if(SIGNATURE_SOURCES)
        zephyr_library_sources(${SIGNATURE_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClSignature/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClSignature/inc/internal
    )
endif()

# TRNG component
if(CONFIG_SGI_PKC_TRNG)
    file(GLOB_RECURSE TRNG_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxClTrng/src/*.c)
    if(TRNG_SOURCES)
        zephyr_library_sources(${TRNG_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxClTrng/inc
        ${SGI_PKC_BASE}/src/comps/mcuxClTrng/inc/internal
    )
endif()

# CSSL C Pre-Processor component
if(CONFIG_SGI_PKC_PRE_PROCESSOR)
    zephyr_include_directories(${SGI_PKC_BASE}/src/comps/mcuxCsslCPreProcessor/inc)
endif()

# CSSL Data Integrity component
if(CONFIG_SGI_PKC_DATA_INTEGRITY)
    zephyr_include_directories(${SGI_PKC_BASE}/src/comps/mcuxCsslDataIntegrity/inc)
endif()

# CSSL Flow Protection component
if(CONFIG_SGI_PKC_FLOW_PROTECTION)
    zephyr_include_directories(${SGI_PKC_BASE}/src/comps/mcuxCsslFlowProtection/inc)
endif()

# CSSL Param Integrity component
if(CONFIG_SGI_PKC_PARAM_INTEGRITY)
    file(GLOB_RECURSE PARAM_INTEGRITY_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxCsslParamIntegrity/src/*.c)
    if(PARAM_INTEGRITY_SOURCES)
        zephyr_library_sources(${PARAM_INTEGRITY_SOURCES})
    endif()
    zephyr_include_directories(${SGI_PKC_BASE}/src/comps/mcuxCsslParamIntegrity/inc)
endif()

# CSSL PRNG component
if(CONFIG_SGI_PKC_CSSL_PRNG)
    file(GLOB_RECURSE CSSL_PRNG_SOURCES ${SGI_PKC_BASE}/src/comps/mcuxCsslPrng/src/*.c)
    if(CSSL_PRNG_SOURCES)
        zephyr_library_sources(${CSSL_PRNG_SOURCES})
    endif()
    zephyr_include_directories(
        ${SGI_PKC_BASE}/src/comps/mcuxCsslPrng/inc
        ${SGI_PKC_BASE}/src/comps/mcuxCsslPrng/inc/internal
    )
endif()

# CSSL Secure Counter component
if(CONFIG_SGI_PKC_SECURE_COUNTER)
    zephyr_include_directories(${SGI_PKC_BASE}/src/comps/mcuxCsslSecureCounter/inc)
endif()


endif() ## SGI_PKC