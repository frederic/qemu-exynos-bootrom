/*
 *  Exynos4210 Advanced Crypto Engine (ACE) Emulation
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License as published by the
 *  Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This model implements ACE registers just as a bulk of memory. Currently,
 * the only reason this device exists is that secondary CPU boot loader
 * uses ACE INFORM5 register as a holding pen.
 */

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "sysemu/sysemu.h"
#include "crypto/aes.h"

//include definition of ACE registers for EXYNOS4 platform
#define CONFIG_ARCH_EXYNOS4		1
#include "hw/misc/ace_sfr.h"

#define DEBUG_ACE           1
#define DEBUG_ACE_EXTEND    1

#ifndef DEBUG_ACE
#define DEBUG_ACE           0
#endif

#ifndef DEBUG_ACE_EXTEND
#define DEBUG_ACE_EXTEND    0
#endif

#if DEBUG_ACE
#define  PRINT_DEBUG(fmt, args...)  \
        do { \
            fprintf(stderr, "  [%s:%d]   "fmt, __func__, __LINE__, ##args); \
        } while (0)

#if DEBUG_ACE_EXTEND
#define  PRINT_DEBUG_EXTEND(fmt, args...) \
        do { \
            fprintf(stderr, "  [%s:%d]   "fmt, __func__, __LINE__, ##args); \
        } while (0)
#else
#define  PRINT_DEBUG_EXTEND(fmt, args...)  do {} while (0)
#endif /* EXTEND */

#else
#define  PRINT_DEBUG(fmt, args...)   do {} while (0)
#define  PRINT_DEBUG_EXTEND(fmt, args...)  do {} while (0)
#endif

#define EXYNOS4210_ACE_REGS_MEM_SIZE 0x1000

static uint64_t exynos4210_ace_read(void *opaque, hwaddr offset,
                                    unsigned size);

typedef struct Exynos4210AceReg {
    const char  *name; /* for debug only */
    uint32_t     offset;
    uint32_t     reset_value;
} Exynos4210AceReg;

// $ awk -F' ' '{printf "{\"%s\", %s, 0x00000000},\n",$2,$2}' ace_regs_exynos4210.h
static const Exynos4210AceReg exynos4210_ace_regs[] = {
	{"ACE_FC_INTSTAT", ACE_FC_INTSTAT, 0x00000000},
	{"ACE_FC_INTENSET", ACE_FC_INTENSET, 0x00000000},
	{"ACE_FC_INTENCLR", ACE_FC_INTENCLR, 0x00000000},
	{"ACE_FC_INTPEND", ACE_FC_INTPEND, 0x00000000},
	{"ACE_FC_FIFOSTAT", ACE_FC_FIFOSTAT, 0x00000000},
	{"ACE_FC_FIFOCTRL", ACE_FC_FIFOCTRL, 0x00000000},
	{"ACE_FC_GLOBAL", ACE_FC_GLOBAL, 0x00000000},
	{"ACE_FC_BRDMAS", ACE_FC_BRDMAS, 0x00000000},
	{"ACE_FC_BRDMAL", ACE_FC_BRDMAL, 0x00000000},
	{"ACE_FC_BRDMAC", ACE_FC_BRDMAC, 0x00000000},
	{"ACE_FC_BTDMAS", ACE_FC_BTDMAS, 0x00000000},
	{"ACE_FC_BTDMAL", ACE_FC_BTDMAL, 0x00000000},
	{"ACE_FC_BTDMAC", ACE_FC_BTDMAC, 0x00000000},
	{"ACE_FC_HRDMAS", ACE_FC_HRDMAS, 0x00000000},
	{"ACE_FC_HRDMAL", ACE_FC_HRDMAL, 0x00000000},
	{"ACE_FC_HRDMAC", ACE_FC_HRDMAC, 0x00000000},
	{"ACE_FC_PKDMAS", ACE_FC_PKDMAS, 0x00000000},
	{"ACE_FC_PKDMAL", ACE_FC_PKDMAL, 0x00000000},
	{"ACE_FC_PKDMAC", ACE_FC_PKDMAC, 0x00000000},
	{"ACE_FC_PKDMAO", ACE_FC_PKDMAO, 0x00000000},
	{"ACE_AES_CONTROL", ACE_AES_CONTROL, 0x00000000},
	{"ACE_AES_STATUS", ACE_AES_STATUS, 0x00000000},
	{"ACE_AES_IN1", ACE_AES_IN1, 0x00000000},
	{"ACE_AES_IN2", ACE_AES_IN2, 0x00000000},
	{"ACE_AES_IN3", ACE_AES_IN3, 0x00000000},
	{"ACE_AES_IN4", ACE_AES_IN4, 0x00000000},
	{"ACE_AES_OUT1", ACE_AES_OUT1, 0x00000000},
	{"ACE_AES_OUT2", ACE_AES_OUT2, 0x00000000},
	{"ACE_AES_OUT3", ACE_AES_OUT3, 0x00000000},
	{"ACE_AES_OUT4", ACE_AES_OUT4, 0x00000000},
	{"ACE_AES_IV1", ACE_AES_IV1, 0x00000000},
	{"ACE_AES_IV2", ACE_AES_IV2, 0x00000000},
	{"ACE_AES_IV3", ACE_AES_IV3, 0x00000000},
	{"ACE_AES_IV4", ACE_AES_IV4, 0x00000000},
	{"ACE_AES_CNT1", ACE_AES_CNT1, 0x00000000},
	{"ACE_AES_CNT2", ACE_AES_CNT2, 0x00000000},
	{"ACE_AES_CNT3", ACE_AES_CNT3, 0x00000000},
	{"ACE_AES_CNT4", ACE_AES_CNT4, 0x00000000},
	{"ACE_AES_KEY1", ACE_AES_KEY1, 0x00000000},
	{"ACE_AES_KEY2", ACE_AES_KEY2, 0x00000000},
	{"ACE_AES_KEY3", ACE_AES_KEY3, 0x00000000},
	{"ACE_AES_KEY4", ACE_AES_KEY4, 0x00000000},
	{"ACE_AES_KEY5", ACE_AES_KEY5, 0x00000000},
	{"ACE_AES_KEY6", ACE_AES_KEY6, 0x00000000},
	{"ACE_AES_KEY7", ACE_AES_KEY7, 0x00000000},
	{"ACE_AES_KEY8", ACE_AES_KEY8, 0x00000000},
	{"ACE_TDES_CONTROL", ACE_TDES_CONTROL, 0x00000000},
	{"ACE_TDES_STATUS", ACE_TDES_STATUS, 0x00000000},
	{"ACE_TDES_KEY11", ACE_TDES_KEY11, 0x00000000},
	{"ACE_TDES_KEY12", ACE_TDES_KEY12, 0x00000000},
	{"ACE_TDES_KEY21", ACE_TDES_KEY21, 0x00000000},
	{"ACE_TDES_KEY22", ACE_TDES_KEY22, 0x00000000},
	{"ACE_TDES_KEY31", ACE_TDES_KEY31, 0x00000000},
	{"ACE_TDES_KEY32", ACE_TDES_KEY32, 0x00000000},
	{"ACE_TDES_IV1", ACE_TDES_IV1, 0x00000000},
	{"ACE_TDES_IV2", ACE_TDES_IV2, 0x00000000},
	{"ACE_TDES_IN1", ACE_TDES_IN1, 0x00000000},
	{"ACE_TDES_IN2", ACE_TDES_IN2, 0x00000000},
	{"ACE_TDES_OUT1", ACE_TDES_OUT1, 0x00000000},
	{"ACE_TDES_OUT2", ACE_TDES_OUT2, 0x00000000},
	{"ACE_HASH_CONTROL", ACE_HASH_CONTROL, 0x00000000},
	{"ACE_HASH_CONTROL2", ACE_HASH_CONTROL2, 0x00000000},
	{"ACE_HASH_FIFO_MODE", ACE_HASH_FIFO_MODE, 0x00000000},
	{"ACE_HASH_BYTESWAP", ACE_HASH_BYTESWAP, 0x00000000},
	{"ACE_HASH_STATUS", ACE_HASH_STATUS, 0x00000000},
	{"ACE_HASH_MSGSIZE_LOW", ACE_HASH_MSGSIZE_LOW, 0x00000000},
	{"ACE_HASH_MSGSIZE_HIGH", ACE_HASH_MSGSIZE_HIGH, 0x00000000},
	{"ACE_HASH_PRELEN_LOW", ACE_HASH_PRELEN_LOW, 0x00000000},
	{"ACE_HASH_PRELEN_HIGH", ACE_HASH_PRELEN_HIGH, 0x00000000},
	{"ACE_HASH_IN1", ACE_HASH_IN1, 0x00000000},
	{"ACE_HASH_IN2", ACE_HASH_IN2, 0x00000000},
	{"ACE_HASH_IN3", ACE_HASH_IN3, 0x00000000},
	{"ACE_HASH_IN4", ACE_HASH_IN4, 0x00000000},
	{"ACE_HASH_IN5", ACE_HASH_IN5, 0x00000000},
	{"ACE_HASH_IN6", ACE_HASH_IN6, 0x00000000},
	{"ACE_HASH_IN7", ACE_HASH_IN7, 0x00000000},
	{"ACE_HASH_IN8", ACE_HASH_IN8, 0x00000000},
	{"ACE_HASH_IN9", ACE_HASH_IN9, 0x00000000},
	{"ACE_HASH_IN10", ACE_HASH_IN10, 0x00000000},
	{"ACE_HASH_IN11", ACE_HASH_IN11, 0x00000000},
	{"ACE_HASH_IN12", ACE_HASH_IN12, 0x00000000},
	{"ACE_HASH_IN13", ACE_HASH_IN13, 0x00000000},
	{"ACE_HASH_IN14", ACE_HASH_IN14, 0x00000000},
	{"ACE_HASH_IN15", ACE_HASH_IN15, 0x00000000},
	{"ACE_HASH_IN16", ACE_HASH_IN16, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN1", ACE_HASH_HMAC_KEY_IN1, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN2", ACE_HASH_HMAC_KEY_IN2, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN3", ACE_HASH_HMAC_KEY_IN3, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN4", ACE_HASH_HMAC_KEY_IN4, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN5", ACE_HASH_HMAC_KEY_IN5, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN6", ACE_HASH_HMAC_KEY_IN6, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN7", ACE_HASH_HMAC_KEY_IN7, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN8", ACE_HASH_HMAC_KEY_IN8, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN9", ACE_HASH_HMAC_KEY_IN9, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN10", ACE_HASH_HMAC_KEY_IN10, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN11", ACE_HASH_HMAC_KEY_IN11, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN12", ACE_HASH_HMAC_KEY_IN12, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN13", ACE_HASH_HMAC_KEY_IN13, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN14", ACE_HASH_HMAC_KEY_IN14, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN15", ACE_HASH_HMAC_KEY_IN15, 0x00000000},
	{"ACE_HASH_HMAC_KEY_IN16", ACE_HASH_HMAC_KEY_IN16, 0x00000000},
	{"ACE_HASH_IV1", ACE_HASH_IV1, 0x00000000},
	{"ACE_HASH_IV2", ACE_HASH_IV2, 0x00000000},
	{"ACE_HASH_IV3", ACE_HASH_IV3, 0x00000000},
	{"ACE_HASH_IV4", ACE_HASH_IV4, 0x00000000},
	{"ACE_HASH_IV5", ACE_HASH_IV5, 0x00000000},
	{"ACE_HASH_IV6", ACE_HASH_IV6, 0x00000000},
	{"ACE_HASH_IV7", ACE_HASH_IV7, 0x00000000},
	{"ACE_HASH_IV8", ACE_HASH_IV8, 0x00000000},
	{"ACE_HASH_RESULT1", ACE_HASH_RESULT1, 0x00000000},
	{"ACE_HASH_RESULT2", ACE_HASH_RESULT2, 0x00000000},
	{"ACE_HASH_RESULT3", ACE_HASH_RESULT3, 0x00000000},
	{"ACE_HASH_RESULT4", ACE_HASH_RESULT4, 0x00000000},
	{"ACE_HASH_RESULT5", ACE_HASH_RESULT5, 0x00000000},
	{"ACE_HASH_RESULT6", ACE_HASH_RESULT6, 0x00000000},
	{"ACE_HASH_RESULT7", ACE_HASH_RESULT7, 0x00000000},
	{"ACE_HASH_RESULT8", ACE_HASH_RESULT8, 0x00000000},
	{"ACE_HASH_SEED1", ACE_HASH_SEED1, 0x00000000},
	{"ACE_HASH_SEED2", ACE_HASH_SEED2, 0x00000000},
	{"ACE_HASH_SEED3", ACE_HASH_SEED3, 0x00000000},
	{"ACE_HASH_SEED4", ACE_HASH_SEED4, 0x00000000},
	{"ACE_HASH_SEED5", ACE_HASH_SEED5, 0x00000000},
	{"ACE_HASH_PRNG1", ACE_HASH_PRNG1, 0x00000000},
	{"ACE_HASH_PRNG2", ACE_HASH_PRNG2, 0x00000000},
	{"ACE_HASH_PRNG3", ACE_HASH_PRNG3, 0x00000000},
	{"ACE_HASH_PRNG4", ACE_HASH_PRNG4, 0x00000000},
	{"ACE_HASH_PRNG5", ACE_HASH_PRNG5, 0x00000000},
	{"ACE_PKA_SFR0", ACE_PKA_SFR0, 0x00000000},
	{"ACE_PKA_SFR1", ACE_PKA_SFR1, 0x00000000},
	{"ACE_PKA_SFR2", ACE_PKA_SFR2, 0x00000000},
	{"ACE_PKA_SFR3", ACE_PKA_SFR3, 0x00000000},
	{"ACE_PKA_SFR4", ACE_PKA_SFR4, 0x00000000}
};

#define ACE_NUM_OF_REGISTERS ARRAY_SIZE(exynos4210_ace_regs)

#define TYPE_EXYNOS4210_ACE "exynos4210.ace"
#define EXYNOS4210_ACE(obj) \
    OBJECT_CHECK(Exynos4210AceState, (obj), TYPE_EXYNOS4210_ACE)

typedef struct Exynos4210AceState {
    SysBusDevice parent_obj;

    MemoryRegion iomem;
    uint32_t reg[ACE_NUM_OF_REGISTERS];
    uint32_t aes_keydata[8];
    uint32_t aes_iv[4];
} Exynos4210AceState;

static uint32_t exynos4210_ace_FCINTPEND(void *opaque, uint32_t curr)
{
    PRINT_DEBUG("QEMU ACE: FCINTPEND triggered\n");
    Exynos4210AceState *s = (Exynos4210AceState *)opaque;
    AES_KEY aes_key;
    uint8_t* SrcAddr = NULL;
    uint8_t* DstAddr = NULL;
    uint32_t FCBRDMAS = exynos4210_ace_read(opaque, ACE_FC_BRDMAS, 4);//SrcAddr
    uint32_t FCBRDMAL = exynos4210_ace_read(opaque, ACE_FC_BRDMAL, 4);//SrcLength
    uint32_t FCBTDMAS = exynos4210_ace_read(opaque, ACE_FC_BTDMAS, 4);//DstAddr
    uint32_t FCBTDMAL = exynos4210_ace_read(opaque, ACE_FC_BTDMAL, 4);//DstLength
    uint32_t AES_control = exynos4210_ace_read(opaque, ACE_AES_CONTROL, 4);

    PRINT_DEBUG("QEMU ACE: AES_control=0x%x, FCBRDMAS=0x%x, FCBRDMAS=0x%x, FCBRDMAS=0x%x, FCBRDMAS=0x%x\n", AES_control, FCBRDMAS, FCBRDMAL, FCBTDMAS, FCBTDMAL);
    if(FCBRDMAS && FCBRDMAL && FCBTDMAS && FCBTDMAL){//BUG what if an address is 0x0 ? should find a better way of triggering processing
		if(FCBRDMAL != FCBTDMAL){
			PRINT_DEBUG("QEMU ACE: Error: FCBRDMAL != FCBTDMAL!\n");
			goto exit;
		}

		SrcAddr = (uint8_t*) malloc(FCBRDMAL);
		cpu_physical_memory_read(FCBRDMAS, SrcAddr, FCBRDMAL);
		DstAddr = (uint8_t*) malloc(FCBTDMAL);
		if((AES_control & ACE_AES_OPERMODE_MASK) != ACE_AES_OPERMODE_CBC){
			PRINT_DEBUG("QEMU ACE: Error: AES mode CBC only!\n");
			goto exit;
		}

		if((AES_control & ACE_AES_FIFO_MASK) != ACE_AES_FIFO_ON){
			PRINT_DEBUG("QEMU ACE: Error: ACE_AES_FIFO_OFF not supported!\n");
			goto exit;
		}

		switch(AES_control & ACE_AES_KEYSIZE_MASK){
			case ACE_AES_KEYSIZE_128:
				aes_key.rounds = 10;
				AES_set_decrypt_key((uint8_t*)&(s->aes_keydata[4]), 128, &aes_key);
				break;
			case ACE_AES_KEYSIZE_192:
				aes_key.rounds = 12;
				AES_set_decrypt_key((uint8_t*)&(s->aes_keydata[2]), 192, &aes_key);
				break;
			case ACE_AES_KEYSIZE_256:
				aes_key.rounds = 14;
				AES_set_decrypt_key((uint8_t*)&(s->aes_keydata[0]), 256, &aes_key);
				break;
			default:
				PRINT_DEBUG("QEMU ACE: Error: invalid ACE_AES_KEYSIZE !\n");
				goto exit;
		}

		if(!(AES_control & ACE_AES_SWAPKEY_ON)){
			PRINT_DEBUG("QEMU ACE: Error: ACE_AES_SWAPKEY_OFF not supported!\n");
			goto exit;
		}

		if(!(AES_control & ACE_AES_SWAPIV_ON)){
			PRINT_DEBUG("QEMU ACE: Error: ACE_AES_SWAPIV_OFF not supported!\n");
			goto exit;
		}

		if(!(AES_control & ACE_AES_SWAPDI_ON)){
			PRINT_DEBUG("QEMU ACE: Error: ACE_AES_SWAPDI_OFF not supported!\n");
			goto exit;
		}

		AES_cbc_encrypt(SrcAddr, DstAddr,
		     FCBRDMAL, &aes_key,
		     (uint8_t*)s->aes_iv, !(AES_control & ACE_AES_MODE_DEC));

		if(!(AES_control & ACE_AES_SWAPDO_ON)){
			PRINT_DEBUG("QEMU ACE: Error: ACE_AES_SWAPDO_OFF not supported!\n");
			goto exit;
		}

		cpu_physical_memory_write(FCBTDMAS, DstAddr, FCBTDMAL);
		curr |= 4;
	}
exit:
    if(SrcAddr){
        free(SrcAddr);
	}
    if(DstAddr){
        free(DstAddr);
	}
	return curr;
}

static uint64_t exynos4210_ace_read(void *opaque, hwaddr offset,
                                    unsigned size)
{
    Exynos4210AceState *s = (Exynos4210AceState *)opaque;
    const Exynos4210AceReg *reg_p = exynos4210_ace_regs;
    unsigned int i;

    for (i = 0; i < ACE_NUM_OF_REGISTERS; i++) {
        if (reg_p->offset == offset) {
            PRINT_DEBUG_EXTEND("%s [0x%04x] -> 0x%04x\n", reg_p->name,
                                   (uint32_t)offset, s->reg[i]);
			if (offset == ACE_FC_INTPEND){
				return exynos4210_ace_FCINTPEND(opaque, s->reg[i]);
			}else{
				return s->reg[i];
			}
        }
        reg_p++;
    }
    PRINT_DEBUG("QEMU ACE ERROR: bad read offset 0x%04x\n", (uint32_t)offset);
    return 0;
}

static void exynos4210_ace_write(void *opaque, hwaddr offset,
                                 uint64_t val, unsigned size)
{
    Exynos4210AceState *s = (Exynos4210AceState *)opaque;
    const Exynos4210AceReg *reg_p = exynos4210_ace_regs;
    unsigned int i;

    for (i = 0; i < ACE_NUM_OF_REGISTERS; i++) {
        if (reg_p->offset == offset) {
            PRINT_DEBUG_EXTEND("%s <0x%04x> <- 0x%04x\n", reg_p->name,
                    (uint32_t)offset, (uint32_t)val);
            s->reg[i] = val;
            // val is casted to uint32_t because .max_access_size is set to 32 bits
            switch(offset){
				case ACE_AES_KEY1:
					s->aes_keydata[0] = (uint32_t) val;
				break;

				case ACE_AES_KEY2:
					s->aes_keydata[1] = (uint32_t) val;
				break;

				case ACE_AES_KEY3:
					s->aes_keydata[2] = (uint32_t) val;
				break;

				case ACE_AES_KEY4:
					s->aes_keydata[3] = (uint32_t) val;
				break;

				case ACE_AES_KEY5:
					s->aes_keydata[4] = (uint32_t) val;
				break;

				case ACE_AES_KEY6:
					s->aes_keydata[5] = (uint32_t) val;
				break;

				case ACE_AES_KEY7:
					s->aes_keydata[6] = (uint32_t) val;
				break;

				case ACE_AES_KEY8:
					s->aes_keydata[7] = (uint32_t) val;
				break;

				case ACE_AES_IV1:
					s->aes_iv[0] = (uint32_t) val;
				break;

				case ACE_AES_IV2:
					s->aes_iv[1] = (uint32_t) val;
				break;

				case ACE_AES_IV3:
					s->aes_iv[2] = (uint32_t) val;
				break;

				case ACE_AES_IV4:
					s->aes_iv[3] = (uint32_t) val;
				break;
			}
            return;
        }
        reg_p++;
    }
    PRINT_DEBUG("QEMU ACE ERROR: bad write offset 0x%04x\n", (uint32_t)offset);
}

static const MemoryRegionOps exynos4210_ace_ops = {
    .read = exynos4210_ace_read,
    .write = exynos4210_ace_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
        .unaligned = false
    }
};

static void exynos4210_ace_reset(DeviceState *dev)
{
    Exynos4210AceState *s = EXYNOS4210_ACE(dev);
    unsigned i;

    /* Set default values for registers */
    for (i = 0; i < ACE_NUM_OF_REGISTERS; i++) {
        s->reg[i] = exynos4210_ace_regs[i].reset_value;
    }
}

static void exynos4210_ace_init(Object *obj)
{
    Exynos4210AceState *s = EXYNOS4210_ACE(obj);
    SysBusDevice *dev = SYS_BUS_DEVICE(obj);

    /* memory mapping */
    memory_region_init_io(&s->iomem, obj, &exynos4210_ace_ops, s,
                          "exynos4210.ace", EXYNOS4210_ACE_REGS_MEM_SIZE);
    sysbus_init_mmio(dev, &s->iomem);
}

static const VMStateDescription exynos4210_ace_vmstate = {
    .name = "exynos4210.ace",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(reg, Exynos4210AceState, ACE_NUM_OF_REGISTERS),
        VMSTATE_END_OF_LIST()
    }
};

static void exynos4210_ace_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->reset = exynos4210_ace_reset;
    dc->vmsd = &exynos4210_ace_vmstate;
}

static const TypeInfo exynos4210_ace_info = {
    .name          = TYPE_EXYNOS4210_ACE,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(Exynos4210AceState),
    .instance_init = exynos4210_ace_init,
    .class_init    = exynos4210_ace_class_init,
};

static void exynos4210_ace_register(void)
{
    type_register_static(&exynos4210_ace_info);
}

type_init(exynos4210_ace_register)
