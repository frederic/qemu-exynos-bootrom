/*
 *  Exynos4210 One-Time Programmable memory emulation
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

#include "qemu/osdep.h"
#include "hw/sysbus.h"
#include "qemu/log.h"
#include "hw/misc/exynos4210_otp.h"

#define DEBUG_OTP           1
#define DEBUG_OTP_EXTEND    1

#ifndef DEBUG_OTP
#define DEBUG_OTP           0
#endif

#ifndef DEBUG_OTP_EXTEND
#define DEBUG_OTP_EXTEND    0
#endif

#if DEBUG_OTP
#define  PRINT_DEBUG(fmt, args...)  \
        do { \
            fprintf(stderr, "  [%s:%d]   "fmt, __func__, __LINE__, ##args); \
        } while (0)

#if DEBUG_OTP_EXTEND
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

#define TYPE_EXYNOS4210_OTP             "exynos4210.otp"
#define EXYNOS4210_OTP(obj) \
    OBJECT_CHECK(Exynos4210OtpState, (obj), TYPE_EXYNOS4210_OTP)

typedef struct Exynos4210OtpState {
    SysBusDevice parent_obj;
    MemoryRegion otp_mem;
} Exynos4210OtpState;

static uint64_t exynos4210_otp_read(void *opaque, hwaddr offset, unsigned size)
{
	PRINT_DEBUG("Read OTP @0x%lx (0x%x)\n", offset, size);
	uint64_t ret;
	assert(size < sizeof(uint64_t));
	assert(offset + size <= EXYNOS4210_OTP_SIZE);
    memcpy(&ret, &otp_data[offset], size);
    return ret;
}

static void exynos4210_otp_write(void *opaque, hwaddr offset, uint64_t value, unsigned size)
{
	PRINT_DEBUG("[UNSUPPORTED]Write OTP @0x%lx = %lx, (0x%x)\n", offset, value, size);
    return;
}

const MemoryRegionOps exynos4210_otp_ops = {
    .read = exynos4210_otp_read,
    .write = exynos4210_otp_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 4,
    }
};

static void exynos4210_otp_init(Object *obj)
{
    Exynos4210OtpState *s = EXYNOS4210_OTP(obj);
    SysBusDevice *dev = SYS_BUS_DEVICE(obj);

    memory_region_init_io(&s->otp_mem, obj, &exynos4210_otp_ops, NULL, TYPE_EXYNOS4210_OTP, EXYNOS4210_OTP_SIZE);
    sysbus_init_mmio(dev, &s->otp_mem);
}

static const TypeInfo exynos4210_otp_info = {
    .name          = TYPE_EXYNOS4210_OTP,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_init = exynos4210_otp_init,
    .instance_size = sizeof(Exynos4210OtpState),
};

static void exynos4210_otp_register(void)
{
    type_register_static(&exynos4210_otp_info);
}

type_init(exynos4210_otp_register)
