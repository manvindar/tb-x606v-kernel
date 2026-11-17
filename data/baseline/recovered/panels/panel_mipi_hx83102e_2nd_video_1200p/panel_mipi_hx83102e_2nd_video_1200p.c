/*
 * Candidate recovered from the shipping Lenovo TB-X606V kernel image (Linux 4.9.190+, 2022-06-30): NOT the original source.
 * Per-function evidence status is listed in recon/RECON-PANELS-TOUCH.md; nothing here is verified until the CI compare harness has run.
 * Structure follows the Lenovo-drop panel_mipi_hx83102e_video_1200p.c (GPL-2.0); data words, delays, call order, strings and the field
 * values of lcm_get_params come from the shipping binary (recon/trace/<panel>/).
 */

#define LOG_TAG "LCM"

#ifndef BUILD_LK
#include <linux/string.h>
#include <linux/kernel.h>
#endif

#include "lcm_drv.h"
#include "tpd.h"
#ifdef BUILD_LK
#include <platform/upmu_common.h>
#include <platform/mt_gpio.h>
#include <platform/mt_i2c.h>
#include <platform/mt_pmic.h>
#include <string.h>
#elif defined(BUILD_UBOOT)
#include <asm/arch/mt_gpio.h>
#else
#include "disp_dts_gpio.h"
#endif

#ifndef MACH_FPGA
#include <lcm_pmic.h>
#endif

#define LCM_LOGI(fmt, args...)  printk("[KERNEL/"LOG_TAG"]"fmt, ##args)
#define LCM_LOGD(fmt, args...)  printk("[KERNEL/"LOG_TAG"]"fmt, ##args)

#define LCM_ID (0x98)

static struct LCM_UTIL_FUNCS lcm_util;

#define SET_RESET_PIN(v)	(lcm_util.set_reset_pin_gpio((v)))
#define MDELAY(n)		(lcm_util.mdelay(n))
#define UDELAY(n)		(lcm_util.udelay(n))
extern void BACKLIGHT_GPIO_enable(void);
extern void BACKLIGHT_GPIO_disable(void);
extern void SGM37604A_set_backlight_reg_init(void);
/* provided by the shipping Himax touch driver; absent from both public trees (see RECON-PANELS-TOUCH.md) */
extern int Himax_gesture_status(void);

#define dsi_set_cmdq_V22(cmdq, cmd, count, ppara, force_update) \
	lcm_util.dsi_set_cmdq_V22(cmdq, cmd, count, ppara, force_update)
#define dsi_set_cmdq(pdata, queue_size, force_update) \
		lcm_util.dsi_set_cmdq(pdata, queue_size, force_update)
#define read_reg_v2(cmd, buffer, buffer_size) \
		lcm_util.dsi_dcs_read_lcm_reg_v2(cmd, buffer, buffer_size)

#ifndef BUILD_LK
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/i2c.h>
#include <linux/irq.h>
#include <linux/uaccess.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/platform_device.h>
#include <linux/i2c/ocp2131.h>
#endif

#define LCM_DSI_CMD_MODE								0
#define FRAME_WIDTH									(1200)
#define FRAME_HEIGHT									(1920)

#define LCM_PHYSICAL_WIDTH								(138780)
#define LCM_PHYSICAL_HEIGHT								(222048)

#define REGFLAG_DELAY		0xFFFC
#define REGFLAG_UDELAY	0xFFFB
#define REGFLAG_END_OF_TABLE	0xFFFD

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

struct LCM_setting_table {
	unsigned int cmd;
	unsigned char count;
	unsigned char para_list[64];
};

/* shipping .data: {0x55, 1, {0xFF}} then the end marker (bytes verified in recon/<panel>/tables.json) */
static struct LCM_setting_table CABC_mode[] = {
	{ 0x55, 0x01, {0xFF} },
	{ REGFLAG_END_OF_TABLE, 0x00, {} },
};

static struct LCM_setting_table bl_level[] = {
	{ 0x51, 0x02, {0x0F, 0xFF} },
	{ REGFLAG_END_OF_TABLE, 0x00, {} },
};

static struct LCM_setting_table dimming_level[] = {
	{ 0x53, 0x01, {0x2C} },
	{ REGFLAG_DELAY, 10, {} },
};

static unsigned char lcm_dimming_pending;

static void push_table(void *cmdq, struct LCM_setting_table *table,
	unsigned int count, unsigned char force_update)
{
	unsigned int i;
	unsigned cmd;
	for (i = 0; i < count; i++) {
		cmd = table[i].cmd;
		switch (cmd) {

		case REGFLAG_DELAY:
			if (table[i].count <= 10)
				MDELAY(table[i].count);
			else
				MDELAY(table[i].count);
			break;

		case REGFLAG_UDELAY:
			UDELAY(table[i].count);
			break;

		case REGFLAG_END_OF_TABLE:
			break;

		default:
			dsi_set_cmdq_V22(cmdq, cmd, table[i].count, table[i].para_list, force_update);
		}
	}
}

static void lcm_set_util_funcs(const struct LCM_UTIL_FUNCS *util)
{
	memcpy(&lcm_util, util, sizeof(struct LCM_UTIL_FUNCS));
}

static void lcm_get_params(struct LCM_PARAMS *params)
{
	memset(params, 0, sizeof(struct LCM_PARAMS));

	params->type = LCM_TYPE_DSI;

	params->width = FRAME_WIDTH;
	params->height = FRAME_HEIGHT;
	params->physical_width = LCM_PHYSICAL_WIDTH/1000;
	params->physical_height = LCM_PHYSICAL_HEIGHT/1000;

	params->dsi.mode = SYNC_PULSE_VDO_MODE;
	params->dsi.switch_mode = CMD_MODE;
	params->dsi.switch_mode_enable = 0;

	params->dsi.LANE_NUM = LCM_FOUR_LANE;
	params->dsi.data_format.color_order = LCM_COLOR_ORDER_RGB;
	params->dsi.data_format.trans_seq = LCM_DSI_TRANS_SEQ_MSB_FIRST;
	params->dsi.data_format.padding = LCM_DSI_PADDING_ON_LSB;
	params->dsi.data_format.format = LCM_DSI_FORMAT_RGB888;

	params->dsi.packet_size = 256;
	params->dsi.PS = LCM_PACKED_PS_24BIT_RGB888;

	params->dsi.vertical_sync_active = 8;
	params->dsi.vertical_backporch = 28;
	params->dsi.vertical_frontporch = 98;
	params->dsi.vertical_active_line = FRAME_HEIGHT;

	params->dsi.horizontal_sync_active = 14;
	params->dsi.horizontal_backporch = 26;
	params->dsi.horizontal_frontporch = 32;
	params->dsi.horizontal_active_pixel = FRAME_WIDTH;
	params->dsi.ssc_disable = 1;

	params->dsi.PLL_CLOCK = 498;

	params->dsi.clk_lp_per_line_enable = 0;
	params->dsi.esd_check_enable = 1;
	params->dsi.customization_esd_check_enable = 1;
	params->dsi.lcm_esd_check_table[0].cmd = 0x09;
	params->dsi.lcm_esd_check_table[0].count = 4;
	params->dsi.lcm_esd_check_table[0].para_list[0] = 0x80;
	params->dsi.lcm_esd_check_table[0].para_list[1] = 0x73;
	params->dsi.lcm_esd_check_table[0].para_list[2] = 0x04;
	params->dsi.lcm_esd_check_table[0].para_list[3] = 0x00;
}

static void init_lcm_register(void)
{
	unsigned int data_array[16];

	data_array[0] = 0x00043902;
	data_array[1] = 0x2E1083B9;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x0000CDE9;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000001BB;
	dsi_set_cmdq(data_array, 2, 1);
	MDELAY(5);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000000E9;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00053902;
	data_array[1] = 0xFF0C67D1;
	data_array[2] = 0x00000005;
	dsi_set_cmdq(data_array, 3, 1);
	data_array[0] = 0x00123902;
	data_array[1] = 0xAFFA10B1;
	data_array[2] = 0xC12B2BAF;
	data_array[3] = 0x36363975;
	data_array[4] = 0x21223636;
	data_array[5] = 0x00000015;
	dsi_set_cmdq(data_array, 6, 1);
	data_array[0] = 0x00113902;
	data_array[1] = 0x47B000B2;
	data_array[2] = 0x62220080;
	data_array[3] = 0x0000002F;
	data_array[4] = 0xD7201500;
	data_array[5] = 0x00000000;
	dsi_set_cmdq(data_array, 6, 1);
	data_array[0] = 0x00113902;
	data_array[1] = 0x7F647FB4;
	data_array[2] = 0x68718564;
	data_array[3] = 0x01980150;
	data_array[4] = 0x00FF0058;
	data_array[5] = 0x000000FF;
	dsi_set_cmdq(data_array, 6, 1);
	data_array[0] = 0x00043902;
	data_array[1] = 0x8085FCBF;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00033902;
	data_array[1] = 0x002B2BD2;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x002C3902;
	data_array[1] = 0x000000D3;
	data_array[2] = 0x00040100;
	data_array[3] = 0x27270C14;
	data_array[4] = 0x1F1F2F22;
	data_array[5] = 0x10320404;
	data_array[6] = 0x321D001D;
	data_array[7] = 0xB607B617;
	data_array[8] = 0x001A1032;
	data_array[9] = 0x1A00001A;
	data_array[10] = 0x1A55013A;
	data_array[11] = 0x0F766039;
	dsi_set_cmdq(data_array, 12, 1);
	MDELAY(5);
	data_array[0] = 0x002F3902;
	data_array[1] = 0x0B0300E0;
	data_array[2] = 0x3B241711;
	data_array[3] = 0x684A4C44;
	data_array[4] = 0x8A8B7971;
	data_array[5] = 0xB0B19E94;
	data_array[6] = 0x73695E57;
	data_array[7] = 0x110B0300;
	data_array[8] = 0x443B2417;
	data_array[9] = 0x71684A4C;
	data_array[10] = 0x948A8B79;
	data_array[11] = 0x57B0B19E;
	data_array[12] = 0x0073695E;
	dsi_set_cmdq(data_array, 13, 1);
	MDELAY(5);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000001BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00053902;
	data_array[1] = 0x019B01B1;
	data_array[2] = 0x00000031;
	dsi_set_cmdq(data_array, 3, 1);
	data_array[0] = 0x000C3902;
	data_array[1] = 0x7C0001D3;
	data_array[2] = 0x10110000;
	data_array[3] = 0x01000E00;
	dsi_set_cmdq(data_array, 4, 1);
	MDELAY(5);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000002BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00073902;
	data_array[1] = 0x33004EB4;
	data_array[2] = 0x00883311;
	dsi_set_cmdq(data_array, 3, 1);
	data_array[0] = 0x00043902;
	data_array[1] = 0x0200F2BF;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000000BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x000F3902;
	data_array[1] = 0x222323C0;
	data_array[2] = 0x0017A211;
	data_array[3] = 0x08000080;
	data_array[4] = 0x00636300;
	dsi_set_cmdq(data_array, 5, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x0000F9C6;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000030C7;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00093902;
	data_array[1] = 0x040400C8;
	data_array[2] = 0x13820000;
	data_array[3] = 0x000000FF;
	dsi_set_cmdq(data_array, 4, 1);
	data_array[0] = 0x00043902;
	data_array[1] = 0x050407D0;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x002D3902;
	data_array[1] = 0x2D2D2DD5;
	data_array[2] = 0x1818182D;
	data_array[3] = 0x21202118;
	data_array[4] = 0x25242520;
	data_array[5] = 0x18181824;
	data_array[6] = 0x39393918;
	data_array[7] = 0x2E2E2E39;
	data_array[8] = 0x0302032E;
	data_array[9] = 0x01000102;
	data_array[10] = 0x07060700;
	data_array[11] = 0x05040506;
	data_array[12] = 0x00000004;
	dsi_set_cmdq(data_array, 13, 1);
	MDELAY(5);
	data_array[0] = 0x002D3902;
	data_array[1] = 0x181818D6;
	data_array[2] = 0x18181818;
	data_array[3] = 0x20212018;
	data_array[4] = 0x24252421;
	data_array[5] = 0x2D2D2D25;
	data_array[6] = 0x3939392D;
	data_array[7] = 0x2E2E2E39;
	data_array[8] = 0x0405042E;
	data_array[9] = 0x06070605;
	data_array[10] = 0x00010007;
	data_array[11] = 0x02030201;
	data_array[12] = 0x00000003;
	dsi_set_cmdq(data_array, 13, 1);
	MDELAY(5);
	data_array[0] = 0x00183902;
	data_array[1] = 0x021312E7;
	data_array[2] = 0x0E484602;
	data_array[3] = 0x2721180E;
	data_array[4] = 0x017A1977;
	data_array[5] = 0x00000027;
	data_array[6] = 0x68001700;
	dsi_set_cmdq(data_array, 7, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000001BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00083902;
	data_array[1] = 0x012C02E7;
	data_array[2] = 0x0EC00D8E;
	dsi_set_cmdq(data_array, 3, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000002BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x001D3902;
	data_array[1] = 0xFD01FFE7;
	data_array[2] = 0x22000001;
	data_array[3] = 0x00000000;
	data_array[4] = 0x00000000;
	data_array[5] = 0x00000000;
	data_array[6] = 0x00000000;
	data_array[7] = 0x02008100;
	data_array[8] = 0x00000040;
	dsi_set_cmdq(data_array, 9, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000000BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000000BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00093902;
	data_array[1] = 0xA80370BA;
	data_array[2] = 0xC000F285;
	data_array[3] = 0x0000000D;
	dsi_set_cmdq(data_array, 4, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000002BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x000D3902;
	data_array[1] = 0xFFFFFFD8;
	data_array[2] = 0xFFF0FFFF;
	data_array[3] = 0xFFFFFFFF;
	data_array[4] = 0x000000F0;
	dsi_set_cmdq(data_array, 5, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000003BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00193902;
	data_array[1] = 0xAAAAAAD8;
	data_array[2] = 0xAAA0AAAA;
	data_array[3] = 0xAAAAAAAA;
	data_array[4] = 0x555555A0;
	data_array[5] = 0x55505555;
	data_array[6] = 0x55555555;
	data_array[7] = 0x00000050;
	dsi_set_cmdq(data_array, 8, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000000BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000002CC;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000003BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000080B2;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00023902;
	data_array[1] = 0x000000BD;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00033902;
	data_array[1] = 0x001111E1;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x00033902;
	data_array[1] = 0x00000051;
	dsi_set_cmdq(data_array, 2, 1);
	data_array[0] = 0x24531500;
	dsi_set_cmdq(data_array, 1, 1);
	data_array[0] = 0x00053902;
	data_array[1] = 0xF00D04C9;
	data_array[2] = 0x00000000;
	dsi_set_cmdq(data_array, 3, 1);
	data_array[0] = 0x01551500;
	dsi_set_cmdq(data_array, 1, 1);
	MDELAY(5);
	data_array[0] = 0x00173902;
	data_array[1] = 0x2C412DE4;
	data_array[2] = 0xA79F9F9F;
	data_array[3] = 0xC3C3A7A7;
	data_array[4] = 0x03FFFFFF;
	data_array[5] = 0x1E1E1E1E;
	data_array[6] = 0x00002000;
	dsi_set_cmdq(data_array, 7, 1);
	MDELAY(5);
	data_array[0] = 0x00110500;
	dsi_set_cmdq(data_array, 1, 1);
	MDELAY(50);
	data_array[0] = 0x00290500;
	dsi_set_cmdq(data_array, 1, 1);
	MDELAY(20);
}

static void lcm_init(void)
{
	int ret = 0;

	LCM_LOGD("lcm_init\n");
	ret = OCP2131_write_bytes(0x00, 0x12);
	if (ret < 0)
		LCM_LOGI("hx83102p----ocp2131----cmd=%0x--i2c write error----\n", 0x00);
	else
		LCM_LOGI("hx83102p----ocp2131----cmd=%0x--i2c write success----\n", 0x00);
	MDELAY(2);
	ret = OCP2131_write_bytes(0x01, 0x12);
	if (ret < 0)
		LCM_LOGI("hx83102p----ocp2131----cmd=%0x--i2c write error----\n", 0x01);
	else
		LCM_LOGI("hx83102p----ocp2131----cmd=%0x--i2c write success----\n", 0x01);
	OCP2131_GPIO_ENP_enable();
	MDELAY(5);
	OCP2131_GPIO_ENN_enable();
	MDELAY(5);
	SET_RESET_PIN(1);
	MDELAY(1);
	SET_RESET_PIN(0);
	tpd_gpio_output(0, 1);
	MDELAY(1);
	tpd_gpio_output(0, 0);
	MDELAY(15);
	tpd_gpio_output(0, 1);
	SET_RESET_PIN(1);
	MDELAY(160);

	init_lcm_register();
	lcm_dimming_pending = 1;
	LCM_LOGI("hx83102p----BOE----lcm mode = vdo mode ----\n");
	BACKLIGHT_GPIO_enable();
	SGM37604A_set_backlight_reg_init();
}

static void lcm_suspend(void)
{
	unsigned int data_array[16];

	LCM_LOGD("lcm_suspend\n");
	BACKLIGHT_GPIO_disable();
	MDELAY(10);
	data_array[0] = 0x00280500;
	dsi_set_cmdq(data_array, 1, 1);
	MDELAY(30);
	data_array[0] = 0x00100500;
	dsi_set_cmdq(data_array, 1, 1);
	MDELAY(120);
	if (!Himax_gesture_status()) {
		data_array[0] = 0x00043902;
		data_array[1] = 0x2E1083B9;
		dsi_set_cmdq(data_array, 2, 1);
		data_array[0] = 0x21B11500;
		dsi_set_cmdq(data_array, 1, 1);
	}
	MDELAY(2);
	if (!Himax_gesture_status()) {
		OCP2131_GPIO_ENN_disable();
		MDELAY(5);
		OCP2131_GPIO_ENP_disable();
	}
}

static void lcm_resume(void)
{
	LCM_LOGD("lcm_resume\n");

	lcm_init();
}


/* in the shipping image these two are reached through LCM_DRIVER slots the public headers lack; kept referenced so they are built and comparable */
static void __attribute__((used)) lcm_set_cabc_mode(int value)
{
	CABC_mode[0].para_list[0] = value;
	push_table(NULL, CABC_mode, sizeof(CABC_mode) / sizeof(struct LCM_setting_table), 1);
}

static void lcm_init_power(void)
{
}

static void lcm_suspend_power(void)
{
}

static void lcm_resume_power(void)
{
}

static void __attribute__((used)) lcm_set_recovery_backlight(void)
{
	push_table(NULL, bl_level, sizeof(bl_level) / sizeof(struct LCM_setting_table), 1);
}

static void lcm_update(unsigned int x, unsigned int y, unsigned int width, unsigned int height)
{
}

static unsigned int lcm_compare_id(void)
{
	unsigned int id = 0, version_id = 0;
	unsigned char buffer[2];
	unsigned int array[16];
	struct LCM_setting_table switch_table_page1[] = {
		{ 0xFF, 0x03, {0x98, 0x81, 0x01} }
	};
	struct LCM_setting_table switch_table_page0[] = {
		{ 0xFF, 0x03, {0x98, 0x81, 0x00} }
	};

	SET_RESET_PIN(1);
	SET_RESET_PIN(0);
	MDELAY(1);

	SET_RESET_PIN(1);
	MDELAY(20);

	push_table(NULL, switch_table_page1, sizeof(switch_table_page1) / sizeof(struct LCM_setting_table), 1);

	array[0] = 0x00023700;	/* read id return two byte,version and id */
	dsi_set_cmdq(array, 1, 1);

	read_reg_v2(0x00, buffer, 1);
	id = buffer[0];		/* we only need ID */

	read_reg_v2(0x01, buffer, 1);
	version_id = buffer[0];

	LCM_LOGI("%s,NT36525B_id=0x%08x,version_id=0x%x\n", __func__, id, version_id);
	push_table(NULL, switch_table_page0, sizeof(switch_table_page0) / sizeof(struct LCM_setting_table), 1);

	if (id == LCM_ID && version_id == 0x25)
		return 1;
	else
		return 0;
}


static void lcm_set_dimming_register(void)
{
	push_table(NULL, dimming_level, sizeof(dimming_level) / sizeof(struct LCM_setting_table), 1);
	LCM_LOGI("%s\n", __func__);
	lcm_dimming_pending = 0;
}

static void lcm_setbacklight_cmdq(void *handle, unsigned int level)
{
	LCM_LOGI("%s,hx83102p backlight: level = %d\n", __func__, level);

	if (level >= 5 && lcm_dimming_pending == 1)
		lcm_set_dimming_register();

	bl_level[0].para_list[0] = (level&0xFF) >> 4;
	bl_level[0].para_list[1] = (level&0x0F) << 4;

	push_table(NULL, bl_level, sizeof(bl_level) / sizeof(struct LCM_setting_table), 1);
}

/* return TRUE: need recovery */
/* return FALSE: No need recovery */
static unsigned int lcm_esd_check(void)
{
	char buffer[3];
	int array[4];

	array[0] = 0x00013700;
	dsi_set_cmdq(array, 1, 1);

	read_reg_v2(0x53, buffer, 1);

	if (buffer[0] != 0x24) {
		LCM_LOGI("[LCM ERROR] [0x53]=0x%02x\n", buffer[0]);
		return TRUE;
	}
	LCM_LOGI("[LCM NORMAL] [0x53]=0x%02x\n", buffer[0]);
	return FALSE;
}

static unsigned int lcm_ata_check(unsigned char *buffer)
{
	unsigned int ret = 0;
	unsigned int x0 = FRAME_WIDTH / 4;
	unsigned int x1 = FRAME_WIDTH * 3 / 4;

	unsigned char x0_MSB = ((x0 >> 8) & 0xFF);
	unsigned char x0_LSB = (x0 & 0xFF);
	unsigned char x1_MSB = ((x1 >> 8) & 0xFF);
	unsigned char x1_LSB = (x1 & 0xFF);

	unsigned int data_array[3];
	unsigned char read_buf[4];

	LCM_LOGI("ATA check size = 0x%x,0x%x,0x%x,0x%x\n", x0_MSB, x0_LSB, x1_MSB, x1_LSB);
	data_array[0] = 0x0005390A;	/* HS packet */
	data_array[1] = (x1_MSB << 24) | (x0_LSB << 16) | (x0_MSB << 8) | 0x2a;
	data_array[2] = (x1_LSB);
	dsi_set_cmdq(data_array, 3, 1);

	data_array[0] = 0x00043700;	/* read id return two byte,version and id */
	dsi_set_cmdq(data_array, 1, 1);

	read_reg_v2(0x2A, read_buf, 4);

	if ((read_buf[0] == x0_MSB) && (read_buf[1] == x0_LSB)
	    && (read_buf[2] == x1_MSB) && (read_buf[3] == x1_LSB))
		ret = 1;
	else
		ret = 0;

	x0 = 0;
	x1 = FRAME_WIDTH - 1;

	x0_MSB = ((x0 >> 8) & 0xFF);
	x0_LSB = (x0 & 0xFF);
	x1_MSB = ((x1 >> 8) & 0xFF);
	x1_LSB = (x1 & 0xFF);

	data_array[0] = 0x0005390A;	/* HS packet */
	data_array[1] = (x1_MSB << 24) | (x0_LSB << 16) | (x0_MSB << 8) | 0x2a;
	data_array[2] = (x1_LSB);
	dsi_set_cmdq(data_array, 3, 1);
	return ret;
}

static void *lcm_switch_mode(int mode)
{
	return NULL;
}

struct LCM_DRIVER mipi_hx83102e_2nd_video_1200p_lcm_drv = {
	.name = "mipi_hx83102e_2nd_video_1200p",
	.set_util_funcs = lcm_set_util_funcs,
	.get_params = lcm_get_params,
	.init = lcm_init,
	.suspend = lcm_suspend,
	.resume = lcm_resume,
	.compare_id = lcm_compare_id,
	.init_power = lcm_init_power,
	.resume_power = lcm_resume_power,
	.suspend_power = lcm_suspend_power,
	.esd_check = lcm_esd_check,
	.set_backlight_cmdq = lcm_setbacklight_cmdq,
	.ata_check = lcm_ata_check,
	.update = lcm_update,
	.switch_mode = lcm_switch_mode,
	/* shipping struct also carries lcm_set_cabc_mode (+0x30) and lcm_set_recovery_backlight (+0x50); neither public lcm_drv.h has those members */
};
