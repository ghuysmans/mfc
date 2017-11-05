//mostly taken from nfc-mfclassic.c...
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include "nfc/nfc.h"
#include "mifare.h"

#define FAIL(msg) {fprintf(stderr, "%s\n", msg); ret = 2; goto end;}
#define FAILEXPLAIN(f) {nfc_perror(pnd, f); ret = 2; goto end;}

static mifare_param auth = {
	.mpa.abtKey = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
};

static const nfc_modulation modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106,
};


bool reset_counter(nfc_device *pnd, uint8_t block, int32_t value, uint8_t addr) {
	static mifare_param write;
	*(int32_t*)write.mpd.abtData = *(int32_t*)(write.mpd.abtData + 8) = value;
	*(int32_t*)(write.mpd.abtData + 4) = ~value;
	write.mpd.abtData[12] = write.mpd.abtData[14] = addr;
	write.mpd.abtData[13] = write.mpd.abtData[15] = ~addr;
	return nfc_initiator_mifare_cmd(pnd, MC_WRITE, block, &write);
}

bool read_counter(nfc_device *pnd, uint8_t block, int32_t *out_value) {
	static mifare_param read;
	if (nfc_initiator_mifare_cmd(pnd, MC_READ, block, &read)) {
		*out_value = *(int32_t*)read.mpd.abtData;
		return true;
	}
	else
		return false;
}

bool update_counter(nfc_device *pnd, uint8_t block, int32_t delta) {
	mifare_cmd mc;
	if (delta < 0) {
		delta = -delta;
		mc = MC_DECREMENT;
	}
	else if (!delta)
		return true; //nothing to do
	else
		mc = MC_INCREMENT;

	mifare_param *p = (mifare_param*)&delta;
	return
		nfc_initiator_mifare_cmd(pnd, mc, block, p) &&
		nfc_initiator_mifare_cmd(pnd, MC_TRANSFER, block, p /* ignored */);
}


void usage(const char *prog) {
	printf("usage: %s [<value> | (+|-)<offset>]\n", prog);
	printf("update and read a counter on a MIFARE Classic card.\n");
}

int main(int argc, char *argv[]) {
	int ret = 0;

	if (argc != 2) {
		usage(argv[0]);
		return 1;
	}
	else if (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h")) {
		usage(argv[0]);
		return 0;
	}

	nfc_context *ctx = NULL;
	nfc_device *pnd = NULL;
	nfc_target nt;

	nfc_init(&ctx);
	if (!ctx)
		FAIL("nfc_init");

	if (! (pnd = nfc_open(ctx, NULL)))
		FAIL("nfc_open");
	if (nfc_initiator_init(pnd) < 0)
		FAILEXPLAIN("nfc_initiator_init");
	if (nfc_device_set_property_bool(pnd, NP_INFINITE_SELECT, 0) < 0)
		FAILEXPLAIN("nfc_device_set_property_bool");
	//FIXME allow specifying a UID (then, change the length!)
	if (nfc_initiator_select_passive_target(pnd, modulation, NULL, 0, &nt) < 1)
		FAIL("nfc_initiator_select_passive_target");
	if (!(nt.nti.nai.btSak & 0x08))
		FAIL("not a MiFare Classic");
	printf("UID: %02x%02x%02x%02x\n",
		nt.nti.nai.abtUid[0], nt.nti.nai.abtUid[1],
		nt.nti.nai.abtUid[2], nt.nti.nai.abtUid[3]);
	memcpy(auth.mpa.abtAuthUid, nt.nti.nai.abtUid, 4);

	if (!nfc_initiator_mifare_cmd(pnd, MC_AUTH_A, 0x3e, &auth))
		FAIL("MC_AUTH");

	bool r;
	char *f;
	if (isdigit(argv[1][0])) {
		r = reset_counter(pnd, 0x3e, atoi(argv[1]), 42 /* why not? */);
		f = "reset";
	}
	else if (argv[1][0] == '-') {
		r = update_counter(pnd, 0x3e, atoi(argv[1]));
		f = "decrement";
	}
	else if (argv[1][0]=='+' || isdigit(argv[1][0])) {
		r = update_counter(pnd, 0x3e, atoi(argv[1]+1));
		f = "increment";
	}
	else {
		usage(argv[0]);
		ret = 1;
		goto end;
	}
	if (!r)
		FAILEXPLAIN(f);

	int32_t counter;
	if (!read_counter(pnd, 0x3e, &counter))
		FAIL("MC_READ");
	printf("Counter: 0x%08x, %d\n", counter, counter);

end:
	if (pnd)
		nfc_close(pnd);
	if (ctx)
		nfc_exit(ctx);
	exit(ret);
}
