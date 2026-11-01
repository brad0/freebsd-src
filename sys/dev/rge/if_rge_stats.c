/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019, 2020, 2023-2025 Kevin Lo <kevlo@openbsd.org>
 * Copyright (c) 2025 Adrian Chadd <adrian@FreeBSD.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*	$OpenBSD: if_rge.c,v 1.38 2025/09/19 00:41:14 kevlo Exp $	*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sockio.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>
#include <sys/queue.h>
#include <sys/taskqueue.h>
#include <sys/bus.h>
#include <sys/module.h>
#include <sys/rman.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/mii/mii.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include "if_rge_vendor.h"
#include "if_rgereg.h"
#include "if_rgevar.h"
#include "if_rge_debug.h"

#include "if_rge_stats.h"


/**
 * @brief Convert the hardware statistics block to host byte order
 *
 * The NIC writes the counters out in little-endian order.
 */
static void
rge_hw_mac_stats_letoh(struct rge_hw_mac_stats *hws)
{
	hws->rge_tx_ok = le64toh(hws->rge_tx_ok);
	hws->rge_rx_ok = le64toh(hws->rge_rx_ok);
	hws->rge_tx_er = le64toh(hws->rge_tx_er);
	hws->rge_rx_er = le32toh(hws->rge_rx_er);
	hws->rge_miss_pkt = le16toh(hws->rge_miss_pkt);
	hws->rge_fae = le16toh(hws->rge_fae);
	hws->rge_tx_1col = le32toh(hws->rge_tx_1col);
	hws->rge_tx_mcol = le32toh(hws->rge_tx_mcol);
	hws->rge_rx_ok_phy = le64toh(hws->rge_rx_ok_phy);
	hws->rge_rx_ok_brd = le64toh(hws->rge_rx_ok_brd);
	hws->rge_rx_ok_mul = le32toh(hws->rge_rx_ok_mul);
	hws->rge_tx_abt = le16toh(hws->rge_tx_abt);
	hws->rge_tx_undrn = le16toh(hws->rge_tx_undrn);
	hws->re_tx_octets = le64toh(hws->re_tx_octets);
	hws->re_rx_octets = le64toh(hws->re_rx_octets);
	hws->re_rx_multicast64 = le64toh(hws->re_rx_multicast64);
	hws->re_tx_unicast64 = le64toh(hws->re_tx_unicast64);
	hws->re_tx_broadcast64 = le64toh(hws->re_tx_broadcast64);
	hws->re_tx_multicast64 = le64toh(hws->re_tx_multicast64);
	hws->re_tx_pause_on = le32toh(hws->re_tx_pause_on);
	hws->re_tx_pause_off = le32toh(hws->re_tx_pause_off);
	hws->re_tx_pause_all = le32toh(hws->re_tx_pause_all);
	hws->re_tx_deferred = le32toh(hws->re_tx_deferred);
	hws->re_tx_late_collision = le32toh(hws->re_tx_late_collision);
	hws->re_tx_all_collision = le32toh(hws->re_tx_all_collision);
	hws->re_tx_aborted32 = le32toh(hws->re_tx_aborted32);
	hws->re_align_errors32 = le32toh(hws->re_align_errors32);
	hws->re_rx_frame_too_long = le32toh(hws->re_rx_frame_too_long);
	hws->re_rx_runt = le32toh(hws->re_rx_runt);
	hws->re_rx_pause_on = le32toh(hws->re_rx_pause_on);
	hws->re_rx_pause_off = le32toh(hws->re_rx_pause_off);
	hws->re_rx_pause_all = le32toh(hws->re_rx_pause_all);
	hws->re_rx_unknown_opcode = le32toh(hws->re_rx_unknown_opcode);
	hws->re_rx_mac_error = le32toh(hws->re_rx_mac_error);
	hws->re_tx_underrun32 = le32toh(hws->re_tx_underrun32);
	hws->re_rx_mac_missed = le32toh(hws->re_rx_mac_missed);
	hws->re_rx_tcam_dropped = le32toh(hws->re_rx_tcam_dropped);
	hws->re_tdu = le32toh(hws->re_tdu);
	hws->re_rdu = le32toh(hws->re_rdu);
}

/**
 * @brief Fetch the MAC statistics from the hardware
 *
 * I don't know if this can be done asynchronously (eg via
 * an interrupt notification path for completion) as I
 * currently don't have datasheets.  OpenBSD and the
 * older if_re driver both implement this using polling.
 *
 * Must be called with the driver lock held.
 */
int
rge_hw_mac_stats_fetch(struct rge_softc *sc, struct rge_hw_mac_stats *hws)
{
	struct rge_mac_stats *ss = &sc->sc_mac_stats;
	uint32_t reg;
	uint8_t command;
	int i;

	RGE_ASSERT_LOCKED(sc);

	command = RGE_READ_1(sc, RGE_CMD);
	if (command == 0xff || (command & RGE_CMD_RXENB) == 0)
		return (ENETDOWN);

	bus_dmamap_sync(sc->sc_dmat_stats_buf, ss->map, BUS_DMASYNC_PREREAD);

#if 0
                if (extend_stats)
                        re_set_mac_ocp_bit(sc, 0xEA84, (BIT_1 | BIT_0));
#endif

	/* Program in the memory page to write data into */
	RGE_WRITE_4(sc, RGE_DTCCR_HI, RGE_ADDR_HI(ss->paddr));
	RGE_WRITE_BARRIER_4(sc, RGE_DTCCR_HI);

	(void) RGE_READ_1(sc, RGE_CMD);

	RGE_WRITE_4(sc, RGE_DTCCR_LO, RGE_ADDR_LO(ss->paddr));
	RGE_WRITE_BARRIER_4(sc, RGE_DTCCR_LO);

	/* Inform the hardware to begin stats writing */
	RGE_WRITE_4(sc, RGE_DTCCR_LO, RGE_ADDR_LO(ss->paddr) | RGE_DTCCR_CMD);
	RGE_WRITE_BARRIER_4(sc, RGE_DTCCR_LO);

	for (i = 0; i < 1000; i++) {
		RGE_READ_BARRIER_4(sc, RGE_DTCCR_LO);
		reg = RGE_READ_4(sc, RGE_DTCCR_LO);
		if ((reg & RGE_DTCCR_CMD) == 0)
			break;
		DELAY(10);
	}

#if 0
                if (extend_stats)
                        re_clear_mac_ocp_bit(sc, 0xEA84, (BIT_1 | BIT_0));
#endif

	if ((reg & RGE_DTCCR_CMD) != 0)
		return (ETIMEDOUT);

	bus_dmamap_sync(sc->sc_dmat_stats_buf, ss->map, BUS_DMASYNC_POSTREAD);

	if (hws != NULL) {
		*hws = *ss->stats;
		rge_hw_mac_stats_letoh(hws);
	}

	return (0);
}
