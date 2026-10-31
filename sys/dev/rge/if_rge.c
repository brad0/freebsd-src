/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2019, 2020, 2023-2026 Kevin Lo <kevlo@openbsd.org>
 * Copyright (c) 2025 Adrian Chadd <adrian@FreeBSD.org>
 *
 * Hardware programming portions from Realtek Semiconductor.
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

/*	$OpenBSD: if_rge.c,v 1.46 2026/10/13 00:20:11 kevlo Exp $	*/

#include "opt_rss.h"

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
#include <sys/kernel.h>
#include <sys/smp.h>
#include <sys/cpuset.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <net/bpf.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_media.h>
#include <net/if_types.h>
#include <net/if_vlan_var.h>
#include <net/debugnet.h>
#ifdef RSS
#include <net/rss_config.h>
#endif

#include <machine/bus.h>
#include <machine/resource.h>

#include <dev/mii/mii.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include "if_rge_vendor.h"
#include "if_rgereg.h"
#include "if_rgevar.h"
#include "if_rge_hw.h"
#include "if_rge_microcode.h"
#include "if_rge_debug.h"
#include "if_rge_sysctl.h"
#include "if_rge_stats.h"

#define ETHER_IS_VALID(addr) \
	(!ETHER_IS_MULTICAST(addr.octet) && !ETHER_IS_ZERO(addr.octet))

#define	RGE_CSUM_FEATURES		(CSUM_IP | CSUM_TCP | CSUM_UDP)
#define	RGE_CSUM_FEATURES_IPV6		(CSUM_TCP_IPV6 | CSUM_UDP_IPV6)

/* Largest TSO frame handed to the hardware, including the L2 header. */
#define	RGE_TSO_MAXSIZE			\
	(IP_MAXPACKET + sizeof(struct ether_vlan_header))

#ifdef RSS
CTASSERT(RGE_RSS_KEY_SIZE == RSS_KEYSIZE);
#endif

static int		rge_attach(device_t);
static int		rge_detach(device_t);

#if 0
int		rge_activate(struct device *, int);
#endif
static void	rge_intr_msi(void *);
static int	rge_alloc_msi(struct rge_softc *);
static int	rge_alloc_msix(struct rge_softc *);
static int	rge_setup_msix_intr(struct rge_softc *);
static void	rge_teardown_msix_intr(struct rge_softc *);
static void	rge_intr_link(void *);
static void	rge_intr_rxq(void *);
static void	rge_intr_txq(void *);
static void	rge_rxq_task(void *, int);
static void	rge_rxq_service(struct rge_queues *);
static int	rge_ioctl(struct ifnet *, u_long, caddr_t);
static int	rge_transmit_if(if_t, struct mbuf *);
static void	rge_qflush_if(if_t);
static void	rge_init_if(void *);
static void	rge_init_locked(struct rge_softc *);
static void	rge_stop_locked(struct rge_softc *);
static int	rge_ifmedia_upd(if_t);
static void	rge_ifmedia_sts(if_t, struct ifmediareq *);
static int	rge_allocmem(struct rge_softc *);
static int	rge_alloc_rx_mem(struct rge_softc *, struct rge_queues *);
static int	rge_alloc_tx_mem(struct rge_softc *, struct rge_queues *);
static int	rge_alloc_stats_mem(struct rge_softc *);
static int	rge_freemem(struct rge_softc *);
static void	rge_free_rx_mem(struct rge_softc *, struct rge_queues *);
static void	rge_free_tx_mem(struct rge_softc *, struct rge_queues *);
static int	rge_free_stats_mem(struct rge_softc *);
static int	rge_newbuf(struct rge_queues *);
static void	rge_rx_list_init(struct rge_queues *);
static void	rge_tx_list_init(struct rge_queues *);
static void	rge_fill_rx_ring(struct rge_queues *);
static void	rge_fill_rx_desc_addr(struct rge_queues *, int);
static void	rge_fill_tx_desc_addr(struct rge_queues *, int);
static void	rge_free_rx_ring(struct rge_softc *, struct rge_queues *);
static void	rge_free_tx_ring(struct rge_softc *, struct rge_queues *);
static void	rge_rxcsum(struct rge_softc *, uint32_t, uint32_t,
		    struct mbuf *);
static int	rge_tx_offload(struct rge_softc *, struct mbuf *, uint32_t *,
		    uint32_t *);
static int	rge_rxeof(struct rge_queues *, struct mbufq *, bool *);
static int	rge_txeof(struct rge_queues *);
static void	rge_iff_locked(struct rge_softc *);
static void	rge_init_rss(struct rge_softc *);
static void	rge_add_media_types(struct rge_softc *);
static void	rge_tx_task(void *, int);
static void	rge_txq_flush_mbufs(struct rge_softc *sc);
static void	rge_tick(void *);
static void	rge_link_state(struct rge_softc *);
static void	rge_setwol(struct rge_softc *);

#ifdef DEBUGNET
DEBUGNET_DEFINE(rge);
#endif

struct rge_matchid {
	uint16_t vendor;
	uint16_t device;
	const char *name;
};

const struct rge_matchid rge_devices[] = {
	{ PCI_VENDOR_REALTEK, PCI_PRODUCT_REALTEK_E3000, "Killer E3000" },
	{ PCI_VENDOR_REALTEK, PCI_PRODUCT_REALTEK_E5000, "Killer E5000" },
	{ PCI_VENDOR_REALTEK, PCI_PRODUCT_REALTEK_RTL8125, "RTL8125" },
	{ PCI_VENDOR_REALTEK, PCI_PRODUCT_REALTEK_RTL8126, "RTL8126", },
	{ PCI_VENDOR_REALTEK, PCI_PRODUCT_REALTEK_RTL8127, "RTL8127" },
	{ 0, 0, NULL }
};

static int
rge_probe(device_t dev)
{
	uint16_t vendor, device;
	const struct rge_matchid *ri;

	vendor = pci_get_vendor(dev);
	device = pci_get_device(dev);

	for (ri = rge_devices; ri->name != NULL; ri++) {
		if ((vendor == ri->vendor) && (device == ri->device)) {
			device_set_desc(dev, ri->name);
			return (BUS_PROBE_DEFAULT);
		}
	}

	return (ENXIO);
}

static void
rge_attach_if(struct rge_softc *sc, const char *eaddr)
{
	if_initname(sc->sc_ifp, device_get_name(sc->sc_dev),
	    device_get_unit(sc->sc_dev));
	if_setdev(sc->sc_ifp, sc->sc_dev);
	if_setinitfn(sc->sc_ifp, rge_init_if);
	if_setsoftc(sc->sc_ifp, sc);
	if_setflags(sc->sc_ifp, IFF_BROADCAST | IFF_SIMPLEX | IFF_MULTICAST);
	if_setioctlfn(sc->sc_ifp, rge_ioctl);
	if_settransmitfn(sc->sc_ifp, rge_transmit_if);
	if_setqflushfn(sc->sc_ifp, rge_qflush_if);

	/* Set offload as appropriate */
	if_sethwassist(sc->sc_ifp, RGE_CSUM_FEATURES | RGE_CSUM_FEATURES_IPV6);
	if_setcapabilities(sc->sc_ifp, IFCAP_HWCSUM | IFCAP_TXCSUM_IPV6);

	/* TSO is only supported with the v2 (16 byte) descriptors. */
	if (sc->rge_flags & RGE_FLAG_DESCV2) {
		if_setcapabilitiesbit(sc->sc_ifp, IFCAP_TSO4 | IFCAP_TSO6, 0);
		if_sethwassistbits(sc->sc_ifp, CSUM_IP_TSO | CSUM_IP6_TSO, 0);
		if_sethwtsomax(sc->sc_ifp,
		    IP_MAXPACKET - (ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN));
		if_sethwtsomaxsegcount(sc->sc_ifp, RGE_TX_NSEGS);
		if_sethwtsomaxsegsize(sc->sc_ifp, RGE_JUMBO_FRAMELEN);
	}
	if_setcapenable(sc->sc_ifp, if_getcapabilities(sc->sc_ifp));

	/* Enable WOL if PM is supported. */
	if (pci_has_pm(sc->sc_dev)) {
		if_setcapabilitiesbit(sc->sc_ifp, IFCAP_WOL_MAGIC, 0);
		if_setcapenablebit(sc->sc_ifp, IFCAP_WOL_MAGIC, 0);
	}

	/* Attach interface */
	ether_ifattach(sc->sc_ifp, eaddr);
	sc->sc_ether_attached = true;

	/* post ether_ifattach() bits */

	/* VLAN capabilities */
	if_setcapabilitiesbit(sc->sc_ifp, IFCAP_VLAN_MTU |
	    IFCAP_VLAN_HWTAGGING, 0);
	if_setcapabilitiesbit(sc->sc_ifp, IFCAP_VLAN_HWCSUM, 0);
	if (sc->rge_flags & RGE_FLAG_DESCV2)
		if_setcapabilitiesbit(sc->sc_ifp, IFCAP_VLAN_HWTSO, 0);
	if_setcapenable(sc->sc_ifp, if_getcapabilities(sc->sc_ifp));

	if_setifheaderlen(sc->sc_ifp, sizeof(struct ether_vlan_header));

	/* TODO: is this needed for iftransmit? */
	if_setsendqlen(sc->sc_ifp, RGE_TX_LIST_CNT - 1);
	if_setsendqready(sc->sc_ifp);

#ifdef DEBUGNET
	DEBUGNET_SET(sc->sc_ifp, rge);
#endif
}

static int
rge_attach(device_t dev)
{
	struct ether_addr eaddr;
	struct rge_softc *sc;
	struct rge_queues *q;
	uint32_t hwrev, reg;
	int i, rid;
	int error;

	sc = device_get_softc(dev);
	sc->sc_dev = dev;
	sc->sc_ifp = if_gethandle(IFT_ETHER);
	mtx_init(&sc->sc_mtx, device_get_nameunit(dev), MTX_NETWORK_LOCK,
	    MTX_DEF);

	callout_init_mtx(&sc->sc_timeout, &sc->sc_mtx, 0);

	/* Enable bus mastering */
	pci_enable_busmaster(dev);

	/*
	 * Map control/status registers.
	 */

	/*
	 * The openbsd driver (and my E3000 NIC) handle registering three
	 * kinds of BARs - a 64 bit MMIO BAR, a 32 bit MMIO BAR, and then
	 * a legacy IO port BAR.
	 *
	 * To simplify bring-up, I'm going to request resources for the first
	 * MMIO BAR (BAR2) which should be a 32 bit BAR.
	 */
	rid = PCIR_BAR(2);
	sc->sc_bres = bus_alloc_resource_any(dev, SYS_RES_MEMORY, &rid,
	    RF_ACTIVE);
	if (sc->sc_bres == NULL) {
		RGE_PRINT_ERROR(sc,
		    "Unable to allocate bus resource: memory\n");
		goto fail;
	}
	sc->rge_bhandle = rman_get_bushandle(sc->sc_bres);
	sc->rge_btag = rman_get_bustag(sc->sc_bres);
	sc->rge_bsize = rman_get_size(sc->sc_bres);

	/* Attach sysctl nodes; this also fetches the loader tunables */
	rge_sysctl_attach(sc);

	/* Determine hardware revision */
	hwrev = RGE_READ_4(sc, RGE_TXCFG) & RGE_TXCFG_HWREV;
	switch (hwrev) {
	case 0x60900000:
		sc->rge_type = MAC_R25;
		device_printf(dev, "chip rev: RTL8125 (0x%08x)\n", hwrev);
		break;
	case 0x64100000:
		sc->rge_type = MAC_R25B;
		device_printf(dev, "chip rev: RTL8125B (0x%08x)\n", hwrev);
		break;
	case 0x64900000:
		sc->rge_type = MAC_R26_1;
		device_printf(dev, "chip rev: RTL8126_1 (0x%08x)\n", hwrev);
		break;
	case 0x64a00000:
		sc->rge_type = MAC_R26_2;
		device_printf(dev, "chip rev: RTL8126_2 (0x%08x)\n", hwrev);
		break;
	case 0x68800000:
		sc->rge_type = MAC_R25D_1;
		device_printf(dev, "chip rev: RTL8125D_1 (0x%08x)\n", hwrev);
		break;
	case 0x68900000:
		sc->rge_type = MAC_R25D_2;
		device_printf(dev, "chip rev: RTL8125D_2 (0x%08x)\n", hwrev);
		break;
	case 0x6c900000:
		if (rge_read_mac_ocp(sc, 0xd006) == 0x0007) {
			sc->rge_type = MAC_R27ATF;
			device_printf(dev, "chip rev: RTL8127ATF (0x%08x)\n",
			    hwrev);
		} else {
			sc->rge_type = MAC_R27;
			device_printf(dev, "chip rev: RTL8127 (0x%08x)\n",
			    hwrev);
		}
		sc->sc_linkvec = RGE_LINK_VECTOR_8127;
		sc->rge_min_msix = RGE_MIN_MSIX_VECTORS_8127;
		/* The RTL8127 uses the 16 byte RX/TX descriptor format. */
		sc->rge_flags |= RGE_FLAG_DESCV2;
		break;
	default:
		RGE_PRINT_ERROR(sc, "unknown version 0x%08x\n", hwrev);
		goto fail;
	}

	rge_config_imtype(sc, RGE_IMTYPE_SIM);

	/* Check if PCIe */
	if (pci_find_cap(dev, PCIY_EXPRESS, &reg) == 0) {
		sc->rge_flags |= RGE_FLAG_PCIE;
		sc->sc_expcap = reg;
	}

	/*
	 * Default to a single RX/TX queue serviced by a single MSI
	 * interrupt.  The RTL8127 can instead use MSI-X with one vector
	 * per RX queue (RSS), a TX vector and a link vector.
	 */
	sc->sc_nqueues = sc->sc_ntxqs = 1;
	if (RGE_TYPE_R27(sc) && sc->sc_msix_disable == 0)
		(void)rge_alloc_msix(sc);
#ifndef RSS
	if (sc->sc_nqueues > 1)
		arc4rand(sc->sc_rss_key, sizeof(sc->sc_rss_key), 0);
#endif

	sc->sc_queues = mallocarray(sc->sc_nqueues, sizeof(struct rge_queues),
	    M_DEVBUF, M_WAITOK | M_ZERO);
	for (i = 0; i < sc->sc_nqueues; i++) {
		q = &sc->sc_queues[i];
		q->q_sc = sc;
		q->q_index = i;
		q->q_tx_index = (sc->rge_flags & RGE_FLAG_MULTIVEC) ?
		    RGE_TX_VECTOR_8127(i) : 0;
		snprintf(q->q_name, sizeof(q->q_name), "%s rxq%d",
		    device_get_nameunit(dev), i);
		snprintf(q->q_tx_name, sizeof(q->q_tx_name), "%s txq%d",
		    device_get_nameunit(dev), i);
		mtx_init(&q->q_rx_mtx, q->q_name, "rge rxq", MTX_DEF);
		q->q_rx_mtx_inited = true;
	}

	if ((sc->rge_flags & RGE_FLAG_MULTIVEC) == 0 &&
	    rge_alloc_msi(sc) != 0)
		goto fail;

	/* Allocate top level bus DMA tag */
	error = bus_dma_tag_create(bus_get_dma_tag(dev),
	    1, /* alignment */
	    0, /* boundary */
	    BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR,
	    NULL, NULL, /* filter (unused) */
	    BUS_SPACE_MAXSIZE, /* maxsize */
	    BUS_SPACE_UNRESTRICTED, /* nsegments */
	    BUS_SPACE_MAXSIZE, /* maxsegsize */
	    0, /* flags */
	    NULL, NULL, /* lockfunc, lockarg */
	    &sc->sc_dmat);
	if (error) {
		RGE_PRINT_ERROR(sc,
		    "couldn't allocate device DMA tag (error %d)\n", error);
		goto fail;
	}

	/*
	 * Allocate TX/RX descriptor and buffer tags.
	 *
	 * The descriptor tags are sized for the larger (32 byte) v1
	 * descriptors; the v2 descriptor rings simply use the first half.
	 */
	error = bus_dma_tag_create(sc->sc_dmat,
	    RGE_ALIGN, /* alignment */
	    0, /* boundary */
	    BUS_SPACE_MAXADDR_32BIT, BUS_SPACE_MAXADDR,
	    NULL, NULL, /* filter (unused) */
	    RGE_TX_LIST_SZ, /* maxsize */
	    1, /* nsegments */
	    RGE_TX_LIST_SZ, /* maxsegsize */
	    0, /* flags */
	    NULL, NULL, /* lockfunc, lockarg */
	    &sc->sc_dmat_tx_desc);
	if (error) {
		RGE_PRINT_ERROR(sc,
		    "couldn't allocate device TX descriptor "
		    "DMA tag (error %d)\n", error);
		    goto fail;
	}

	error = bus_dma_tag_create(sc->sc_dmat,
	    1, /* alignment */
	    0, /* boundary */
	    BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR,
	    NULL, NULL, /* filter (unused) */
	    RGE_TSO_MAXSIZE, /* maxsize */
	    RGE_TX_NSEGS, /* nsegments */
	    RGE_JUMBO_FRAMELEN, /* maxsegsize */
	    0, /* flags */
	    NULL, NULL, /* lockfunc, lockarg */
	    &sc->sc_dmat_tx_buf);
	if (error) {
		RGE_PRINT_ERROR(sc,
		    "couldn't allocate device TX buffer DMA tag (error %d)\n",
		    error);
		goto fail;
	}

	error = bus_dma_tag_create(sc->sc_dmat,
	    RGE_ALIGN, /* alignment */
	    0, /* boundary */
	    BUS_SPACE_MAXADDR_32BIT, BUS_SPACE_MAXADDR,
	    NULL, NULL, /* filter (unused) */
	    RGE_RX_LIST_SZ, /* maxsize */
	    1, /* nsegments */
	    RGE_RX_LIST_SZ, /* maxsegsize */
	    0, /* flags */
	    NULL, NULL, /* lockfunc, lockarg */
	    &sc->sc_dmat_rx_desc);
	if (error) {
		RGE_PRINT_ERROR(sc,
		    "couldn't allocate device RX descriptor "
		    "DMA tag (error %d)\n", error);
		goto fail;
	}

	error = bus_dma_tag_create(sc->sc_dmat,
	    1, /* alignment */
	    0, /* boundary */
	    BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR,
	    NULL, NULL, /* filter (unused) */
	    MCLBYTES, /* maxsize */
	    1, /* nsegments */
	    MCLBYTES, /* maxsegsize */
	    0, /* flags */
	    NULL, NULL, /* lockfunc, lockarg */
	    &sc->sc_dmat_rx_buf);
	if (error) {
		RGE_PRINT_ERROR(sc,
		    "couldn't allocate device RX buffer DMA tag (error %d)\n",
		    error);
		goto fail;
	}

	error = bus_dma_tag_create(sc->sc_dmat,
	    RGE_STATS_ALIGNMENT, /* alignment */
	    0, /* boundary */
	    BUS_SPACE_MAXADDR, BUS_SPACE_MAXADDR,
	    NULL, NULL, /* filter (unused) */
	    RGE_STATS_BUF_SIZE, /* maxsize */
	    1, /* nsegments */
	    RGE_STATS_BUF_SIZE, /* maxsegsize */
	    0, /* flags */
	    NULL, NULL, /* lockfunc, lockarg */
	    &sc->sc_dmat_stats_buf);
	if (error) {
		RGE_PRINT_ERROR(sc,
		    "couldn't allocate device RX buffer DMA tag (error %d)\n",
		    error);
		goto fail;
	}

	/* Disable PCIe ASPM and ECPM if requested. */
	if (sc->sc_disable_aspm) {
		int ecap;
		if (pci_find_cap(dev, PCIY_EXPRESS, &ecap) == 0) {
			uint16_t lctl;
			lctl = pci_read_config(dev,
			    ecap + PCIER_LINK_CTL, 2);
			lctl &= ~(PCIEM_LINK_CTL_ASPMC |
			    PCIEM_LINK_CTL_ECPM);
			pci_write_config(dev,
			    ecap + PCIER_LINK_CTL, lctl, 2);
		}
	}

	RGE_LOCK(sc);
	if (rge_chipinit(sc)) {
		RGE_UNLOCK(sc);
		goto fail;
	}

	rge_get_macaddr(sc, eaddr.octet);
	RGE_UNLOCK(sc);

	if (!ETHER_IS_VALID(eaddr)) {
		device_printf(dev,
		    "No MAC address found.  Using ether_gen_addr().\n");
		ether_gen_addr_byname(device_get_nameunit(dev), &eaddr);
	}

	if (rge_allocmem(sc))
		goto fail;
	if (rge_alloc_stats_mem(sc))
		goto fail;

	/* Initialize ifmedia structures. */
	ifmedia_init(&sc->sc_media, IFM_IMASK, rge_ifmedia_upd,
	    rge_ifmedia_sts);
	rge_add_media_types(sc);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_AUTO, 0, NULL);
	ifmedia_set(&sc->sc_media, IFM_ETHER | IFM_AUTO);
	sc->sc_media.ifm_media = sc->sc_media.ifm_cur->ifm_media;

	rge_attach_if(sc, eaddr.octet);

	/*
	 * TODO: technically should be per txq but we only support
	 * one TXQ at the moment.
	 */
	mbufq_init(&sc->sc_txq, RGE_TX_LIST_CNT);

	snprintf(sc->sc_tq_name, sizeof(sc->sc_tq_name),
	    "%s taskq", device_get_nameunit(sc->sc_dev));
	snprintf(sc->sc_tq_thr_name, sizeof(sc->sc_tq_thr_name),
	    "%s taskq thread", device_get_nameunit(sc->sc_dev));

	sc->sc_tq = taskqueue_create(sc->sc_tq_name, M_NOWAIT,
	    taskqueue_thread_enqueue, &sc->sc_tq);
	taskqueue_start_threads(&sc->sc_tq, 1, PI_NET, "%s",
	    sc->sc_tq_thr_name);

	TASK_INIT(&sc->sc_tx_task, 0, rge_tx_task, sc);

	/* Hook up the MSI-X interrupts now that everything is set up. */
	if ((sc->rge_flags & RGE_FLAG_MULTIVEC) != 0) {
		if (rge_setup_msix_intr(sc) != 0)
			goto fail;
		device_printf(dev, "using MSI-X, %d RX queue%s\n",
		    sc->sc_nqueues, sc->sc_nqueues > 1 ? "s" : "");
	}

	return (0);
fail:
	rge_detach(dev);
	return (ENXIO);
}

/**
 * @brief flush the mbufq queue
 *
 * Again this should likely be per-TXQ.
 *
 * This should be called with the driver lock held.
 */
static void
rge_txq_flush_mbufs(struct rge_softc *sc)
{
	struct mbuf *m;
	int ntx = 0;

	RGE_ASSERT_LOCKED(sc);

	while ((m = mbufq_dequeue(&sc->sc_txq)) != NULL) {
		m_freem(m);
		ntx++;
	}

	RGE_DPRINTF(sc, RGE_DEBUG_XMIT, "%s: %d frames flushed\n", __func__,
	    ntx);
}

static int
rge_detach(device_t dev)
{
	struct rge_softc *sc = device_get_softc(dev);
	int i, rid;

	/* global flag, detaching */
	RGE_LOCK(sc);
	sc->sc_stopped = true;
	sc->sc_detaching = true;
	RGE_UNLOCK(sc);

	/* stop/drain network interface */
	callout_drain(&sc->sc_timeout);

	/* Make sure TX task isn't running */
	if (sc->sc_tq != NULL) {
		while (taskqueue_cancel(sc->sc_tq, &sc->sc_tx_task, NULL) != 0)
			taskqueue_drain(sc->sc_tq, &sc->sc_tx_task);
	}

	RGE_LOCK(sc);
	callout_stop(&sc->sc_timeout);

	/* stop NIC / DMA */
	if (sc->sc_bres != NULL && sc->sc_queues != NULL)
		rge_stop_locked(sc);

	/* TODO: wait for completion */

	/* Free pending TX mbufs */
	rge_txq_flush_mbufs(sc);

	RGE_UNLOCK(sc);

	/*
	 * Tear down the MSI-X interrupts and the RX queue taskqueues
	 * before the rings they service are freed.
	 */
	rge_teardown_msix_intr(sc);

	/* Free taskqueue */
	if (sc->sc_tq != NULL) {
		taskqueue_free(sc->sc_tq);
		sc->sc_tq = NULL;
	}

	/* Free descriptor memory */
	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: freemem\n", __func__);
	rge_freemem(sc);
	rge_free_stats_mem(sc);

	if (sc->sc_ifp) {
		RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: ifdetach/if_free\n",
		    __func__);
		if (sc->sc_ether_attached)
			ether_ifdetach(sc->sc_ifp);
		if_free(sc->sc_ifp);
	}

	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: sc_dmat_tx_desc\n", __func__);
	if (sc->sc_dmat_tx_desc)
		bus_dma_tag_destroy(sc->sc_dmat_tx_desc);
	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: sc_dmat_tx_buf\n", __func__);
	if (sc->sc_dmat_tx_buf)
		bus_dma_tag_destroy(sc->sc_dmat_tx_buf);
	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: sc_dmat_rx_desc\n", __func__);
	if (sc->sc_dmat_rx_desc)
		bus_dma_tag_destroy(sc->sc_dmat_rx_desc);
	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: sc_dmat_rx_buf\n", __func__);
	if (sc->sc_dmat_rx_buf)
		bus_dma_tag_destroy(sc->sc_dmat_rx_buf);
	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: sc_dmat_stats_buf\n", __func__);
	if (sc->sc_dmat_stats_buf)
		bus_dma_tag_destroy(sc->sc_dmat_stats_buf);
	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: sc_dmat\n", __func__);
	if (sc->sc_dmat)
		bus_dma_tag_destroy(sc->sc_dmat);

	/* Teardown interrupts */
	for (i = 0; i < RGE_MSI_MESSAGES; i++) {
		if (sc->sc_ih[i] != NULL) {
			bus_teardown_intr(sc->sc_dev, sc->sc_irq[i],
			    sc->sc_ih[i]);
			sc->sc_ih[i] = NULL;
		}
	}

	/* Free interrupt resources */
	for (i = 0, rid = 1; i < RGE_MSI_MESSAGES; i++, rid++) {
		if (sc->sc_irq[i] != NULL) {
			bus_release_resource(sc->sc_dev, SYS_RES_IRQ,
			    rid, sc->sc_irq[i]);
			sc->sc_irq[i] = NULL;
		}
	}

	/* Free MSI/MSI-X allocation */
	if (sc->rge_flags & (RGE_FLAG_MSI | RGE_FLAG_MULTIVEC))
		pci_release_msi(dev);

	if (sc->sc_bres) {
		RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: release mmio\n",
		    __func__);
		bus_release_resource(dev, SYS_RES_MEMORY,
		    rman_get_rid(sc->sc_bres), sc->sc_bres);
		sc->sc_bres = NULL;
	}

	if (sc->sc_queues) {
		for (i = 0; i < sc->sc_nqueues; i++) {
			if (sc->sc_queues[i].q_rx_mtx_inited)
				mtx_destroy(&sc->sc_queues[i].q_rx_mtx);
		}
		free(sc->sc_queues, M_DEVBUF);
		sc->sc_queues = NULL;
	}

	mtx_destroy(&sc->sc_mtx);

	return (0);
}

/**
 * @brief Allocate and hook up the single MSI interrupt.
 */
static int
rge_alloc_msi(struct rge_softc *sc)
{
	device_t dev = sc->sc_dev;
	int error, i, msic, rid;

	/* Allocate MSI */
	msic = pci_msi_count(dev);
	if (msic == 0) {
		RGE_PRINT_ERROR(sc, "%s: only MSI interrupts supported\n",
		    __func__);
		return (ENXIO);
	}

	msic = RGE_MSI_MESSAGES;
	if (pci_alloc_msi(dev, &msic) != 0) {
		RGE_PRINT_ERROR(sc, "%s: failed to allocate MSI\n",
		    __func__);
		return (ENXIO);
	}

	sc->rge_flags |= RGE_FLAG_MSI;

	/* We need at least one MSI */
	if (msic < RGE_MSI_MESSAGES) {
		RGE_PRINT_ERROR(sc, "%s: didn't allocate enough MSI\n",
		    __func__);
		return (ENXIO);
	}

	/*
	 * Allocate interrupt entries.
	 */
	for (i = 0, rid = 1; i < RGE_MSI_MESSAGES; i++, rid++) {
		sc->sc_irq[i] = bus_alloc_resource_any(dev, SYS_RES_IRQ,
		    &rid, RF_ACTIVE);
		if (sc->sc_irq[i] == NULL) {
			RGE_PRINT_ERROR(sc, "%s: couldn't allocate MSI %d",
			    __func__, rid);
			return (ENXIO);
		}
	}

	/* Hook interrupts */
	for (i = 0; i < RGE_MSI_MESSAGES; i++) {
		error = bus_setup_intr(dev, sc->sc_irq[i],
		    INTR_TYPE_NET | INTR_MPSAFE, NULL, rge_intr_msi,
		    sc, &sc->sc_ih[i]);
		if (error != 0) {
			RGE_PRINT_ERROR(sc,
			    "%s: couldn't setup intr %d (error %d)", __func__,
			    i, error);
			return (error);
		}
	}

	return (0);
}

/**
 * @brief Allocate the MSI-X vectors used by the RTL8127.
 *
 * The RTL8127 MSI-X table has fixed slots: RX queue N uses vector N,
 * TX queue N uses vector RGE_TX_VECTOR_8127(N) and the link interrupt
 * uses vector RGE_LINK_VECTOR_8127.  Only allocate IRQs for the vectors
 * actually used and use pci_remap_msix() to sparsely populate the table.
 *
 * On success RGE_FLAG_MULTIVEC is set and sc_nqueues holds the number
 * of RX queues to use.  On failure nothing is changed and the caller
 * falls back to a single MSI interrupt.
 */
static int
rge_alloc_msix(struct rge_softc *sc)
{
	device_t dev = sc->sc_dev;
	u_int *vectors;
	int error, i, msgs, nqueues;

	if (pci_msix_count(dev) < sc->rge_min_msix)
		return (ENXIO);

	nqueues = MIN(RGE_MAX_VECTORS_8127, mp_ncpus);
#ifdef RSS
	nqueues = MIN(nqueues, rss_getnumbuckets());
#endif
	if (sc->sc_max_rx_queues > 0)
		nqueues = MIN(nqueues, sc->sc_max_rx_queues);
	if (nqueues < 1)
		nqueues = 1;
	/* The hardware wants a power of two number of RX queues. */
	nqueues = 1 << (fls(nqueues) - 1);

	/* RX queues, plus one TX vector and the link vector. */
	msgs = nqueues + 2;
	if (pci_alloc_msix(dev, &msgs) != 0)
		return (ENXIO);
	if (msgs < 3) {
		pci_release_msi(dev);
		return (ENXIO);
	}
	nqueues = MIN(nqueues, msgs - 2);
	nqueues = 1 << (fls(nqueues) - 1);

	vectors = mallocarray(sc->rge_min_msix, sizeof(*vectors), M_DEVBUF,
	    M_WAITOK | M_ZERO);
	for (i = 0; i < nqueues; i++)
		vectors[i] = i + 1;
	vectors[RGE_TX_VECTOR_8127(0)] = nqueues + 1;
	vectors[sc->sc_linkvec] = nqueues + 2;
	error = pci_remap_msix(dev, sc->rge_min_msix, vectors);
	free(vectors, M_DEVBUF);
	if (error != 0) {
		RGE_PRINT_ERROR(sc, "%s: couldn't remap MSI-X (error %d)\n",
		    __func__, error);
		pci_release_msi(dev);
		return (error);
	}

	sc->sc_nqueues = nqueues;
	sc->rge_flags |= RGE_FLAG_MULTIVEC;
	return (0);
}

/**
 * @brief Hook up the per-queue and link MSI-X interrupts.
 *
 * The SYS_RES_IRQ rid for MSI-X table slot N is N + 1.
 */
static int
rge_setup_msix_intr(struct rge_softc *sc)
{
	device_t dev = sc->sc_dev;
	struct rge_queues *q;
	cpuset_t cpus;
	int error, i, rid;
#ifndef RSS
	int cpu = CPU_FIRST();
#endif

	for (i = 0; i < sc->sc_nqueues; i++) {
		q = &sc->sc_queues[i];
#ifdef RSS
		q->q_cpu = rss_getcpu(i % rss_getnumbuckets());
#else
		q->q_cpu = cpu;
		cpu = CPU_NEXT(cpu);
#endif

		TASK_INIT(&q->q_rx_task, 0, rge_rxq_task, q);
		q->q_tq = taskqueue_create_fast("rge_rxq", M_WAITOK,
		    taskqueue_thread_enqueue, &q->q_tq);
		CPU_SETOF(q->q_cpu, &cpus);
		taskqueue_start_threads_cpuset(&q->q_tq, 1, PI_NET, &cpus,
		    "%s", q->q_name);

		rid = q->q_index + 1;
		q->q_irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
		    RF_ACTIVE);
		if (q->q_irq == NULL) {
			RGE_PRINT_ERROR(sc, "couldn't allocate RX queue %d "
			    "MSI-X vector\n", i);
			return (ENXIO);
		}
		error = bus_setup_intr(dev, q->q_irq,
		    INTR_TYPE_NET | INTR_MPSAFE, NULL, rge_intr_rxq, q,
		    &q->q_ihc);
		if (error != 0) {
			RGE_PRINT_ERROR(sc, "couldn't setup RX queue %d "
			    "interrupt (error %d)\n", i, error);
			return (error);
		}
		bus_describe_intr(dev, q->q_irq, q->q_ihc, "rxq%d", i);
		bus_bind_intr(dev, q->q_irq, q->q_cpu);
	}

	for (i = 0; i < sc->sc_ntxqs; i++) {
		q = &sc->sc_queues[i];
		rid = q->q_tx_index + 1;
		q->q_tx_irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
		    RF_ACTIVE);
		if (q->q_tx_irq == NULL) {
			RGE_PRINT_ERROR(sc, "couldn't allocate TX queue %d "
			    "MSI-X vector\n", i);
			return (ENXIO);
		}
		error = bus_setup_intr(dev, q->q_tx_irq,
		    INTR_TYPE_NET | INTR_MPSAFE, NULL, rge_intr_txq, q,
		    &q->q_tx_ihc);
		if (error != 0) {
			RGE_PRINT_ERROR(sc, "couldn't setup TX queue %d "
			    "interrupt (error %d)\n", i, error);
			return (error);
		}
		bus_describe_intr(dev, q->q_tx_irq, q->q_tx_ihc, "txq%d", i);
		bus_bind_intr(dev, q->q_tx_irq, q->q_cpu);
	}

	rid = sc->sc_linkvec + 1;
	sc->sc_link_irq = bus_alloc_resource_any(dev, SYS_RES_IRQ, &rid,
	    RF_ACTIVE);
	if (sc->sc_link_irq == NULL) {
		RGE_PRINT_ERROR(sc, "couldn't allocate link MSI-X vector\n");
		return (ENXIO);
	}
	error = bus_setup_intr(dev, sc->sc_link_irq,
	    INTR_TYPE_NET | INTR_MPSAFE, NULL, rge_intr_link, sc,
	    &sc->sc_link_ih);
	if (error != 0) {
		RGE_PRINT_ERROR(sc, "couldn't setup link interrupt "
		    "(error %d)\n", error);
		return (error);
	}
	bus_describe_intr(dev, sc->sc_link_irq, sc->sc_link_ih, "link");

	return (0);
}

/**
 * @brief Tear down the MSI-X interrupts and RX queue taskqueues.
 *
 * Safe to call on a partially set up softc.
 */
static void
rge_teardown_msix_intr(struct rge_softc *sc)
{
	device_t dev = sc->sc_dev;
	struct rge_queues *q;
	int i;

	if (sc->sc_link_ih != NULL) {
		bus_teardown_intr(dev, sc->sc_link_irq, sc->sc_link_ih);
		sc->sc_link_ih = NULL;
	}
	if (sc->sc_link_irq != NULL) {
		bus_release_resource(dev, SYS_RES_IRQ,
		    rman_get_rid(sc->sc_link_irq), sc->sc_link_irq);
		sc->sc_link_irq = NULL;
	}

	if (sc->sc_queues == NULL)
		return;

	for (i = 0; i < sc->sc_nqueues; i++) {
		q = &sc->sc_queues[i];
		if (q->q_tx_ihc != NULL) {
			bus_teardown_intr(dev, q->q_tx_irq, q->q_tx_ihc);
			q->q_tx_ihc = NULL;
		}
		if (q->q_tx_irq != NULL) {
			bus_release_resource(dev, SYS_RES_IRQ,
			    rman_get_rid(q->q_tx_irq), q->q_tx_irq);
			q->q_tx_irq = NULL;
		}
		if (q->q_ihc != NULL) {
			bus_teardown_intr(dev, q->q_irq, q->q_ihc);
			q->q_ihc = NULL;
		}
		if (q->q_irq != NULL) {
			bus_release_resource(dev, SYS_RES_IRQ,
			    rman_get_rid(q->q_irq), q->q_irq);
			q->q_irq = NULL;
		}
		if (q->q_tq != NULL) {
			while (taskqueue_cancel(q->q_tq, &q->q_rx_task,
			    NULL) != 0)
				taskqueue_drain(q->q_tq, &q->q_rx_task);
			taskqueue_free(q->q_tq);
			q->q_tq = NULL;
		}
	}
}

static void
rge_intr_msi(void *arg)
{
	struct mbufq rx_mq;
	struct epoch_tracker et;
	struct mbuf *m;
	struct rge_softc *sc = arg;
	struct rge_queues *q = &sc->sc_queues[0];
	uint32_t status;
	int claimed = 0, rv;

	sc->sc_drv_stats.intr_cnt++;

	mbufq_init(&rx_mq, RGE_RX_LIST_CNT);

	if ((if_getdrvflags(sc->sc_ifp) & IFF_DRV_RUNNING) == 0)
		return;

	RGE_LOCK(sc);

	if (sc->sc_suspended || sc->sc_stopped || sc->sc_detaching) {
		RGE_UNLOCK(sc);
		return;
	}

	/* Disable interrupts. */
	RGE_WRITE_4(sc, RGE_IMR, 0);

	if (!(sc->rge_flags & RGE_FLAG_MSI)) {
		if ((RGE_READ_4(sc, RGE_ISR) & sc->rge_intrs) == 0)
			goto done;
	}

	status = RGE_READ_4(sc, RGE_ISR);
	if (status)
		RGE_WRITE_4(sc, RGE_ISR, status);

	if (status & RGE_ISR_PCS_TIMEOUT)
		claimed = 1;

	rv = 0;
	if (status & sc->rge_intrs) {

		RGE_RXQ_LOCK(q);
		rv |= rge_rxeof(q, &rx_mq, NULL);
		RGE_RXQ_UNLOCK(q);
		rv |= rge_txeof(q);

		if (status & RGE_ISR_SYSTEM_ERR) {
			sc->sc_drv_stats.intr_system_err_cnt++;
			rge_init_locked(sc);
		}
		claimed = 1;
	}

	if (sc->rge_timerintr) {
		if (!rv) {
			/*
			 * Nothing needs to be processed, fallback
			 * to use TX/RX interrupts.
			 */
			rge_setup_intr(sc, RGE_IMTYPE_NONE);

			/*
			 * Recollect, mainly to avoid the possible
			 * race introduced by changing interrupt
			 * masks.
			 */
			RGE_RXQ_LOCK(q);
			rge_rxeof(q, &rx_mq, NULL);
			RGE_RXQ_UNLOCK(q);
			rge_txeof(q);
		} else
			RGE_WRITE_4(sc, RGE_TIMERCNT, 1);
	} else if (rv) {
		/*
		 * Assume that using simulated interrupt moderation
		 * (hardware timer based) could reduce the interrupt
		 * rate.
		 */
		rge_setup_intr(sc, RGE_IMTYPE_SIM);
	}

	RGE_WRITE_4(sc, RGE_IMR, sc->rge_intrs);

done:
	RGE_UNLOCK(sc);

	NET_EPOCH_ENTER(et);
	/* Handle any RX frames, outside of the driver lock */
	while ((m = mbufq_dequeue(&rx_mq)) != NULL) {
		sc->sc_drv_stats.recv_input_cnt++;
		if_input(sc->sc_ifp, m);
	}
	NET_EPOCH_EXIT(et);

	(void) claimed;
}

/**
 * @brief MSI-X link state interrupt.
 */
static void
rge_intr_link(void *arg)
{
	struct rge_softc *sc = arg;

	rge_disable_queue(sc, sc->sc_linkvec);

	RGE_LOCK(sc);
	if (sc->sc_suspended || sc->sc_stopped || sc->sc_detaching) {
		RGE_UNLOCK(sc);
		return;
	}
	sc->sc_drv_stats.intr_cnt++;
	rge_link_state(sc);
	rge_enable_queue(sc, sc->sc_linkvec);
	RGE_UNLOCK(sc);
}

/**
 * @brief Service an RX queue in multi-vector mode.
 *
 * Process up to rx_process_limit frames.  If there's more work pending
 * then re-schedule via the queue taskqueue, leaving the vector masked;
 * otherwise unmask the queue vector.
 *
 * This is called without any locks held.
 */
static void
rge_rxq_service(struct rge_queues *q)
{
	struct rge_softc *sc = q->q_sc;
	struct epoch_tracker et;
	struct mbufq rx_mq;
	struct mbuf *m;
	bool more = false;

	mbufq_init(&rx_mq, RGE_RX_LIST_CNT);

	RGE_RXQ_LOCK(q);
	if ((if_getdrvflags(sc->sc_ifp) & IFF_DRV_RUNNING) == 0 ||
	    sc->sc_suspended || sc->sc_stopped || sc->sc_detaching) {
		/* Leave the vector masked; rge_init_locked() unmasks it */
		RGE_RXQ_UNLOCK(q);
		return;
	}

	rge_rxeof(q, &rx_mq, &more);
	if (!more)
		rge_enable_queue(sc, q->q_index);
	RGE_RXQ_UNLOCK(q);

	NET_EPOCH_ENTER(et);
	/* Handle any RX frames, outside of the queue lock */
	while ((m = mbufq_dequeue(&rx_mq)) != NULL) {
		sc->sc_drv_stats.recv_input_cnt++;
		if_input(sc->sc_ifp, m);
	}
	NET_EPOCH_EXIT(et);

	if (more)
		taskqueue_enqueue(q->q_tq, &q->q_rx_task);
}

/**
 * @brief MSI-X RX queue interrupt.
 */
static void
rge_intr_rxq(void *arg)
{
	struct rge_queues *q = arg;

	rge_disable_queue(q->q_sc, q->q_index);
	rge_rxq_service(q);
}

/**
 * @brief Deferred RX queue processing.
 */
static void
rge_rxq_task(void *arg, int npending __unused)
{
	struct rge_queues *q = arg;

	rge_rxq_service(q);
}

/**
 * @brief MSI-X TX queue completion interrupt.
 */
static void
rge_intr_txq(void *arg)
{
	struct rge_queues *q = arg;
	struct rge_softc *sc = q->q_sc;

	rge_disable_queue(sc, q->q_tx_index);

	RGE_LOCK(sc);
	if ((if_getdrvflags(sc->sc_ifp) & IFF_DRV_RUNNING) == 0 ||
	    sc->sc_suspended || sc->sc_stopped || sc->sc_detaching) {
		RGE_UNLOCK(sc);
		return;
	}
	rge_txeof(q);
	rge_enable_queue(sc, q->q_tx_index);
	RGE_UNLOCK(sc);
}

static inline void
rge_tx_list_sync(struct rge_softc *sc, struct rge_queues *q,
    unsigned int idx, unsigned int len, int ops)
{
	bus_dmamap_sync(sc->sc_dmat_tx_desc, q->q_tx.rge_tx_list_map, ops);
}

/**
 * @brief Queue the given mbuf at the given TX slot index for transmit.
 *
 * If the frame couldn't be enqueued then 0 is returned.
 * The caller needs to handle that and free/re-queue the mbuf as required.
 *
 * Note that this doesn't actually kick-start the transmit itself;
 * see rge_txstart() for the register to poke to start transmit.
 *
 * This must be called with the driver lock held.
 *
 * @param sc	driver softc
 * @param q	TX queue ring
 * @param mp	mbuf to enqueue, updated if defragmentation replaces it
 * @returns	if the mbuf is enqueued, it's consumed here and the number of
 * 		TX descriptors used is returned; if there's no space then 0 is
 *		returned; if the mbuf couldn't be mapped and the caller should
 *		free it then -1 is returned.
 */
/**
 * @brief Fill in a TX descriptor (v1 or v2 format).
 *
 * Note: vendor driver puts wmb() after opts2/extsts,
 * before opts1/status.
 *
 * It does this:
 * - set rge_addr
 * - set extsts
 * - wmb
 * - set status - at this point it's owned by the hardware
 */
static inline void
rge_tx_desc_fill(struct rge_softc *sc, struct rge_queues *q, int idx,
    uint64_t addr, uint32_t extsts, uint32_t cmdsts)
{
	if (sc->rge_flags & RGE_FLAG_DESCV2) {
		struct rge_tx_desc_v2 *d = &q->q_tx.rge_tx_list_v2[idx];

		d->rge_addr = htole64(addr);
		d->rge_extsts = htole32(extsts);
		wmb();
		d->rge_cmdsts = htole32(cmdsts);
	} else {
		struct rge_tx_desc *d = &q->q_tx.rge_tx_list[idx];

		d->rge_addr = htole64(addr);
		d->rge_extsts = htole32(extsts);
		wmb();
		d->rge_cmdsts = htole32(cmdsts);
	}
}

static inline void
rge_tx_desc_set_cmdsts(struct rge_softc *sc, struct rge_queues *q, int idx,
    uint32_t cmdsts)
{
	if (sc->rge_flags & RGE_FLAG_DESCV2)
		q->q_tx.rge_tx_list_v2[idx].rge_cmdsts = htole32(cmdsts);
	else
		q->q_tx.rge_tx_list[idx].rge_cmdsts = htole32(cmdsts);
}

static int
rge_encap(struct rge_softc *sc, struct rge_queues *q, struct mbuf **mp,
    int idx)
{
	struct rge_txq *txq;
	bus_dmamap_t txmap;
	struct mbuf *m;
	uint32_t cmdsts, cflags = 0, tflags = 0;
	int cur, error, i;
	bus_dma_segment_t seg[RGE_TX_NSEGS];
	int nsegs;

	RGE_ASSERT_LOCKED(sc);

	m = *mp;
	txq = &q->q_tx.rge_txq[idx];
	txmap = txq->txq_dmamap;

	sc->sc_drv_stats.tx_encap_cnt++;

	/* Work out the VLAN / checksum / TSO descriptor bits */
	if (rge_tx_offload(sc, m, &cflags, &tflags) != 0)
		return (-1);

	nsegs = RGE_TX_NSEGS;
	error = bus_dmamap_load_mbuf_sg(sc->sc_dmat_tx_buf, txmap, m,
	    seg, &nsegs, BUS_DMA_NOWAIT);

	switch (error) {
	case 0:
		break;
	case EFBIG: /* mbuf chain is too fragmented */
		sc->sc_drv_stats.tx_encap_refrag_cnt++;
		nsegs = RGE_TX_NSEGS;
		m = m_defrag(m, M_NOWAIT);
		if (m != NULL) {
			*mp = m;
			if (bus_dmamap_load_mbuf_sg(sc->sc_dmat_tx_buf, txmap,
			    m, seg, &nsegs, BUS_DMA_NOWAIT) == 0)
				break;
		}
		/* FALLTHROUGH */
	default:
		sc->sc_drv_stats.tx_encap_err_toofrag++;
		return (-1);
	}

	bus_dmamap_sync(sc->sc_dmat_tx_buf, txmap, BUS_DMASYNC_PREWRITE);

	cur = idx;
	for (i = 1; i < nsegs; i++) {
		cur = RGE_NEXT_TX_DESC(cur);

		cmdsts = RGE_TDCMDSTS_OWN | tflags;
		cmdsts |= seg[i].ds_len;

		if (cur == RGE_TX_LIST_CNT - 1)
			cmdsts |= RGE_TDCMDSTS_EOR;
		if (i == nsegs - 1)
			cmdsts |= RGE_TDCMDSTS_EOF;

		rge_tx_desc_fill(sc, q, cur, seg[i].ds_addr, cflags, cmdsts);
	}

	/* Update info of TX queue and descriptors. */
	txq->txq_mbuf = m;
	txq->txq_descidx = cur;

	cmdsts = RGE_TDCMDSTS_SOF | tflags;
	cmdsts |= seg[0].ds_len;

	if (idx == RGE_TX_LIST_CNT - 1)
		cmdsts |= RGE_TDCMDSTS_EOR;
	if (nsegs == 1)
		cmdsts |= RGE_TDCMDSTS_EOF;

	rge_tx_desc_fill(sc, q, idx, seg[0].ds_addr, cflags, cmdsts);
	wmb();

	if (cur >= idx) {
		rge_tx_list_sync(sc, q, idx, nsegs,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	} else {
		rge_tx_list_sync(sc, q, idx, RGE_TX_LIST_CNT - idx,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
		rge_tx_list_sync(sc, q, 0, cur + 1,
		    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	}

	/* Transfer ownership of packet to the chip. */
	cmdsts |= RGE_TDCMDSTS_OWN;
	rge_tx_list_sync(sc, q, idx, 1, BUS_DMASYNC_POSTWRITE);
	rge_tx_desc_set_cmdsts(sc, q, idx, cmdsts);
	rge_tx_list_sync(sc, q, idx, 1, BUS_DMASYNC_PREWRITE);
	wmb();

	return (nsegs);
}

static int
rge_ioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	struct rge_softc *sc = if_getsoftc(ifp);
	struct ifreq *ifr = (struct ifreq *)data;
	int error = 0;

	switch (cmd) {
	case SIOCSIFMTU:
		/* Note: no hardware reinit is required */
		if (ifr->ifr_mtu < ETHERMIN || ifr->ifr_mtu > RGE_JUMBO_MTU) {
			error = EINVAL;
			break;
		}
		if (if_getmtu(ifp) != ifr->ifr_mtu)
			if_setmtu(ifp, ifr->ifr_mtu);

		VLAN_CAPABILITIES(ifp);
		break;

	case SIOCSIFFLAGS:
		RGE_LOCK(sc);
		if ((if_getflags(ifp) & IFF_UP) != 0) {
			if ((if_getdrvflags(ifp) & IFF_DRV_RUNNING) != 0) {
				if (((if_getflags(ifp) ^ sc->rge_if_flags)
				    & (IFF_PROMISC | IFF_ALLMULTI)) != 0)
					rge_iff_locked(sc);
			} else
				rge_init_locked(sc);
		} else {
			if ((if_getdrvflags(ifp) & IFF_DRV_RUNNING) != 0)
				rge_stop_locked(sc);
		}
		sc->rge_if_flags = if_getflags(ifp);
		RGE_UNLOCK(sc);
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		RGE_LOCK(sc);
		if ((if_getdrvflags(ifp) & IFF_DRV_RUNNING) != 0)
			rge_iff_locked(sc);
		RGE_UNLOCK(sc);
		break;
	case SIOCGIFMEDIA:
	case SIOCSIFMEDIA:
		error = ifmedia_ioctl(ifp, ifr, &sc->sc_media, cmd);
		break;
	case SIOCSIFCAP:
		{
			int mask;
			bool reinit = false;

			/* Get the mask of changed bits */
			mask = ifr->ifr_reqcap ^ if_getcapenable(ifp);

			/*
			 * Locked so we don't have a narrow window where frames
			 * are being processed with the updated flags but the
			 * hardware configuration hasn't yet changed.
			 */
			RGE_LOCK(sc);

			if ((mask & IFCAP_TXCSUM) != 0 &&
			    (if_getcapabilities(ifp) & IFCAP_TXCSUM) != 0) {
				if_togglecapenable(ifp, IFCAP_TXCSUM);
				if ((if_getcapenable(ifp) & IFCAP_TXCSUM) != 0)
					if_sethwassistbits(ifp, RGE_CSUM_FEATURES, 0);
				else
					if_sethwassistbits(ifp, 0, RGE_CSUM_FEATURES);
				reinit = 1;
			}

			if ((mask & IFCAP_TXCSUM_IPV6) != 0 &&
			    (if_getcapabilities(ifp) &
			    IFCAP_TXCSUM_IPV6) != 0) {
				if_togglecapenable(ifp, IFCAP_TXCSUM_IPV6);
				if ((if_getcapenable(ifp) &
				    IFCAP_TXCSUM_IPV6) != 0)
					if_sethwassistbits(ifp,
					    RGE_CSUM_FEATURES_IPV6, 0);
				else
					if_sethwassistbits(ifp, 0,
					    RGE_CSUM_FEATURES_IPV6);
			}

			if ((mask & IFCAP_TSO4) != 0 &&
			    (if_getcapabilities(ifp) & IFCAP_TSO4) != 0) {
				if_togglecapenable(ifp, IFCAP_TSO4);
				if ((if_getcapenable(ifp) & IFCAP_TSO4) != 0)
					if_sethwassistbits(ifp, CSUM_IP_TSO, 0);
				else
					if_sethwassistbits(ifp, 0, CSUM_IP_TSO);
			}

			if ((mask & IFCAP_TSO6) != 0 &&
			    (if_getcapabilities(ifp) & IFCAP_TSO6) != 0) {
				if_togglecapenable(ifp, IFCAP_TSO6);
				if ((if_getcapenable(ifp) & IFCAP_TSO6) != 0)
					if_sethwassistbits(ifp, CSUM_IP6_TSO,
					    0);
				else
					if_sethwassistbits(ifp, 0,
					    CSUM_IP6_TSO);
			}

			/* TSO needs the matching TX checksum offload */
			if ((if_getcapenable(ifp) & IFCAP_TXCSUM) == 0 &&
			    (if_getcapenable(ifp) & IFCAP_TSO4) != 0) {
				if_setcapenablebit(ifp, 0, IFCAP_TSO4);
				if_sethwassistbits(ifp, 0, CSUM_IP_TSO);
			}
			if ((if_getcapenable(ifp) & IFCAP_TXCSUM_IPV6) == 0 &&
			    (if_getcapenable(ifp) & IFCAP_TSO6) != 0) {
				if_setcapenablebit(ifp, 0, IFCAP_TSO6);
				if_sethwassistbits(ifp, 0, CSUM_IP6_TSO);
			}

			if ((mask & IFCAP_VLAN_HWTAGGING) != 0 &&
			    (if_getcapabilities(ifp) & IFCAP_VLAN_HWTAGGING) != 0) {
				if_togglecapenable(ifp, IFCAP_VLAN_HWTAGGING);
				reinit = 1;
			}

			if ((mask & IFCAP_VLAN_HWTSO) != 0 &&
			    (if_getcapabilities(ifp) & IFCAP_VLAN_HWTSO) != 0)
				if_togglecapenable(ifp, IFCAP_VLAN_HWTSO);

			if ((mask & IFCAP_WOL_MAGIC) != 0 &&
			    (if_getcapabilities(ifp) & IFCAP_WOL_MAGIC) != 0)
				if_togglecapenable(ifp, IFCAP_WOL_MAGIC);

			if ((mask & IFCAP_RXCSUM) != 0 &&
			    (if_getcapabilities(ifp) & IFCAP_RXCSUM) != 0) {
				if_togglecapenable(ifp, IFCAP_RXCSUM);
				reinit = 1;
			}

			if (reinit && if_getdrvflags(ifp) & IFF_DRV_RUNNING) {
				if_setdrvflagbits(ifp, 0, IFF_DRV_RUNNING);
				rge_init_locked(sc);
			}

			RGE_UNLOCK(sc);
			VLAN_CAPABILITIES(ifp);
		}
		break;
	default:
		error = ether_ioctl(ifp, cmd, data);
		break;
	}

	return (error);
}

static void
rge_qflush_if(if_t ifp)
{
	struct rge_softc *sc = if_getsoftc(ifp);

	/* TODO: this should iterate over the TXQs */
	RGE_LOCK(sc);
	rge_txq_flush_mbufs(sc);
	RGE_UNLOCK(sc);
}

/**
 * @brief Transmit the given frame to the hardware.
 *
 * This routine is called by the network stack to send
 * a frame to the device.
 *
 * For now we simply direct dispatch this frame to the
 * hardware (and thus avoid maintaining our own internal
 * queue)
 */
static int
rge_transmit_if(if_t ifp, struct mbuf *m)
{
	struct rge_softc *sc = if_getsoftc(ifp);
	int ret;

	sc->sc_drv_stats.transmit_call_cnt++;

	RGE_LOCK(sc);
	if (sc->sc_stopped == true) {
		sc->sc_drv_stats.transmit_stopped_cnt++;
		RGE_UNLOCK(sc);
		return (ENETDOWN);	/* TODO: better error? */
	}

	/* XXX again should be a per-TXQ thing */
	ret = mbufq_enqueue(&sc->sc_txq, m);
	if (ret != 0) {
		sc->sc_drv_stats.transmit_full_cnt++;
		RGE_UNLOCK(sc);
		return (ret);
	}
	RGE_UNLOCK(sc);

	/* mbuf is owned by the driver, schedule transmit */
	taskqueue_enqueue(sc->sc_tq, &sc->sc_tx_task);
	sc->sc_drv_stats.transmit_queued_cnt++;

	return (0);
}

static void
rge_init_if(void *xsc)
{
	struct rge_softc *sc = xsc;

	RGE_LOCK(sc);
	rge_init_locked(sc);
	RGE_UNLOCK(sc);
}

/**
 * @brief Unmask the MSI-X vectors in multi-vector mode.
 *
 * Each RX queue vector is unmasked with its queue lock held so the
 * queue interrupt handler is guaranteed to observe the interface as
 * running once it acquires the lock.
 *
 * Must be called with the driver lock held.
 */
static void
rge_enable_queues(struct rge_softc *sc)
{
	struct rge_queues *q;
	int i;

	RGE_ASSERT_LOCKED(sc);

	for (i = 0; i < sc->sc_nqueues; i++) {
		q = &sc->sc_queues[i];
		RGE_RXQ_LOCK(q);
		rge_enable_queue(sc, q->q_index);
		RGE_RXQ_UNLOCK(q);
		if (i < sc->sc_ntxqs)
			rge_enable_queue(sc, q->q_tx_index);
	}
	rge_enable_queue(sc, sc->sc_linkvec);
}

static void
rge_init_locked(struct rge_softc *sc)
{
	uint32_t rxconf, val;
	int i, num_miti;

	RGE_ASSERT_LOCKED(sc);

	RGE_DPRINTF(sc, RGE_DEBUG_INIT, "%s: called!\n", __func__);

	/* Don't double-init the hardware */
	if ((if_getdrvflags(sc->sc_ifp) & IFF_DRV_RUNNING) != 0) {
		/*
		 * Note: I'm leaving this disabled by default; however
		 * I'm leaving it in here so I can figure out what's
		 * causing this to be initialised both from the ioctl
		 * API and if_init() API.
		 */
/*		RGE_PRINT_ERROR(sc, "%s: called whilst running?\n", __func__); */
		return;
	}

	/*
	 * Bring the hardware down so we know it's in a good known
	 * state before we bring it up in a good known state.
	 */
	rge_stop_locked(sc);

	/* Set MAC address. */
	rge_set_macaddr(sc, if_getlladdr(sc->sc_ifp));

	/* Initialize RX and TX descriptors lists. */
	for (i = 0; i < sc->sc_nqueues; i++) {
		RGE_RXQ_LOCK(&sc->sc_queues[i]);
		rge_rx_list_init(&sc->sc_queues[i]);
		RGE_RXQ_UNLOCK(&sc->sc_queues[i]);
	}
	rge_tx_list_init(&sc->sc_queues[0]);

	if (rge_chipinit(sc)) {
		RGE_PRINT_ERROR(sc, "%s: ERROR: chip init fail!\n", __func__);
		return;
	}

	if (rge_phy_config(sc))
		return;

	RGE_SETBIT_1(sc, RGE_EECMD, RGE_EECMD_WRITECFG);

	RGE_CLRBIT_1(sc, 0xf1, 0x80);
	rge_disable_aspm_clkreq(sc);
	RGE_WRITE_2(sc, RGE_EEE_TXIDLE_TIMER,
	    RGE_JUMBO_MTU + ETHER_HDR_LEN + 32);

	/* Load the addresses of the RX and TX lists into the chip. */
	for (i = 0; i < sc->sc_nqueues; i++)
		rge_fill_rx_desc_addr(&sc->sc_queues[i], i);
	rge_fill_tx_desc_addr(&sc->sc_queues[0], 0);

	/* Set the initial RX and TX configurations. */
	if (sc->rge_type == MAC_R25)
		rxconf = RGE_RXCFG_CONFIG;
	else if (sc->rge_type == MAC_R25B)
		rxconf = RGE_RXCFG_CONFIG_8125B;
	else if (RGE_TYPE_R25D(sc))
		rxconf = RGE_RXCFG_CONFIG_8125D;
	else
		rxconf = RGE_RXCFG_CONFIG_8126;
	if (sc->rge_flags & RGE_FLAG_DESCV2)
		rxconf &= ~RGE_RXCFG_ENBDESCV1;
	RGE_WRITE_4(sc, RGE_RXCFG, rxconf);
	RGE_WRITE_4(sc, RGE_TXCFG, RGE_TXCFG_CONFIG);

	val = pci_read_config(sc->sc_dev, 0x70c, 4) & ~0x3f000000;
	pci_write_config(sc->sc_dev, 0x70c, val | 0x27000000, 4);

	if (RGE_TYPE_R26(sc) || RGE_TYPE_R27(sc)) {
		/* Disable L1 timeout. */
		val = pci_read_config(sc->sc_dev, 0x890, 4) & ~0x00000001;
		pci_write_config(sc->sc_dev, 0x890, val, 4);
	} else if (!RGE_TYPE_R25D(sc))
		RGE_WRITE_2(sc, 0x0382, 0x221b);

	if (sc->sc_nqueues > 1)
		rge_init_rss(sc);
	else
		RGE_WRITE_4(sc, RGE_RSS_CTRL, 0);

	val = RGE_READ_2(sc, RGE_RXQUEUE_CTRL) & ~0x001c;
	RGE_WRITE_2(sc, RGE_RXQUEUE_CTRL, val | (fls(sc->sc_nqueues) - 1) << 2);

	RGE_CLRBIT_1(sc, RGE_CFG1, RGE_CFG1_SPEED_DOWN);

	rge_write_mac_ocp(sc, 0xc140, 0xffff);
	rge_write_mac_ocp(sc, 0xc142, 0xffff);

	if (sc->rge_flags & RGE_FLAG_DESCV2) {
		val = rge_read_mac_ocp(sc, 0xeb58) & ~0x0003;
		rge_write_mac_ocp(sc, 0xeb58, val | 0x0002);
	} else
		RGE_MAC_SETBIT(sc, 0xeb58, 0x0001);

	if (RGE_TYPE_R26(sc) || RGE_TYPE_R27(sc)) {
		if (sc->rge_flags & RGE_FLAG_DESCV2)
			RGE_SETBIT_1(sc, 0xd8, 0x02);
		else
			RGE_CLRBIT_1(sc, 0xd8, 0x02);
		if (RGE_TYPE_R27(sc)) {
			RGE_MAC_CLRBIT(sc, 0xe00c, 0x1000);
			RGE_MAC_CLRBIT(sc, 0xc0c2, 0x0040);
		}
	}

	val = rge_read_mac_ocp(sc, 0xe614);
	val &= RGE_TYPE_R27(sc) ? ~0x0f00 : ~0x0700;
	if (sc->rge_type == MAC_R25 || RGE_TYPE_R25D(sc))
		rge_write_mac_ocp(sc, 0xe614, val | 0x0300);
	else if (sc->rge_type == MAC_R25B)
		rge_write_mac_ocp(sc, 0xe614, val | 0x0200);
	else if (RGE_TYPE_R26(sc))
		rge_write_mac_ocp(sc, 0xe614, val | 0x0300);
	else
		rge_write_mac_ocp(sc, 0xe614, val | 0x0f00);

	val = rge_read_mac_ocp(sc, 0xe63e) & ~0x0c00;
	rge_write_mac_ocp(sc, 0xe63e, val |
	    ((fls(sc->sc_ntxqs) - 1) & 0x03) << 10);

	val = rge_read_mac_ocp(sc, 0xe63e) & ~0x0030;
	rge_write_mac_ocp(sc, 0xe63e, val | 0x0020);

	RGE_MAC_CLRBIT(sc, 0xc0b4, 0x0001);
	RGE_MAC_SETBIT(sc, 0xc0b4, 0x0001);

	RGE_MAC_SETBIT(sc, 0xc0b4, 0x000c);

	val = rge_read_mac_ocp(sc, 0xeb6a) & ~0x00ff;
	rge_write_mac_ocp(sc, 0xeb6a, val | 0x0033);

	val = rge_read_mac_ocp(sc, 0xeb50) & ~0x03e0;
	rge_write_mac_ocp(sc, 0xeb50, val | 0x0040);

	RGE_MAC_CLRBIT(sc, 0xe056, 0x00f0);

	RGE_WRITE_1(sc, RGE_TDFNR, 0x10);

	RGE_MAC_CLRBIT(sc, 0xe040, 0x1000);

	val = rge_read_mac_ocp(sc, 0xea1c) & ~0x0003;
	rge_write_mac_ocp(sc, 0xea1c, val | 0x0001);

	if (RGE_TYPE_R25D(sc))
		rge_write_mac_ocp(sc, 0xe0c0, 0x4403);
	else
		rge_write_mac_ocp(sc, 0xe0c0, 0x4000);

	RGE_MAC_SETBIT(sc, 0xe052, 0x0060);
	RGE_MAC_CLRBIT(sc, 0xe052, 0x0088);

	val = rge_read_mac_ocp(sc, 0xd430) & ~0x0fff;
	rge_write_mac_ocp(sc, 0xd430, val | 0x045f);

	RGE_SETBIT_1(sc, RGE_DLLPR, RGE_DLLPR_PFM_EN | RGE_DLLPR_TX_10M_PS_EN);
	RGE_SETBIT_1(sc, RGE_PPSW, 0x40);

	if (sc->rge_type == MAC_R25)
		RGE_SETBIT_1(sc, RGE_MCUCMD, 0x01);

	if (!RGE_TYPE_R25D(sc)) {
		/* Disable EEE plus. */
		RGE_MAC_CLRBIT(sc, 0xe080, 0x0002);
	}

	if (RGE_TYPE_R26(sc) || RGE_TYPE_R27(sc))
		RGE_MAC_CLRBIT(sc, 0xea1c, 0x0304);
	else
		RGE_MAC_CLRBIT(sc, 0xea1c, 0x0004);

	/* Clear tcam entries. */
	RGE_MAC_SETBIT(sc, 0xeb54, 0x0001);
	DELAY(1);
	RGE_MAC_CLRBIT(sc, 0xeb54, 0x0001);

	RGE_CLRBIT_2(sc, 0x1880, 0x0030);

	if (RGE_TYPE_R27(sc)) {
		val = rge_read_mac_ocp(sc, 0xd40c) & ~0xe038;
		rge_write_mac_ocp(sc, 0xd40c, val | 0x8020);
	}

	/* Config interrupt type. */
	if (RGE_TYPE_R27(sc)) {
		val = RGE_READ_1(sc, RGE_INT_CFG0);
		val &= ~(RGE_INT_CFG0_EN | RGE_INT_CFG0_AUTO_CLEAR_IMR |
		    RGE_INT_CFG0_AVOID_MISS_INTR);
		if (sc->rge_flags & RGE_FLAG_MULTIVEC)
			val |= RGE_INT_CFG0_EN;
		RGE_WRITE_1(sc, RGE_INT_CFG0, val);
	} else if (sc->rge_type != MAC_R25)
		RGE_CLRBIT_1(sc, RGE_INT_CFG0, RGE_INT_CFG0_EN);

	/* Clear timer interrupts. */
	RGE_WRITE_4(sc, RGE_TIMERINT0, 0);
	RGE_WRITE_4(sc, RGE_TIMERINT1, 0);
	RGE_WRITE_4(sc, RGE_TIMERINT2, 0);
	RGE_WRITE_4(sc, RGE_TIMERINT3, 0);

	num_miti =
	    (sc->rge_type == MAC_R25B || RGE_TYPE_R26(sc)) ? 32 : 64;
	/* Clear interrupt moderation timer. */
	for (i = 0; i < num_miti; i++)
		RGE_WRITE_4(sc, RGE_INTMITI(i), 0);

	if (RGE_TYPE_R26(sc)) {
		RGE_CLRBIT_1(sc, RGE_INT_CFG0,
		    RGE_INT_CFG0_TIMEOUT_BYPASS | RGE_INT_CFG0_RDU_BYPASS_8126 |
		    RGE_INT_CFG0_MITIGATION_BYPASS);
		RGE_WRITE_2(sc, RGE_INT_CFG1, 0);
	}

	if (sc->rge_flags & RGE_FLAG_MULTIVEC) {
		for (i = 0; i < sc->sc_nqueues; i++) {
			RGE_WRITE_1(sc, RGE_RX_MULTIVEC_INTMITI(i),
			    RGE_TIMER_VALUE);
			RGE_WRITE_1(sc, RGE_TX_MULTIVEC_INTMITI(i),
			    RGE_TIMER_VALUE);
		}
	}

	RGE_MAC_SETBIT(sc, 0xc0ac, 0x1f80);

	rge_write_mac_ocp(sc, 0xe098, 0xc302);

	RGE_MAC_CLRBIT(sc, 0xe032, 0x0003);
	val = rge_read_csi(sc, 0x98) & ~0x0000ff00;
	rge_write_csi(sc, 0x98, val);
	DELAY(20);

	if (RGE_TYPE_R25D(sc)) {
		val = rge_read_mac_ocp(sc, 0xe092) & ~0x00ff;
		rge_write_mac_ocp(sc, 0xe092, val | 0x0008);
	} else
		RGE_MAC_CLRBIT(sc, 0xe092, 0x00ff);

	/* Enable/disable HW VLAN tagging based on enabled capability */
	if ((if_getcapabilities(sc->sc_ifp) & IFCAP_VLAN_HWTAGGING) != 0)
		RGE_SETBIT_4(sc, RGE_RXCFG, RGE_RXCFG_VLANSTRIP);
	else
		RGE_CLRBIT_4(sc, RGE_RXCFG, RGE_RXCFG_VLANSTRIP);

	/* Enable/disable RX checksum based on enabled capability */
	if ((if_getcapenable(sc->sc_ifp) & IFCAP_RXCSUM) != 0)
		RGE_SETBIT_2(sc, RGE_CPLUSCMD, RGE_CPLUSCMD_RXCSUM);
	else
		RGE_CLRBIT_2(sc, RGE_CPLUSCMD, RGE_CPLUSCMD_RXCSUM);
	RGE_READ_2(sc, RGE_CPLUSCMD);

	/* Set Maximum frame size. */
	if (sc->rge_type == MAC_R25 || sc->rge_type == MAC_R25B)
		RGE_WRITE_2(sc, RGE_RXMAXSIZE, RGE_JUMBO_FRAMELEN);
	else
		RGE_WRITE_2(sc, RGE_RXMAXSIZE,
		    RGE_JUMBO_FRAMELEN | RGE_RXCFG_VLANPHYS);

	/* Disable RXDV gate. */
	RGE_CLRBIT_1(sc, RGE_PPSW, 0x08);

	/* Program promiscuous mode and multicast filters. */
	rge_iff_locked(sc);

	if (RGE_TYPE_R27(sc))
		RGE_CLRBIT_1(sc, RGE_RADMFIFO_PROTECT, 0x2001);

	rge_disable_aspm_clkreq(sc);

	RGE_CLRBIT_1(sc, RGE_EECMD, RGE_EECMD_WRITECFG);
	DELAY(10);

	rge_ifmedia_upd(sc->sc_ifp);

	/* Enable transmit and receive. */
	RGE_WRITE_1(sc, RGE_CMD, RGE_CMD_TXENB | RGE_CMD_RXENB);

	/* Enable interrupts (single vector mode). */
	if ((sc->rge_flags & RGE_FLAG_MULTIVEC) == 0)
		rge_setup_intr(sc, RGE_IMTYPE_SIM);

	if_setdrvflagbits(sc->sc_ifp, IFF_DRV_RUNNING, 0);
	if_setdrvflagbits(sc->sc_ifp, 0, IFF_DRV_OACTIVE);

	callout_reset(&sc->sc_timeout, hz, rge_tick, sc);

	RGE_DPRINTF(sc, RGE_DEBUG_INIT, "%s: init completed!\n", __func__);

	/* Unblock transmit when we release the lock */
	sc->sc_stopped = false;

	/*
	 * In multi-vector mode the RX queue interrupts don't take the
	 * driver lock, so only unmask them once we're marked running.
	 */
	if (sc->rge_flags & RGE_FLAG_MULTIVEC)
		rge_enable_queues(sc);
}

/*
 * @brief Stop the adapter and free any mbufs allocated to the RX and TX lists.
 *
 * Must be called with the driver lock held.
 */
void
rge_stop_locked(struct rge_softc *sc)
{
	int i;

	RGE_ASSERT_LOCKED(sc);

	RGE_DPRINTF(sc, RGE_DEBUG_INIT, "%s: called!\n", __func__);

	callout_stop(&sc->sc_timeout);

	/* Stop pending TX submissions */
	sc->sc_stopped = true;

	if_setdrvflagbits(sc->sc_ifp, 0, IFF_DRV_RUNNING);
	sc->rge_timerintr = 0;
	sc->sc_watchdog = 0;

	RGE_CLRBIT_4(sc, RGE_RXCFG, RGE_RXCFG_ALLPHYS | RGE_RXCFG_INDIV |
	    RGE_RXCFG_MULTI | RGE_RXCFG_BROAD | RGE_RXCFG_RUNT |
	    RGE_RXCFG_ERRPKT);

	rge_hw_reset(sc);

	RGE_MAC_CLRBIT(sc, 0xc0ac, 0x1f80);

	if_setdrvflagbits(sc->sc_ifp, 0, IFF_DRV_OACTIVE);

	for (i = 0; i < sc->sc_nqueues; i++)
		rge_free_rx_ring(sc, &sc->sc_queues[i]);
	rge_free_tx_ring(sc, &sc->sc_queues[0]);

	/* Free pending TX frames */
	/* TODO: should be per TX queue */
	rge_txq_flush_mbufs(sc);
}

/*
 * Set media options.
 */
static int
rge_ifmedia_upd(if_t ifp)
{
	struct rge_softc *sc = if_getsoftc(ifp);
	struct ifmedia *ifm = &sc->sc_media;
	int anar, gig, val;

	if (IFM_TYPE(ifm->ifm_media) != IFM_ETHER)
		return (EINVAL);

	/* Disable Gigabit Lite. */
	RGE_PHY_CLRBIT(sc, 0xa428, 0x0200);
	if (RGE_TYPE_R26(sc) || RGE_TYPE_R27(sc))
		RGE_PHY_CLRBIT(sc, 0xa5ea, 0x0007);
	else
		RGE_PHY_CLRBIT(sc, 0xa5ea, 0x0001);

	val = rge_read_phy_ocp(sc, 0xa5d4);
	switch (sc->rge_type) {
	case MAC_R27:
		val &= ~RGE_ADV_10000TFDX;
		/* fallthrough */
	case MAC_R26_1:
	case MAC_R26_2:
		val &= ~RGE_ADV_5000TFDX;
		/* fallthrough */
	default:
		val &= ~RGE_ADV_2500TFDX;
		break;
	}

	anar = ANAR_TX_FD | ANAR_TX | ANAR_10_FD | ANAR_10;
	gig = GTCR_ADV_1000TFDX | GTCR_ADV_1000THDX;

	switch (IFM_SUBTYPE(ifm->ifm_media)) {
	case IFM_AUTO:
		val |= RGE_ADV_2500TFDX;
		if (RGE_TYPE_R26(sc))
			val |= RGE_ADV_5000TFDX;
		else if (sc->rge_type == MAC_R27)
			val |= RGE_ADV_5000TFDX | RGE_ADV_10000TFDX;
		break;
	case IFM_10G_T:
		val |= RGE_ADV_10000TFDX;
		if_setbaudrate(ifp, IF_Gbps(10));
		break;
	case IFM_5000_T:
		val |= RGE_ADV_5000TFDX;
		if_setbaudrate(ifp, IF_Gbps(5));
		break;
	case IFM_2500_T:
		val |= RGE_ADV_2500TFDX;
		if_setbaudrate(ifp, IF_Mbps(2500));
		break;
	case IFM_1000_T:
		if_setbaudrate(ifp, IF_Gbps(1));
		break;
	case IFM_100_TX:
		gig = rge_read_phy(sc, 0, MII_100T2CR) &
		    ~(GTCR_ADV_1000TFDX | GTCR_ADV_1000THDX);
		anar = ((ifm->ifm_media & IFM_GMASK) == IFM_FDX) ?
		    ANAR_TX | ANAR_TX_FD | ANAR_10_FD | ANAR_10 :
		    ANAR_TX | ANAR_10_FD | ANAR_10;
		if_setbaudrate(ifp, IF_Mbps(100));
		break;
	case IFM_10_T:
		gig = rge_read_phy(sc, 0, MII_100T2CR) &
		    ~(GTCR_ADV_1000TFDX | GTCR_ADV_1000THDX);
		anar = ((ifm->ifm_media & IFM_GMASK) == IFM_FDX) ?
		    ANAR_10_FD | ANAR_10 : ANAR_10;
		if_setbaudrate(ifp, IF_Mbps(10));
		break;
	default:
		RGE_PRINT_ERROR(sc, "unsupported media type\n");
		return (EINVAL);
	}

	rge_write_phy(sc, 0, MII_ANAR, anar | ANAR_PAUSE_ASYM | ANAR_FC);
	rge_write_phy(sc, 0, MII_100T2CR, gig);
	rge_write_phy_ocp(sc, 0xa5d4, val);
	rge_write_phy(sc, 0, MII_BMCR, BMCR_RESET | BMCR_AUTOEN |
	    BMCR_STARTNEG);

	return (0);
}

/*
 * Report current media status.
 */
static void
rge_ifmedia_sts(if_t ifp, struct ifmediareq *ifmr)
{
	struct rge_softc *sc = if_getsoftc(ifp);
	uint16_t status = 0;

	ifmr->ifm_status = IFM_AVALID;
	ifmr->ifm_active = IFM_ETHER;

	if (rge_get_link_status(sc)) {
		ifmr->ifm_status |= IFM_ACTIVE;

		status = RGE_READ_2(sc, RGE_PHYSTAT);
		if ((status & RGE_PHYSTAT_FDX) ||
		    (status & (RGE_PHYSTAT_1000MBPS | RGE_PHYSTAT_2500MBPS |
		    RGE_PHYSTAT_5000MBPS | RGE_PHYSTAT_10000MBPS)))
			ifmr->ifm_active |= IFM_FDX;
		else
			ifmr->ifm_active |= IFM_HDX;

		if (status & RGE_PHYSTAT_10MBPS)
			ifmr->ifm_active |= IFM_10_T;
		else if (status & RGE_PHYSTAT_100MBPS)
			ifmr->ifm_active |= IFM_100_TX;
		else if (status & RGE_PHYSTAT_1000MBPS)
			ifmr->ifm_active |= IFM_1000_T;
		else if (status & RGE_PHYSTAT_2500MBPS)
			ifmr->ifm_active |= IFM_2500_T;
		else if (status & RGE_PHYSTAT_5000MBPS)
			ifmr->ifm_active |= IFM_5000_T;
		else if (status & RGE_PHYSTAT_10000MBPS)
			ifmr->ifm_active |= IFM_10G_T;
	}
}

/**
 * @brief callback to load/populate a single physical address
 */
static void
rge_dma_load_cb(void *arg, bus_dma_segment_t *segs, int nsegs, int error)
{
	bus_addr_t *paddr = (bus_addr_t *) arg;

	*paddr = 0;

	if (error) {
		printf("%s: error! (%d)\n", __func__, error);
		*paddr = 0;
		return;
	}

	if (nsegs != 1) {
		printf("%s: too many segs (got %d)\n", __func__, nsegs);
		*paddr = 0;
		return;
	}

	*paddr = segs[0].ds_addr;
}

/**
 * @brief Allocate memory for a TX ring.
 *
 * Called with the driver lock NOT held.
 */
static int
rge_alloc_tx_mem(struct rge_softc *sc, struct rge_queues *q)
{
	int error;
	int i;

	RGE_ASSERT_UNLOCKED(sc);

	/* Allocate DMA'able memory for the TX ring. */
	error = bus_dmamem_alloc(sc->sc_dmat_tx_desc,
	    (void **) &q->q_tx.rge_tx_list,
	    BUS_DMA_WAITOK | BUS_DMA_ZERO | BUS_DMA_COHERENT,
	    &q->q_tx.rge_tx_list_map);
	if (error) {
		RGE_PRINT_ERROR(sc, "%s: error (alloc tx_list.map) (%d)\n",
		    __func__, error);
		return (error);
	}
	/* The v2 descriptor ring shares the same memory. */
	q->q_tx.rge_tx_list_v2 = (struct rge_tx_desc_v2 *)q->q_tx.rge_tx_list;

	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: tx_list=%p\n", __func__,
	    q->q_tx.rge_tx_list);
	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: tx_list_map=%p\n", __func__,
	    q->q_tx.rge_tx_list_map);

	/* Load the map for the TX ring. */
	error = bus_dmamap_load(sc->sc_dmat_tx_desc,
	    q->q_tx.rge_tx_list_map,
	    q->q_tx.rge_tx_list,
	    RGE_TX_LIST_SZ,
	    rge_dma_load_cb,
	    (void *) &q->q_tx.rge_tx_list_paddr,
	    BUS_DMA_NOWAIT);

	if ((error != 0) || (q->q_tx.rge_tx_list_paddr == 0)) {
		RGE_PRINT_ERROR(sc, "%s: error (load tx_list.map) (%d)\n",
		    __func__, error);
		if (error == 0)
			error = ENXIO;
		return (error);
	}

	/* Create DMA maps for TX buffers. */
	for (i = 0; i < RGE_TX_LIST_CNT; i++) {
		error = bus_dmamap_create(sc->sc_dmat_tx_buf,
		    0, &q->q_tx.rge_txq[i].txq_dmamap);
		if (error) {
			RGE_PRINT_ERROR(sc,
			    "can't create DMA map for TX (%d)\n", error);
			return (error);
		}
	}

	return (0);
}

/**
 * @brief Allocate memory for an RX ring.
 *
 * Called with the driver lock NOT held.
 */
static int
rge_alloc_rx_mem(struct rge_softc *sc, struct rge_queues *q)
{
	int error;
	int i;

	RGE_ASSERT_UNLOCKED(sc);

	/* Allocate DMA'able memory for the RX ring. */
	error = bus_dmamem_alloc(sc->sc_dmat_rx_desc,
	    (void **) &q->q_rx.rge_rx_list,
	    BUS_DMA_WAITOK | BUS_DMA_ZERO | BUS_DMA_COHERENT,
	    &q->q_rx.rge_rx_list_map);
	if (error) {
		RGE_PRINT_ERROR(sc, "%s: error (alloc rx_list.map) (%d)\n",
		    __func__, error);
		return (error);
	}
	/* The v2 descriptor ring shares the same memory. */
	q->q_rx.rge_rx_list_v2 = (struct rge_rx_desc_v2 *)q->q_rx.rge_rx_list;

	RGE_DPRINTF(sc, RGE_DEBUG_INIT, "%s: rx_list=%p\n", __func__,
	    q->q_rx.rge_rx_list);
	RGE_DPRINTF(sc, RGE_DEBUG_INIT, "%s: rx_list_map=%p\n", __func__,
	    q->q_rx.rge_rx_list_map);

	/* Load the map for the RX ring. */
	error = bus_dmamap_load(sc->sc_dmat_rx_desc,
	    q->q_rx.rge_rx_list_map,
	    q->q_rx.rge_rx_list,
	    RGE_RX_LIST_SZ,
	    rge_dma_load_cb,
	    (void *) &q->q_rx.rge_rx_list_paddr,
	    BUS_DMA_NOWAIT);

	if ((error != 0) || (q->q_rx.rge_rx_list_paddr == 0)) {
		RGE_PRINT_ERROR(sc, "%s: error (load rx_list.map) (%d)\n",
		    __func__, error);
		if (error == 0)
			error = ENXIO;
		return (error);
	}

	/* Create DMA maps for RX buffers. */
	for (i = 0; i < RGE_RX_LIST_CNT; i++) {
		error = bus_dmamap_create(sc->sc_dmat_rx_buf,
		    0, &q->q_rx.rge_rxq[i].rxq_dmamap);
		if (error) {
			RGE_PRINT_ERROR(sc,
			    "can't create DMA map for RX (%d)\n", error);
			return (error);
		}
	}

	return (0);
}

/**
 * @brief Allocate memory for RX/TX rings.
 *
 * Each RX queue gets its own RX ring; only a single TX ring is used.
 *
 * Called with the driver lock NOT held.
 */
static int
rge_allocmem(struct rge_softc *sc)
{
	int error;
	int i;

	RGE_ASSERT_UNLOCKED(sc);

	error = rge_alloc_tx_mem(sc, &sc->sc_queues[0]);
	if (error != 0)
		goto error;

	for (i = 0; i < sc->sc_nqueues; i++) {
		error = rge_alloc_rx_mem(sc, &sc->sc_queues[i]);
		if (error != 0)
			goto error;
	}

	return (0);
error:

	rge_freemem(sc);

	return (error);
}

/**
 * @brief Allocate memory for MAC stats.
 *
 * Called with the driver lock NOT held.
 */
static int
rge_alloc_stats_mem(struct rge_softc *sc)
{
	struct rge_mac_stats *ss = &sc->sc_mac_stats;
	int error;

	RGE_ASSERT_UNLOCKED(sc);

	/* Allocate DMA'able memory for the stats buffer. */
	error = bus_dmamem_alloc(sc->sc_dmat_stats_buf,
	    (void **) &ss->stats, BUS_DMA_WAITOK | BUS_DMA_ZERO,
	    &ss->map);
	if (error) {
		RGE_PRINT_ERROR(sc, "%s: error (alloc stats) (%d)\n",
		    __func__, error);
		goto error;
	}

	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: stats=%p\n", __func__, ss->stats);
	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: map=%p\n", __func__, ss->map);

	/* Load the map for the TX ring. */
	error = bus_dmamap_load(sc->sc_dmat_stats_buf,
	    ss->map,
	    ss->stats,
	    RGE_STATS_BUF_SIZE,
	    rge_dma_load_cb,
	    (void *) &ss->paddr,
	    BUS_DMA_NOWAIT);

	if ((error != 0) || (ss->paddr == 0)) {
		RGE_PRINT_ERROR(sc, "%s: error (load stats.map) (%d)\n",
		    __func__, error);
		if (error == 0)
			error = ENXIO;
		goto error;
	}

	return (0);

error:
	rge_free_stats_mem(sc);

	return (error);
}


/**
 * @brief Free a TX ring's DMA buffers and mbufs.
 *
 * Called with the driver lock NOT held.
 */
static void
rge_free_tx_mem(struct rge_softc *sc, struct rge_queues *q)
{
	int i;

	/* TX buf */
	for (i = 0; i < RGE_TX_LIST_CNT; i++) {
		struct rge_txq *tx = &q->q_tx.rge_txq[i];

		/* unmap/free mbuf if it's still alloc'ed and mapped */
		if (tx->txq_mbuf != NULL) {
			static bool do_warning = false;

			if (do_warning == false) {
				RGE_PRINT_ERROR(sc,
				    "%s: TX mbuf should've been freed!\n",
				    __func__);
				do_warning = true;
			}
			if (tx->txq_dmamap != NULL) {
				bus_dmamap_sync(sc->sc_dmat_tx_buf,
				    tx->txq_dmamap, BUS_DMASYNC_POSTREAD);
				bus_dmamap_unload(sc->sc_dmat_tx_buf,
				    tx->txq_dmamap);
			}
			m_free(tx->txq_mbuf);
			tx->txq_mbuf = NULL;
		}

		/* Destroy the dmamap if it's allocated */
		if (tx->txq_dmamap != NULL) {
			bus_dmamap_destroy(sc->sc_dmat_tx_buf, tx->txq_dmamap);
			tx->txq_dmamap = NULL;
		}
	}

	/* TX desc */
	if (q->q_tx.rge_tx_list != NULL) {
		bus_dmamap_unload(sc->sc_dmat_tx_desc, q->q_tx.rge_tx_list_map);
		bus_dmamem_free(sc->sc_dmat_tx_desc, q->q_tx.rge_tx_list,
		    q->q_tx.rge_tx_list_map);
	}
	memset(&q->q_tx, 0, sizeof(q->q_tx));
}

/**
 * @brief Free an RX ring's DMA buffers and mbufs.
 *
 * Called with the driver lock NOT held.
 */
static void
rge_free_rx_mem(struct rge_softc *sc, struct rge_queues *q)
{
	int i;

	/* RX buf */
	for (i = 0; i < RGE_RX_LIST_CNT; i++) {
		struct rge_rxq *rx = &q->q_rx.rge_rxq[i];

		/* unmap/free mbuf if it's still alloc'ed and mapped */
		if (rx->rxq_mbuf != NULL) {
			if (rx->rxq_dmamap != NULL) {
				bus_dmamap_sync(sc->sc_dmat_rx_buf,
				    rx->rxq_dmamap, BUS_DMASYNC_POSTREAD);
				bus_dmamap_unload(sc->sc_dmat_rx_buf,
				    rx->rxq_dmamap);
			}
			m_free(rx->rxq_mbuf);
			rx->rxq_mbuf = NULL;
		}

		/* Destroy the dmamap if it's allocated */
		if (rx->rxq_dmamap != NULL) {
			bus_dmamap_destroy(sc->sc_dmat_rx_buf, rx->rxq_dmamap);
			rx->rxq_dmamap = NULL;
		}
	}

	/* RX desc */
	if (q->q_rx.rge_rx_list != NULL) {
		bus_dmamap_unload(sc->sc_dmat_rx_desc, q->q_rx.rge_rx_list_map);
		bus_dmamem_free(sc->sc_dmat_rx_desc, q->q_rx.rge_rx_list,
		    q->q_rx.rge_rx_list_map);
	}
	memset(&q->q_rx, 0, sizeof(q->q_rx));
}

/**
 * @brief Free the TX/RX DMA buffers and mbufs.
 *
 * Called with the driver lock NOT held.
 */
static int
rge_freemem(struct rge_softc *sc)
{
	int i;

	RGE_ASSERT_UNLOCKED(sc);

	if (sc->sc_queues == NULL)
		return (0);

	rge_free_tx_mem(sc, &sc->sc_queues[0]);
	for (i = 0; i < sc->sc_nqueues; i++)
		rge_free_rx_mem(sc, &sc->sc_queues[i]);

	return (0);
}

/**
 * @brief Free the stats memory.
 *
 * Called with the driver lock NOT held.
 */
static int
rge_free_stats_mem(struct rge_softc *sc)
{
	struct rge_mac_stats *ss = &sc->sc_mac_stats;

	RGE_ASSERT_UNLOCKED(sc);

	if (ss->stats != NULL) {
		bus_dmamap_unload(sc->sc_dmat_stats_buf, ss->map);
		bus_dmamem_free(sc->sc_dmat_stats_buf, ss->stats, ss->map);
	}
	memset(ss, 0, sizeof(*ss));
	return (0);
}

static uint32_t
rx_ring_space(struct rge_queues *q)
{
	uint32_t prod, cons;
	uint32_t ret;

	RGE_RXQ_ASSERT_LOCKED(q);

	prod = q->q_rx.rge_rxq_prodidx;
	cons = q->q_rx.rge_rxq_considx;

	ret = (cons + RGE_RX_LIST_CNT - prod - 1) % RGE_RX_LIST_CNT + 1;

	if (ret > RGE_RX_LIST_CNT)
		return RGE_RX_LIST_CNT;

	return (ret);
}

/*
 * Initialize the RX descriptor and attach an mbuf cluster at the given offset.
 *
 * Note: this relies on the rxr ring buffer abstraction to not
 * over-fill the RX ring.  For FreeBSD we'll need to use the
 * prod/cons RX indexes to know how much RX ring space to
 * populate.
 *
 * This routine will increment the producer index if successful.
 *
 * This must be called with the RX queue lock held.
 */
static int
rge_newbuf(struct rge_queues *q)
{
	struct rge_softc *sc = q->q_sc;
	struct mbuf *m;
	struct rge_rx_desc *r = NULL;
	struct rge_rx_desc_v2 *rv2 = NULL;
	struct rge_rxq *rxq;
	bus_dmamap_t rxmap;
	bus_dma_segment_t seg[1];
	uint32_t cmdsts;
	const uint32_t *dw;
	int nsegs;
	uint32_t idx;

	RGE_RXQ_ASSERT_LOCKED(q);

	/*
	 * Verify we have enough space in the ring; error out
	 * if we do not.
	 */
	if (rx_ring_space(q) == 0)
		return (ENOBUFS);

	idx = q->q_rx.rge_rxq_prodidx;
	rxq = &q->q_rx.rge_rxq[idx];
	rxmap = rxq->rxq_dmamap;

	/*
	 * If we already have an mbuf here then something messed up;
	 * exit out as the hardware may be DMAing to it.
	 */
	if (rxq->rxq_mbuf != NULL) {
		RGE_PRINT_ERROR(sc,
		    "%s: RX ring slot %d already has an mbuf?\n", __func__,
		    idx);
		return (ENOBUFS);
	}

	/* Allocate single buffer backed mbuf of MCLBYTES */
	m = m_getcl(M_NOWAIT, MT_DATA, M_PKTHDR);
	if (m == NULL)
		return (ENOBUFS);

	m->m_len = m->m_pkthdr.len = MCLBYTES;

	nsegs = 1;
	if (bus_dmamap_load_mbuf_sg(sc->sc_dmat_rx_buf, rxmap, m, seg, &nsegs,
	    BUS_DMA_NOWAIT)) {
		m_freem(m);
		return (ENOBUFS);
	}

	/*
	 * Make sure any changes made to the buffer have been flushed to host
	 * memory.
	 */
	bus_dmamap_sync(sc->sc_dmat_rx_buf, rxmap,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);

	/*
	 * Map the segment into RX descriptors.  Note that this
	 * only currently supports a single segment per mbuf;
	 * the call to load_mbuf_sg above specified a single segment.
	 */
	if (sc->rge_flags & RGE_FLAG_DESCV2)
		rv2 = &q->q_rx.rge_rx_list_v2[idx];
	else
		r = &q->q_rx.rge_rx_list[idx];

	rxq->rxq_mbuf = m;

	cmdsts = seg[0].ds_len; /* XXX how big is this field in the descriptor? */
	if (idx == RGE_RX_LIST_CNT - 1)
		cmdsts |= RGE_RDCMDSTS_EOR;

	/*
	 * Configure the DMA pointer and config, but don't hand
	 * it yet to the hardware.
	 */
	if (rv2 != NULL) {
		rv2->rx_qword0.rge_cmdsts = htole32(cmdsts);
		rv2->rx_qword0.rge_extsts = htole32(0);
		rv2->qword0.rge_addr = htole64(seg[0].ds_addr);
	} else {
		r->hi_qword1.rx_qword4.rge_cmdsts = htole32(cmdsts);
		r->hi_qword1.rx_qword4.rge_extsts = htole32(0);
		r->hi_qword0.rge_addr = htole64(seg[0].ds_addr);
	}
	wmb();

	/*
	 * Mark the specific descriptor slot as "this descriptor is now
	 * owned by the hardware", which when the hardware next sees
	 * this, it'll continue RX DMA.
	 */
	cmdsts |= RGE_RDCMDSTS_OWN;
	if (rv2 != NULL)
		rv2->rx_qword0.rge_cmdsts = htole32(cmdsts);
	else
		r->hi_qword1.rx_qword4.rge_cmdsts = htole32(cmdsts);
	wmb();

	/*
	 * At this point the hope is the whole ring is now updated and
	 * consistent; if the hardware was waiting for a descriptor to be
	 * ready to write into then it should be ready here.
	 */

	/* Address, extsts and cmdsts words (the upper half of a v1 desc) */
	dw = (rv2 != NULL) ? (const uint32_t *)rv2 :
	    &((const uint32_t *)r)[4];
	RGE_DPRINTF(sc, RGE_DEBUG_RECV_DESC,
	    "%s: [%d]: m=%p, m_data=%p, m_len=%ju, phys=0x%jx len %ju, "
	    "desc=0x%08x 0x%08x 0x%08x 0x%08x\n",
	    __func__,
	    idx,
	    m,
	    m->m_data,
	    (uintmax_t) m->m_len,
	    (uintmax_t) seg[0].ds_addr,
	    (uintmax_t) seg[0].ds_len,
	    dw[0], dw[1], dw[2], dw[3]);

	q->q_rx.rge_rxq_prodidx = RGE_NEXT_RX_DESC(idx);

	return (0);
}

static void
rge_rx_list_init(struct rge_queues *q)
{
	RGE_RXQ_ASSERT_LOCKED(q);

	/* This covers both the v1 and (smaller) v2 descriptor rings */
	memset(q->q_rx.rge_rx_list, 0, RGE_RX_LIST_SZ);

	q->q_rx.rge_rxq_prodidx = q->q_rx.rge_rxq_considx = 0;
	q->q_rx.rge_head = NULL;
	q->q_rx.rge_tail = &q->q_rx.rge_head;

	RGE_DPRINTF(q->q_sc, RGE_DEBUG_SETUP, "%s: rx_list=%p\n", __func__,
	    q->q_rx.rge_rx_list);

	rge_fill_rx_ring(q);
}

/**
 * @brief Fill / refill the RX ring as needed.
 *
 * Refill the RX ring with one less than the total descriptors needed.
 * This makes the check in rge_rxeof() easier - it can just check
 * descriptors from cons -> prod and bail once it hits prod.
 * If the whole ring is filled then cons == prod, and that shortcut
 * fails.
 *
 * This must be called with the RX queue lock held.
 */
static void
rge_fill_rx_ring(struct rge_queues *q)
{
	struct rge_softc *sc = q->q_sc;
	uint32_t count, i, prod, cons;

	RGE_RXQ_ASSERT_LOCKED(q);

	prod = q->q_rx.rge_rxq_prodidx;
	cons = q->q_rx.rge_rxq_considx;
	count = rx_ring_space(q);

	/* Fill to count-1; bail if we don't have the space */
	if (count <= 1)
		return;
	count--;

	RGE_DPRINTF(sc, RGE_DEBUG_RECV_DESC, "%s: prod=%u, cons=%u, space=%u\n",
	  __func__, prod, cons, count);

	/* Make sure device->host changes are visible */
	bus_dmamap_sync(sc->sc_dmat_rx_desc, q->q_rx.rge_rx_list_map,
	    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	for (i = 0; i < count; i++) {
		if (rge_newbuf(q))
			break;
	}

	/* Make changes visible to the device */
	bus_dmamap_sync(sc->sc_dmat_rx_desc, q->q_rx.rge_rx_list_map,
	    BUS_DMASYNC_PREWRITE);
}

static void
rge_tx_list_init(struct rge_queues *q)
{
	struct rge_softc *sc = q->q_sc;
	int i;

	RGE_ASSERT_LOCKED(q->q_sc);

	/* This covers both the v1 and (smaller) v2 descriptor rings */
	memset(q->q_tx.rge_tx_list, 0, RGE_TX_LIST_SZ);

	for (i = 0; i < RGE_TX_LIST_CNT; i++)
		q->q_tx.rge_txq[i].txq_mbuf = NULL;

	if (sc->rge_flags & RGE_FLAG_DESCV2)
		q->q_tx.rge_tx_list_v2[RGE_TX_LIST_CNT - 1].rge_cmdsts =
		    htole32(RGE_TDCMDSTS_EOR);
	else
		q->q_tx.rge_tx_list[RGE_TX_LIST_CNT - 1].rge_cmdsts =
		    htole32(RGE_TDCMDSTS_EOR);

	bus_dmamap_sync(sc->sc_dmat_tx_desc, q->q_tx.rge_tx_list_map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	wmb();

	q->q_tx.rge_txq_prodidx = q->q_tx.rge_txq_considx = 0;

	RGE_DPRINTF(sc, RGE_DEBUG_SETUP, "%s: rx_list=%p\n", __func__,
	    q->q_tx.rge_tx_list);
}

static void
rge_fill_rx_desc_addr(struct rge_queues *q, int queue)
{
	struct rge_softc *sc = q->q_sc;

	if (queue == 0) {
		RGE_WRITE_4(sc, RGE_RXDESC_ADDR_LO,
		    RGE_ADDR_LO(q->q_rx.rge_rx_list_paddr));
		RGE_WRITE_4(sc, RGE_RXDESC_ADDR_HI,
		    RGE_ADDR_HI(q->q_rx.rge_rx_list_paddr));
	} else {
		RGE_WRITE_4(sc, RGE_RXDESC_ADDR_LO_V2(queue),
		    RGE_ADDR_LO(q->q_rx.rge_rx_list_paddr));
		RGE_WRITE_4(sc, RGE_RXDESC_ADDR_HI_V2(queue),
		    RGE_ADDR_HI(q->q_rx.rge_rx_list_paddr));
	}
}

static void
rge_fill_tx_desc_addr(struct rge_queues *q, int queue)
{
	struct rge_softc *sc = q->q_sc;

	if (queue == 0) {
		RGE_WRITE_4(sc, RGE_TXDESC_ADDR_LO,
		    RGE_ADDR_LO(q->q_tx.rge_tx_list_paddr));
		RGE_WRITE_4(sc, RGE_TXDESC_ADDR_HI,
		    RGE_ADDR_HI(q->q_tx.rge_tx_list_paddr));
	} else {
		RGE_WRITE_4(sc, RGE_TXDESC_ADDR_LO_V2(queue),
		    RGE_ADDR_LO(q->q_tx.rge_tx_list_paddr));
		RGE_WRITE_4(sc, RGE_TXDESC_ADDR_HI_V2(queue),
		    RGE_ADDR_HI(q->q_tx.rge_tx_list_paddr));
	}
}

/**
 * @brief Free the mbufs attached to an RX ring.
 *
 * Must be called with the driver lock held; takes the RX queue lock.
 */
static void
rge_free_rx_ring(struct rge_softc *sc, struct rge_queues *q)
{
	int i;

	RGE_ASSERT_LOCKED(sc);

	RGE_RXQ_LOCK(q);
	if (q->q_rx.rge_head != NULL) {
		m_freem(q->q_rx.rge_head);
		q->q_rx.rge_head = NULL;
		q->q_rx.rge_tail = &q->q_rx.rge_head;
	}

	/* Free the RX list buffers. */
	for (i = 0; i < RGE_RX_LIST_CNT; i++) {
		if (q->q_rx.rge_rxq[i].rxq_mbuf != NULL) {
			bus_dmamap_unload(sc->sc_dmat_rx_buf,
			    q->q_rx.rge_rxq[i].rxq_dmamap);
			m_freem(q->q_rx.rge_rxq[i].rxq_mbuf);
			q->q_rx.rge_rxq[i].rxq_mbuf = NULL;
		}
	}
	RGE_RXQ_UNLOCK(q);
}

/**
 * @brief Free the mbufs attached to a TX ring.
 *
 * Must be called with the driver lock held.
 */
static void
rge_free_tx_ring(struct rge_softc *sc, struct rge_queues *q)
{
	int i;

	RGE_ASSERT_LOCKED(sc);

	/* Free the TX list buffers. */
	for (i = 0; i < RGE_TX_LIST_CNT; i++) {
		if (q->q_tx.rge_txq[i].txq_mbuf != NULL) {
			bus_dmamap_unload(sc->sc_dmat_tx_buf,
			    q->q_tx.rge_txq[i].txq_dmamap);
			m_freem(q->q_tx.rge_txq[i].txq_mbuf);
			q->q_tx.rge_txq[i].txq_mbuf = NULL;
		}
	}
}

static inline uint32_t
rge_rxstatus_mask(struct rge_softc *sc, int status)
{
	switch (status) {
	case CMDSTS_EOF:
		return (sc->rge_flags & RGE_FLAG_DESCV2) ?
		    RGE_RDCMDSTS_EOF_V2 : RGE_RDCMDSTS_EOF;
	case CMDSTS_SOF:
		return (sc->rge_flags & RGE_FLAG_DESCV2) ?
		    RGE_RDCMDSTS_SOF_V2 : RGE_RDCMDSTS_SOF;
	default:
		return (sc->rge_flags & RGE_FLAG_DESCV2) ?
		    RGE_RDCMDSTS_RXERRSUM_V2 : RGE_RDCMDSTS_RXERRSUM;
	}
}

/**
 * @brief Translate the RX descriptor checksum status into mbuf flags.
 *
 * The v2 descriptors carry the checksum error and protocol bits in
 * cmdsts rather than extsts; the IPv4/IPv6 bits stay in extsts.
 */
static void
rge_rxcsum(struct rge_softc *sc, uint32_t cmdsts, uint32_t extsts,
    struct mbuf *m)
{
	bool ipcsumerr, tcppkt, tcpcsumerr, udppkt, udpcsumerr;

	if (sc->rge_flags & RGE_FLAG_DESCV2) {
		ipcsumerr = (cmdsts & RGE_RDCMDSTS_IPCSUMERR_V2) != 0;
		tcppkt = (cmdsts & RGE_RDCMDSTS_TCPPKT_V2) != 0;
		tcpcsumerr = (cmdsts & RGE_RDCMDSTS_TCPCSUMERR_V2) != 0;
		udppkt = (cmdsts & RGE_RDCMDSTS_UDPPKT_V2) != 0;
		udpcsumerr = (cmdsts & RGE_RDCMDSTS_UDPCSUMERR_V2) != 0;
	} else {
		ipcsumerr = (extsts & RGE_RDEXTSTS_IPCSUMERR) != 0;
		tcppkt = (extsts & RGE_RDEXTSTS_TCPPKT) != 0;
		tcpcsumerr = (extsts & RGE_RDEXTSTS_TCPCSUMERR) != 0;
		udppkt = (extsts & RGE_RDEXTSTS_UDPPKT) != 0;
		udpcsumerr = (extsts & RGE_RDEXTSTS_UDPCSUMERR) != 0;
	}

	/* Check IP header checksum. */
	if (extsts & RGE_RDEXTSTS_IPV4) {
		sc->sc_drv_stats.rx_offload_csum_ipv4_exists++;
		m->m_pkthdr.csum_flags |= CSUM_IP_CHECKED;
		if (!ipcsumerr) {
			sc->sc_drv_stats.rx_offload_csum_ipv4_valid++;
			m->m_pkthdr.csum_flags |= CSUM_IP_VALID;
		}
	}

	/* Check TCP/UDP checksum. */
	if ((extsts & (RGE_RDEXTSTS_IPV4 | RGE_RDEXTSTS_IPV6)) == 0)
		return;

	if (tcppkt) {
		sc->sc_drv_stats.rx_offload_csum_tcp_exists++;
		if (!tcpcsumerr) {
			sc->sc_drv_stats.rx_offload_csum_tcp_valid++;
			/* TCP checksum OK */
			m->m_pkthdr.csum_flags |=
			    CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
			m->m_pkthdr.csum_data = 0xffff;
		}
	}

	if (udppkt) {
		sc->sc_drv_stats.rx_offload_csum_udp_exists++;
		if (!udpcsumerr) {
			sc->sc_drv_stats.rx_offload_csum_udp_valid++;
			/* UDP checksum OK */
			m->m_pkthdr.csum_flags |=
			    CSUM_DATA_VALID | CSUM_PSEUDO_HDR;
			m->m_pkthdr.csum_data = 0xffff;
		}
	}
}

/**
 * @brief Find the offset of the TCP/UDP header in an outbound frame.
 *
 * The stack doesn't hand us parsed header lengths, so look at the
 * ethernet and IP headers; m_copydata() is used so the mbuf chain
 * doesn't need to be modified.
 */
static int
rge_tx_l4_offset(struct mbuf *m, bool ipv6, uint32_t *offp)
{
	struct ether_vlan_header evh;
	uint8_t vhl;
	int ehlen;

	if (m->m_pkthdr.len < ETHER_HDR_LEN)
		return (EINVAL);
	m_copydata(m, 0, ETHER_HDR_LEN, (caddr_t)&evh);
	if (evh.evl_encap_proto == htons(ETHERTYPE_VLAN))
		ehlen = ETHER_HDR_LEN + ETHER_VLAN_ENCAP_LEN;
	else
		ehlen = ETHER_HDR_LEN;

	if (ipv6) {
		*offp = ehlen + sizeof(struct ip6_hdr);
		return (0);
	}

	if (m->m_pkthdr.len < ehlen + (int)sizeof(struct ip))
		return (EINVAL);
	m_copydata(m, ehlen, sizeof(vhl), (caddr_t)&vhl);
	*offp = ehlen + ((vhl & 0x0f) << 2);
	return (0);
}

/**
 * @brief Set up the TX descriptor offload (VLAN, checksum, TSO) bits.
 *
 * cflags is written into the descriptor extsts word and tflags is
 * OR'ed into the cmdsts word of every descriptor of the frame.
 *
 * Returns non-zero if the frame can't be offloaded and should be
 * dropped.
 */
static int
rge_tx_offload(struct rge_softc *sc, struct mbuf *m, uint32_t *cflags,
    uint32_t *tflags)
{
	uint32_t csum = m->m_pkthdr.csum_flags;
	uint32_t hdrlen, mss;

	/* Set up hardware VLAN tagging */
	if (m->m_flags & M_VLANTAG) {
		sc->sc_drv_stats.tx_offload_vlan_tag_set++;
		*cflags |= htons(m->m_pkthdr.ether_vtag) | RGE_TDEXTSTS_VTAG;
	}

	if (csum & CSUM_TSO) {
		if (rge_tx_l4_offset(m, (csum & CSUM_IP6_TSO) != 0,
		    &hdrlen) != 0 || hdrlen > RGE_TDCMDSTS_TCPHO_MAX ||
		    m->m_pkthdr.tso_segsz == 0) {
			sc->sc_drv_stats.tx_offload_tso_err++;
			return (EINVAL);
		}
		*tflags = hdrlen << RGE_TDCMDSTS_TCPHO_SHIFT;
		mss = MIN(m->m_pkthdr.tso_segsz, RGE_TDEXTSTS_MAX_MSS);
		*cflags |= mss << RGE_TDEXTSTS_MSS_SHIFT;
		*cflags |= RGE_TDEXTSTS_TSOENB_V2 | RGE_TDEXTSTS_TSOTCP_V2;
		*cflags |= (csum & CSUM_IP_TSO) ?
		    RGE_TDEXTSTS_TSOIPV4_V2 : RGE_TDEXTSTS_TSOIPV6_V2;
		sc->sc_drv_stats.tx_offload_tso_set++;
		return (0);
	}

	if ((csum & RGE_CSUM_FEATURES) != 0) {
		/*
		 * RGE_TDEXTSTS_IPCSUM needs to be set for IPv4 frames,
		 * otherwise RGE_TDEXTSTS_TCPCSUM / RGE_TDEXTSTS_UDPCSUM
		 * don't take effect.
		 */
		*cflags |= RGE_TDEXTSTS_IPCSUM;
		sc->sc_drv_stats.tx_offload_ip_csum_set++;
	} else if ((csum & RGE_CSUM_FEATURES_IPV6) != 0) {
		/* IPv6 needs the offset of the TCP/UDP header. */
		if (rge_tx_l4_offset(m, true, &hdrlen) != 0)
			return (EINVAL);
		*tflags = hdrlen << RGE_TDCMDSTS_TCPHO_SHIFT;
	}

	if (csum & (CSUM_TCP | CSUM_TCP_IPV6)) {
		sc->sc_drv_stats.tx_offload_tcp_csum_set++;
		*cflags |= RGE_TDEXTSTS_TCPCSUM;
	}
	if (csum & (CSUM_UDP | CSUM_UDP_IPV6)) {
		sc->sc_drv_stats.tx_offload_udp_csum_set++;
		*cflags |= RGE_TDEXTSTS_UDPCSUM;
	}

	return (0);
}

int
rge_rxeof(struct rge_queues *q, struct mbufq *mq, bool *more)
{
	struct rge_softc *sc = q->q_sc;
	struct mbuf *m;
	struct rge_rx_desc *cur_rx = NULL;
	struct rge_rx_desc_v2 *cur_rx_v2 = NULL;
	const uint32_t *dw;
	struct rge_rxq *rxq;
	uint32_t rxstat, extsts;
	uint32_t hash = 0, hashtype = 0;
	int i, mlen, rx = 0;
	int cons, prod;
	int maxpkt;
	bool check_hwcsum;

	maxpkt = sc->sc_rx_process_limit;
	check_hwcsum = ((if_getcapenable(sc->sc_ifp) & IFCAP_RXCSUM) != 0);

	RGE_RXQ_ASSERT_LOCKED(q);

	sc->sc_drv_stats.rxeof_cnt++;

	RGE_DPRINTF(sc, RGE_DEBUG_INTR, "%s; called\n", __func__);

	/* Note: if_re is POSTREAD/WRITE, rge is only POSTWRITE */
	bus_dmamap_sync(sc->sc_dmat_rx_desc, q->q_rx.rge_rx_list_map,
	    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);

	prod = q->q_rx.rge_rxq_prodidx;

	/*
	 * Loop around until we've run out of active descriptors to check
	 * or maxpkt has been reached.
	 */
	for (i = cons = q->q_rx.rge_rxq_considx;
	    maxpkt > 0 && i != prod;
	    i = RGE_NEXT_RX_DESC(i)) {
		/* break out of loop if we're not running */
		if ((if_getdrvflags(sc->sc_ifp) & IFF_DRV_RUNNING) == 0)
			break;

		/* get the current rx descriptor to check descriptor status */
		if (sc->rge_flags & RGE_FLAG_DESCV2) {
			cur_rx_v2 = &q->q_rx.rge_rx_list_v2[i];
			rxstat = le32toh(cur_rx_v2->rx_qword0.rge_cmdsts);
			dw = (const uint32_t *)cur_rx_v2;
		} else {
			cur_rx = &q->q_rx.rge_rx_list[i];
			rxstat =
			    le32toh(cur_rx->hi_qword1.rx_qword4.rge_cmdsts);
			dw = &((const uint32_t *)cur_rx)[4];
		}
		if ((rxstat & RGE_RDCMDSTS_OWN) != 0) {
			break;
		}

		/* Ensure everything else has been DMAed */
		rmb();

		if (sc->rge_flags & RGE_FLAG_DESCV2) {
			hash = le32toh(cur_rx_v2->qword0.rx_rss.rge_rss);
			hashtype =
			    le32toh(cur_rx_v2->qword0.rx_rss.rge_hdr_info) &
			    RGE_RDHDRINFO_RSSTYPE_MASK;
		}

		/* Get the current rx buffer, sync */
		rxq = &q->q_rx.rge_rxq[i];

		/* Ensure any device updates are now visible in host memory */
		bus_dmamap_sync(sc->sc_dmat_rx_buf, rxq->rxq_dmamap,
		    BUS_DMASYNC_POSTREAD);

		/* Unload the DMA map, we are done with it here */
		bus_dmamap_unload(sc->sc_dmat_rx_buf, rxq->rxq_dmamap);
		m = rxq->rxq_mbuf;
		rxq->rxq_mbuf = NULL;

		rx = 1;

		RGE_DPRINTF(sc, RGE_DEBUG_RECV_DESC,
		    "%s: RX: [%d]: m=%p, m_data=%p, m_len=%ju, "
		    "desc=0x%08x 0x%08x 0x%08x 0x%08x\n",
		    __func__,
		    i,
		    m,
		    m->m_data,
		    (uintmax_t) m->m_len,
		    dw[0], dw[1], dw[2], dw[3]);

		if ((rxstat & rge_rxstatus_mask(sc, CMDSTS_SOF)) != 0) {
			if (q->q_rx.rge_head != NULL) {
				sc->sc_drv_stats.rx_desc_err_multidesc++;
				if_inc_counter(sc->sc_ifp, IFCOUNTER_IERRORS,
				    1);
				m_freem(q->q_rx.rge_head);
				q->q_rx.rge_tail = &q->q_rx.rge_head;
			}

			m->m_pkthdr.len = 0;
		} else if (q->q_rx.rge_head == NULL) {
			m_freem(m);
			continue;
		} else
			m->m_flags &= ~M_PKTHDR;

		*q->q_rx.rge_tail = m;
		q->q_rx.rge_tail = &m->m_next;

		mlen = rxstat & RGE_RDCMDSTS_FRAGLEN;
		m->m_len = mlen;

		m = q->q_rx.rge_head;
		m->m_pkthdr.len += mlen;

		/* Ethernet CRC error */
		if (rxstat & rge_rxstatus_mask(sc, CMDSTS_RXERRSUM)) {
			sc->sc_drv_stats.rx_ether_csum_err++;
			if_inc_counter(sc->sc_ifp, IFCOUNTER_IERRORS, 1);
			m_freem(m);
			q->q_rx.rge_head = NULL;
			q->q_rx.rge_tail = &q->q_rx.rge_head;
			continue;
		}

		/*
		 * This mbuf is part of a multi-descriptor frame,
		 * so count it towards that.
		 *
		 * Yes, this means we won't be counting the
		 * final descriptor/mbuf as part of a multi-descriptor
		 * frame; if someone wishes to do that then it
		 * shouldn't be too hard to add.
		 */
		if ((rxstat & rge_rxstatus_mask(sc, CMDSTS_EOF)) == 0) {
			sc->sc_drv_stats.rx_desc_jumbo_frag++;
			continue;
		}

		q->q_rx.rge_head = NULL;
		q->q_rx.rge_tail = &q->q_rx.rge_head;

		m_adj(m, -ETHER_CRC_LEN);
		m->m_pkthdr.rcvif = sc->sc_ifp;
		if_inc_counter(sc->sc_ifp, IFCOUNTER_IPACKETS, 1);

		extsts = (sc->rge_flags & RGE_FLAG_DESCV2) ?
		    le32toh(cur_rx_v2->rx_qword0.rge_extsts) :
		    le32toh(cur_rx->hi_qword1.rx_qword4.rge_extsts);

		/* Check IP header and TCP/UDP checksums. */
		if (check_hwcsum)
			rge_rxcsum(sc, rxstat, extsts, m);

		/* RSS hash, or at least the RX queue the frame arrived on */
		if (hashtype != RGE_RDHDRINFO_RSSTYPE_NONE) {
			m->m_pkthdr.flowid = hash;
			M_HASHTYPE_SET(m, M_HASHTYPE_OPAQUE_HASH);
		} else if (sc->sc_nqueues > 1) {
			m->m_pkthdr.flowid = q->q_index;
			M_HASHTYPE_SET(m, M_HASHTYPE_OPAQUE);
		}

		if (extsts & RGE_RDEXTSTS_VTAG) {
			sc->sc_drv_stats.rx_offload_vlan_tag++;
			m->m_pkthdr.ether_vtag =
			    ntohs(extsts & RGE_RDEXTSTS_VLAN_MASK);
			m->m_flags |= M_VLANTAG;
		}

		mbufq_enqueue(mq, m);

		maxpkt--;
	}

	/* If we stopped because of the packet limit there may be more */
	if (more != NULL)
		*more = (rx != 0 && maxpkt <= 0);

	if (!rx)
		return (0);

	/*
	 * Make sure any device updates to the descriptor ring are
	 * visible to the host before we continue.
	 */
	bus_dmamap_sync(sc->sc_dmat_rx_desc, q->q_rx.rge_rx_list_map,
	    BUS_DMASYNC_PREREAD | BUS_DMASYNC_PREWRITE);
	wmb();

	/* Update the consumer index, refill the RX ring */
	q->q_rx.rge_rxq_considx = i;
	rge_fill_rx_ring(q);

	return (1);
}

int
rge_txeof(struct rge_queues *q)
{
	struct rge_softc *sc = q->q_sc;
	struct ifnet *ifp = sc->sc_ifp;
	struct rge_txq *txq;
	uint32_t txstat;
	int cons, prod, cur, idx;
	int free = 0, ntx = 0;
	int pktlen;
	bool is_mcast;

	RGE_ASSERT_LOCKED(sc);

	sc->sc_drv_stats.txeof_cnt++;

	prod = q->q_tx.rge_txq_prodidx;
	cons = q->q_tx.rge_txq_considx;

	idx = cons;
	while (idx != prod) {
		txq = &q->q_tx.rge_txq[idx];
		cur = txq->txq_descidx;

		rge_tx_list_sync(sc, q, cur, 1, BUS_DMASYNC_POSTREAD);
		txstat = (sc->rge_flags & RGE_FLAG_DESCV2) ?
		    q->q_tx.rge_tx_list_v2[cur].rge_cmdsts :
		    q->q_tx.rge_tx_list[cur].rge_cmdsts;
		rge_tx_list_sync(sc, q, cur, 1, BUS_DMASYNC_PREREAD);
		if ((txstat & htole32(RGE_TDCMDSTS_OWN)) != 0) {
			free = 2;
			break;
		}

		bus_dmamap_sync(sc->sc_dmat_tx_buf, txq->txq_dmamap,
		    BUS_DMASYNC_POSTWRITE);
		bus_dmamap_unload(sc->sc_dmat_tx_buf, txq->txq_dmamap);
		pktlen = txq->txq_mbuf->m_pkthdr.len;
		is_mcast = ((txq->txq_mbuf->m_flags & M_MCAST) != 0);
		m_freem(txq->txq_mbuf);
		txq->txq_mbuf = NULL;
		ntx++;

		if ((txstat &
		    htole32(RGE_TDCMDSTS_EXCESSCOLL | RGE_TDCMDSTS_COLL)) != 0)
			if_inc_counter(ifp, IFCOUNTER_COLLISIONS, 1);
		if ((txstat & htole32(RGE_TDCMDSTS_TXERR)) != 0)
			if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		else {
			if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
			if_inc_counter(ifp, IFCOUNTER_OBYTES, pktlen);
			if (is_mcast)
				if_inc_counter(ifp, IFCOUNTER_OMCASTS, 1);

		}

		idx = RGE_NEXT_TX_DESC(cur);
		free = 1;
	}

	/* If we didn't complete any TX descriptors then return 0 */
	if (free == 0)
		return (0);

	if (idx >= cons) {
		rge_tx_list_sync(sc, q, cons, idx - cons,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
	} else {
		rge_tx_list_sync(sc, q, cons, RGE_TX_LIST_CNT - cons,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
		rge_tx_list_sync(sc, q, 0, idx,
		    BUS_DMASYNC_POSTREAD | BUS_DMASYNC_POSTWRITE);
	}

	q->q_tx.rge_txq_considx = idx;

	RGE_DPRINTF(sc, RGE_DEBUG_XMIT,
	    "%s: handled %d frames; prod=%d, cons=%d\n", __func__,
	    ntx, q->q_tx.rge_txq_prodidx, q->q_tx.rge_txq_considx);

	/*
	 * We processed the ring and hit a descriptor that was still
	 * owned by the hardware, so there's still pending work.
	 *
	 * If we got to the end of the ring and there's no further
	 * frames owned by the hardware then we can quieten the
	 * watchdog.
	 */
	if (free == 2)
		sc->sc_watchdog = 5;
	else
		sc->sc_watchdog = 0;

	/*
	 * Kick-start the transmit task just in case we have
	 * more frames available.
	 */
	taskqueue_enqueue(sc->sc_tq, &sc->sc_tx_task);

	return (1);
}

static u_int
rge_hash_maddr(void *arg, struct sockaddr_dl *sdl, u_int cnt)
{
	uint32_t crc, *hashes = arg;

	/* XXX TODO: validate this does addrlo? */
	crc = ether_crc32_be(LLADDR(sdl), ETHER_ADDR_LEN) >> 26;
	crc &= 0x3f;

	if (crc < 32)
		hashes[0] |= (1 << crc);
	else
		hashes[1] |= (1 << (crc - 32));

	return (1);
}

/**
 * @brief Configure the RX filter and multicast filter.
 *
 * This must be called with the driver lock held.
 */
static void
rge_iff_locked(struct rge_softc *sc)
{
	uint32_t hashes[2];
	uint32_t rxfilt;

	RGE_ASSERT_LOCKED(sc);

	rxfilt = RGE_READ_4(sc, RGE_RXCFG);
	rxfilt &= ~(RGE_RXCFG_ALLPHYS | RGE_RXCFG_MULTI);

	/*
	 * Always accept frames destined to our station address.
	 * Always accept broadcast frames.
	 */
	rxfilt |= RGE_RXCFG_INDIV | RGE_RXCFG_BROAD;

	if ((if_getflags(sc->sc_ifp) & (IFF_PROMISC | IFF_ALLMULTI)) != 0) {
		rxfilt |= RGE_RXCFG_MULTI;
		if ((if_getflags(sc->sc_ifp) & IFF_PROMISC) != 0)
			rxfilt |= RGE_RXCFG_ALLPHYS;
		hashes[0] = hashes[1] = 0xffffffff;
	} else {
		rxfilt |= RGE_RXCFG_MULTI;
		/* Program new filter. */
		memset(hashes, 0, sizeof(hashes));
		if_foreach_llmaddr(sc->sc_ifp, rge_hash_maddr, &hashes);
	}

	RGE_WRITE_4(sc, RGE_RXCFG, rxfilt);
	RGE_WRITE_4(sc, RGE_MAR0, bswap32(hashes[1]));
	RGE_WRITE_4(sc, RGE_MAR4, bswap32(hashes[0]));
}

/**
 * @brief Program the RSS hash key and redirection table.
 *
 * Must be called with the driver lock held.
 */
static void
rge_init_rss(struct rge_softc *sc)
{
	uint8_t rss_key[RGE_RSS_KEY_SIZE];
	uint32_t ctrl, reta = 0;
	int i, qid;

	RGE_ASSERT_LOCKED(sc);

#ifdef RSS
	rss_getkey(rss_key);
#else
	memcpy(rss_key, sc->sc_rss_key, sizeof(rss_key));
#endif

	ctrl = (fls(sc->sc_nqueues) - 1) << 16;
	ctrl |= (RGE_RSS_CTRL_IPV4 | RGE_RSS_CTRL_IPV6);
	ctrl |= (RGE_RSS_CTRL_TCP_IPV4 | RGE_RSS_CTRL_TCP_IPV6);
	ctrl |= (RGE_RSS_CTRL_IPV6_EXT | RGE_RSS_CTRL_TCP_IPV6_EXT);
	ctrl |= (fls(RGE_RSS_MAX_INDTBL_SIZE) - 1) << 8;
	RGE_WRITE_4(sc, RGE_RSS_CTRL, ctrl);

	/* Set up the redirection table. */
	for (i = 0; i < RGE_RSS_MAX_INDTBL_SIZE; i++) {
#ifdef RSS
		qid = rss_get_indirection_to_bucket(i) % sc->sc_nqueues;
#else
		qid = i % sc->sc_nqueues;
#endif

		/*
		 * The low 8 bits are for hash value (n+0);
		 * The next 8 bits are for hash value (n+1), etc.
		 */
		reta = reta >> 8;
		reta |= (((uint32_t)qid) << 24);
		if ((i & 3) == 3) {
			RGE_WRITE_4(sc, RGE_RSS_INDTBL(i >> 2), reta);
			reta = 0;
		}
	}

	/* Now fill our hash function seeds. */
	for (i = 0; i < RGE_RSS_KEY_SIZE / sizeof(uint32_t); i++)
		RGE_WRITE_4(sc, RGE_RSS_KEY(i),
		    le32dec(&rss_key[i * sizeof(uint32_t)]));
}

static void
rge_add_media_types(struct rge_softc *sc)
{
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_10_T, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_10_T | IFM_FDX, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_100_TX, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_100_TX | IFM_FDX, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_1000_T, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_1000_T | IFM_FDX, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_2500_T, 0, NULL);
	ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_2500_T | IFM_FDX, 0, NULL);

	if (RGE_TYPE_R26(sc)) {
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_5000_T, 0, NULL);
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_5000_T | IFM_FDX,
		    0, NULL);
	} else if (sc->rge_type == MAC_R27) {
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_10G_T, 0, NULL);
		ifmedia_add(&sc->sc_media, IFM_ETHER | IFM_10G_T | IFM_FDX,
		    0, NULL);
	}
}

/**
 * @brief Deferred packet dequeue and submit.
 */
static void
rge_tx_task(void *arg, int npending)
{
	struct rge_softc *sc = (struct rge_softc *) arg;
	/* Note: for now, one queue */
	struct rge_queues *q = sc->sc_queues;
	struct mbuf *m;
	int ntx = 0;
	int idx, free, used;

	RGE_DPRINTF(sc, RGE_DEBUG_XMIT, "%s: running\n", __func__);

	RGE_LOCK(sc);
	sc->sc_drv_stats.tx_task_cnt++;

	if (sc->sc_stopped == true) {
		sc->sc_watchdog = 0;
		RGE_UNLOCK(sc);
		return;
	}

	/* Calculate free space. */
	idx = q->q_tx.rge_txq_prodidx;
	free = q->q_tx.rge_txq_considx;
	if (free <= idx)
		free += RGE_TX_LIST_CNT;
	free -= idx;

	for (;;) {
		if (free < RGE_TX_NSEGS + 2) {
			break;
		}

		/* Dequeue */
		m = mbufq_dequeue(&sc->sc_txq);
		if (m == NULL)
			break;

		/* Attempt to encap, m might change due to defrag */
		used = rge_encap(sc, q, &m, idx);
		if (used < 0) {
			if_inc_counter(sc->sc_ifp, IFCOUNTER_OQDROPS, 1);
			m_freem(m);
			continue;
		} else if (used == 0) {
			mbufq_prepend(&sc->sc_txq, m);
			break;
		}

		/*
		 * Note: mbuf is now owned by the tx ring, but we hold the
		 * lock so it's safe to pass it up here to be copied without
		 * worrying the TX task will run and dequeue/free it before
		 * we get a shot at it.
		 */
		ETHER_BPF_MTAP(sc->sc_ifp, m);

		/* Update free/idx pointers */
		free -= used;
		idx += used;
		if (idx >= RGE_TX_LIST_CNT)
			idx -= RGE_TX_LIST_CNT;

		ntx++;
	}

	/* Ok, did we queue anything? If so, poke the hardware */
	if (ntx > 0) {
		q->q_tx.rge_txq_prodidx = idx;
		sc->sc_watchdog = 5;
		RGE_WRITE_2(sc, RGE_TXSTART, RGE_TXSTART_START);
	}

	RGE_DPRINTF(sc, RGE_DEBUG_XMIT,
	    "%s: handled %d frames; prod=%d, cons=%d\n", __func__,
	    ntx, q->q_tx.rge_txq_prodidx, q->q_tx.rge_txq_considx);

	RGE_UNLOCK(sc);
}

/**
 * @brief Called by the sc_timeout callout.
 *
 * This is called by the callout code with the driver lock held.
 */
void
rge_tick(void *arg)
{
	struct rge_softc *sc = arg;

	RGE_ASSERT_LOCKED(sc);

	rge_link_state(sc);

	/*
	 * Since we don't have any other place yet to trigger/test this,
	 * let's do it here every second and just bite the driver
	 * blocking for a little bit whilst it happens.
	 */
	if ((if_getdrvflags(sc->sc_ifp) & IFF_DRV_RUNNING) != 0)
		rge_hw_mac_stats_fetch(sc, &sc->sc_mac_stats.lcl_stats);

	/*
	 * Handle the TX watchdog.
	 */
	if (sc->sc_watchdog > 0) {
		sc->sc_watchdog--;
		if (sc->sc_watchdog == 0) {
			RGE_PRINT_ERROR(sc, "TX timeout (watchdog)\n");
			rge_init_locked(sc);
			sc->sc_drv_stats.tx_watchdog_timeout_cnt++;
		}
	}

	callout_reset(&sc->sc_timeout, hz, rge_tick, sc);
}

/**
 * @brief process a link state change.
 *
 * Must be called with the driver lock held.
 */
void
rge_link_state(struct rge_softc *sc)
{
	int link = LINK_STATE_DOWN;

	RGE_ASSERT_LOCKED(sc);

	if (rge_get_link_status(sc))
		link = LINK_STATE_UP;

	if (if_getlinkstate(sc->sc_ifp) != link) {
		sc->sc_drv_stats.link_state_change_cnt++;
		if_link_state_change(sc->sc_ifp, link);
	}
}

static void
rge_setwol(struct rge_softc *sc)
{
	if_t ifp = sc->sc_ifp;
	int enable;

	mtx_assert(&sc->sc_mtx, MA_OWNED);

	if (!pci_has_pm(sc->sc_dev))
		return;

	enable = (if_getcapenable(ifp) & IFCAP_WOL_MAGIC) != 0;

	rge_wol_config(sc, enable);
}

/**
 * @brief Suspend
 */
static int
rge_suspend(device_t dev)
{
	struct rge_softc *sc = device_get_softc(dev);

	RGE_LOCK(sc);
	rge_stop_locked(sc);
	rge_setwol(sc);
	sc->sc_suspended = true;
	RGE_UNLOCK(sc);

	return (0);
}

/**
 * @brief Resume
 */
static int
rge_resume(device_t dev)
{
	struct rge_softc *sc = device_get_softc(dev);

	RGE_LOCK(sc);

	/* reinit if required */
	if (if_getflags(sc->sc_ifp) & IFF_UP)
		rge_init_locked(sc);

	sc->sc_suspended = false;

	RGE_UNLOCK(sc);

	return (0);
}

/**
 * @brief Shutdown the driver during shutdown
 */
static int
rge_shutdown(device_t dev)
{
	struct rge_softc *sc = device_get_softc(dev);

	RGE_LOCK(sc);
	rge_stop_locked(sc);
	rge_setwol(sc);
	RGE_UNLOCK(sc);

	return (0);
}

#ifdef DEBUGNET
static void
rge_debugnet_init(if_t ifp, int *nrxr, int *ncl, int *clsize)
{
	struct rge_softc *sc;

	sc = if_getsoftc(ifp);
	RGE_LOCK(sc);
	*nrxr = RGE_RX_LIST_CNT;
	*ncl = DEBUGNET_MAX_IN_FLIGHT;
	*clsize = MCLBYTES;
	RGE_UNLOCK(sc);
}

static void
rge_debugnet_event(if_t ifp __unused, enum debugnet_ev event __unused)
{
}

static int
rge_debugnet_transmit(if_t ifp, struct mbuf *m)
{
	struct rge_softc *sc;
	struct rge_queues *q;
	int idx, free, used;

	sc = if_getsoftc(ifp);
	if ((if_getdrvflags(ifp) & IFF_DRV_RUNNING) == 0 ||
	    sc->sc_stopped)
		return (EBUSY);

	q = sc->sc_queues;
	idx = q->q_tx.rge_txq_prodidx;
	free = q->q_tx.rge_txq_considx;
	if (free <= idx)
		free += RGE_TX_LIST_CNT;
	free -= idx;
	if (free < RGE_TX_NSEGS + 2)
		return (ENOBUFS);

	used = rge_encap(sc, q, &m, idx);
	if (used <= 0) {
		m_freem(m);
		return (ENOBUFS);
	}

	idx += used;
	if (idx >= RGE_TX_LIST_CNT)
		idx -= RGE_TX_LIST_CNT;
	q->q_tx.rge_txq_prodidx = idx;

	RGE_WRITE_2(sc, RGE_TXSTART, RGE_TXSTART_START);
	return (0);
}

static int
rge_debugnet_poll(if_t ifp, int count __unused)
{
	struct rge_softc *sc;
	struct rge_queues *q;
	struct mbufq rx_mq;
	struct mbuf *m;
	int i;

	sc = if_getsoftc(ifp);
	if ((if_getdrvflags(ifp) & IFF_DRV_RUNNING) == 0 ||
	    sc->sc_stopped)
		return (EBUSY);

	rge_txeof(&sc->sc_queues[0]);
	mbufq_init(&rx_mq, RGE_RX_LIST_CNT);
	for (i = 0; i < sc->sc_nqueues; i++) {
		q = &sc->sc_queues[i];
		(void)rge_rxeof(q, &rx_mq, NULL);
		while ((m = mbufq_dequeue(&rx_mq)) != NULL)
			if_input(ifp, m);
	}
	return (0);
}
#endif /* DEBUGNET */

static device_method_t rge_methods[] = {
	DEVMETHOD(device_probe,			rge_probe),
	DEVMETHOD(device_attach,		rge_attach),
	DEVMETHOD(device_detach,		rge_detach),

	DEVMETHOD(device_suspend,		rge_suspend),
	DEVMETHOD(device_resume,		rge_resume),
	DEVMETHOD(device_shutdown,		rge_shutdown),

	DEVMETHOD_END
};

static driver_t rge_driver = {
	"rge",
	rge_methods,
	sizeof(struct rge_softc)
};

MODULE_DEPEND(rge, pci, 1, 1, 1);
MODULE_DEPEND(rge, ether, 1, 1, 1);

DRIVER_MODULE_ORDERED(rge, pci, rge_driver, NULL, NULL, SI_ORDER_ANY);
MODULE_PNP_INFO("U16:vendor;U16:device;D:#", pci, rge, rge_devices,
    nitems(rge_devices) - 1);
