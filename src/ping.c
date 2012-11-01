/*
 * Copyright (c) 2004 Christian Biere <christianbiere@gmx.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "ping.h"

#include "lib/append.h"
#include "lib/hashtable.h"
#include "lib/list.h"
#include "lib/dns.h"

#include "udp.h"

static struct {
  net_addr_t dst_addr;
  in_port_t dst_port;
  bool with_ggep_scp;
  bool with_ggep_ip;
  bool crawler_ping;
} globals;

static void
initialize_random(void)
{
  struct timeval tv;
  unsigned long seed;
  
  gettimeofday(&tv, NULL);
  seed = (tv.tv_usec << 16)
    ^ (getpid() + 101 * getuid() + ~gethostid())
    ^ (tv.tv_sec << 13)
    ^ (PTR2UINT(&tv) >> 5);

  srandom(seed);
}

static void
send_ping(in_port_t port)
{
  RUNTIME_ASSERT(0 != port);

  if (globals.crawler_ping) {
    udp_send_crawler_ping(globals.dst_addr, port);
  } else {
    udp_send_ping(globals.dst_addr, port,
      globals.with_ggep_scp, globals.with_ggep_ip);
  }
}

#if 0
/* Crawler */
static hashtable_t *ht_ping, *ht_pong;
static unsigned pong_count;
static list_t *to_ping;
typedef struct { in_addr_t ip; in_port_t port; } host_t;
#endif

static void
pong_received(const net_addr_t *addr, in_port_t port, void *udata)
{
  RUNTIME_ASSERT(addr);

#if 1
  /* Ping */

  (void) udata;

  if (!net_addr_equal(*addr, globals.dst_addr) || port != globals.dst_port)
    return;

  INFO("Received valid pong");
  exit(EXIT_SUCCESS);
    
#else

  /* XXX: Defunct */
  /* Crawler */
    
  const struct ipv4_peer_set *ipp_peers = udata;
  size_t i;
  
  if (hashtable_get(ht_pong, (void *) (uintptr_t) ip, NULL))
    return;
  if (!hashtable_add(ht_pong, (void *) (uintptr_t) ip, (void *) (uintptr_t) port)) {
    CRIT("pong table is full");
    exit(EXIT_FAILURE);
  }
  INFO("Peer count: %u", (unsigned) hashtable_fill(ht_pong));

  pong_count++;

  if (!ipp_peers)
    return;

  for (i = 0; i < ipp_peers->n; i++) {
    
    ip = ipp_peers->addr[i].ip;
    port = ipp_peers->addr[i].port;
    
    if (
      !hashtable_get(ht_pong, UINT2PTR(ip), NULL) &&
      !hashtable_get(ht_ping, UINT2PTR(ip), NULL)
    ) {
      host_t *h;
      
      if (!hashtable_add(ht_ping, UINT2PTR(ip), UINT2PTR(port))) {
        CRIT("ping table is full");
        exit(EXIT_FAILURE);
      }

      h = calloc(1, sizeof *h);
      RUNTIME_ASSERT(h != NULL);
      h->ip = ip;
      h->port = port;
      if (!list_append(to_ping, h)) {
        CRIT("ping list is full");
        exit(EXIT_FAILURE);
      }
    }
  }
#endif
  
}

#if 0
/* Crawler */
static bool
refeed_pings(const void *key, const void *value, void *udata)
{
  host_t *h;

  (void) udata;

  if (hashtable_get(ht_pong, key, NULL))
    return false;
  
  h = calloc(1, sizeof *h);
  if (!h)
    return true;
    
  h->ip = (uintptr_t) key;
  h->port = (uintptr_t) value;

  if (!list_append(to_ping, h)) {
    free(h);
    return true;
  }

  return false;
}
#endif

static void
periodic_ping_handler(ev_watcher_t *watcher, const struct timeval *tv)
{
  static time_t first, last;
  time_t now = tv->tv_sec;
  static int ping_count = 0;
  
  (void) watcher;

  if (!last) {
    first = now;
    last = now;
  }
  
  if (ping_count < 3) {
    if (0 == ping_count || difftime(now, last) > (2 << ping_count)) {
      last = now;
      send_ping(globals.dst_port);
      ping_count++;
    }
  } else if (difftime(now, first) >= 30) {
    WARN("Timeout exceeded, no pong received");
    exit(EXIT_FAILURE);
  }
}

static void
periodic_scan_handler(ev_watcher_t *watcher, const struct timeval *now)
{
  static uint32_t ports = 0;
  static bool finished;
  int n = 0;
  
  (void) watcher;
  (void) now;

  for (n = 0; ports < 65536 && n < 10; ports++, n++) {
    static uint8_t map[65536 / 8];
    uint16_t port;
   
    port = random();
    while (map[port >> 3] & (1 << (port & 0x07)))
      port++;

    map[port >> 3] |= 1 << (port & 0x07);
    if (0 != port)
      send_ping(port);
  }

  if (!finished) {
    uint32_t p;

    p = (ports * 1000) / 65536;
    fprintf(stderr, "\r%3d.%d%% complete", (int) (p / 10), (int) (p % 10));

    if (65536 == ports) {
      fprintf(stderr, "\n");
      finished = true;
    }
  }
}

#if 0
static void
periodic_crawl_handler(ev_watcher_t *watcher, time_t now)
{
  int i;

  for (i = 0; 0 == pong_count && i < 4; i++) {
    host_t *h;
    list_iter_t iter;
    bool v;

    if (list_get_length(to_ping) < 1) {
      hashtable_foreach(ht_ping, refeed_pings, NULL);
      v = list_iter_first(&iter, to_ping);
      while (v) {
        h = list_iter_get_ptr(&iter);
        RUNTIME_ASSERT(h != NULL);
        hashtable_remove(ht_ping, h);
        v = list_iter_next(&iter);
      }
      
      break;
    }

    v = list_iter_first(&iter, to_ping);
    RUNTIME_ASSERT(v);
    h = list_iter_get_ptr(&iter);
    RUNTIME_ASSERT(h != NULL);
    udp_send_ping(h->ip, h->port, globals.with_ggep_scp);
    free(h);
    list_iter_delete(&iter);
  }

  pong_count = 0;
}
#endif


static int
lookup_host(const char *hostname, net_addr_t *addr)
{
  char addr_buf[NET_ADDR_BUFLEN];
  dnslookup_ctx_t *ctx;
  int error;

  RUNTIME_ASSERT(hostname);
  RUNTIME_ASSERT(addr);
  *addr = net_addr_unspecified;

  ctx = dnslookup_ctx_new();
  if (!ctx) {
    CRIT("dnslookup_ctx_new() failed");
    return -1;
  }
  if (dnslookup(ctx, hostname, &error)) {
    INFO("Could not resolve \"%s\"", hostname);
    dnslookup_ctx_free(ctx);
    return -1;
  }

  while (dnslookup_next(ctx, addr))
    if (!net_addr_equal(*addr, net_addr_unspecified))
      break;

  print_net_addr(addr_buf, sizeof addr_buf, *addr);
  DBUG("Host \"%s\" resolved to: \"%s\"", hostname, addr_buf);

  dnslookup_ctx_free(ctx);
  return 0;
}

int
ping_init(ev_watcher_t *watcher, const char *hostname, in_port_t port,
  in_port_t src_port, uint32_t flags)
{
  connection_t *udp_con;

  RUNTIME_ASSERT(watcher);
  RUNTIME_ASSERT(hostname);
  RUNTIME_ASSERT((PING_F_SCAN & flags) || port != 0);

  globals.with_ggep_scp = 0 != (flags & PING_F_SCP);
  globals.with_ggep_ip = 0 != (flags & PING_F_IP);
  globals.crawler_ping = 0 != (flags & PING_F_CRAWLER);

  if (
      lookup_host(hostname, &globals.dst_addr) ||
      net_addr_equal(globals.dst_addr, net_addr_unspecified)
  ) {
    WARN("Could not resolve hostname");
    return -1;
  }
  
  RUNTIME_ASSERT(!net_addr_equal(globals.dst_addr, net_addr_unspecified));
  globals.dst_port = port;

  udp_con = connection_udp(AF_INET == net_addr_family(globals.dst_addr) ? 
              net_addr_ipv4_mapped : net_addr_unspecified,
              src_port);

  if (!udp_con) {
     CRIT("connection_udp() failed: %s", compat_strerror(errno));
     return -1;
  }

#if 0
  /* Crawler */
  if (NULL == (to_ping = list_new())) {
    CRIT("list_new() failed");
    return -1;
  }
  
  if (NULL == (ht_ping = hashtable_new(1000000, NULL, NULL))) {
    CRIT("hashtable_new() failed");
    return -1;
  }

  if (NULL == (ht_pong = hashtable_new(1000000, NULL, NULL))) {
    CRIT("hashtable_new() failed");
    return -1;
  }
#endif

  if (udp_init(watcher, udp_con)) {
    CRIT("udp_init() failed");
    return -1;
  }
  udp_set_pong_callback(pong_received);
  
  ev_watcher_set_periodic_cb(watcher,
      (PING_F_SCAN & flags) ? periodic_scan_handler : periodic_ping_handler);

  initialize_random(); 
  return 0;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
