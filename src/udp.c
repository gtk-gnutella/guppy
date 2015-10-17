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

#include "udp.h"

#include "lib/append.h"
#include "lib/ggep.h"
#include "lib/guid.h"
#include "lib/list.h"
#include "lib/nettools.h"
#include "lib/mem.h"

#define IS_POWER_OF_2(x) ((x) && 0 == ((x) & ((x) - 1)))

static connection_t *udp_con;
static void (*udp_pong_cb)(const net_addr_t *addr, in_port_t, void *);

typedef enum {
  GNET_P_PING = 0x00,
  GNET_P_PONG = 0x01,
  GNET_P_VMSG = 0x31,
  GNET_P_PUSH = 0x40,
  GNET_P_QASK = 0x80,
  GNET_P_QHIT = 0x81
} gnet_p_t;

struct vmsg_head {
  unsigned char vendor_id[4];
  unsigned char selector[2];
  unsigned char version[2];
};

typedef struct ping_info {
  guid_t guid;
  struct timeval tv;
  net_addr_t addr;
  in_port_t port;
  bool replied;
} ping_info_t;

static void
udp_pong_callback(const net_addr_t addr, in_port_t port, void *udata)
{
  if (udp_pong_cb)
    udp_pong_cb(&addr, port, udata);
}

void
udp_set_pong_callback(void (*cb)(const net_addr_t *, in_port_t, void *))
{
  udp_pong_cb = cb;
}

static void
udp_send_packet(const net_addr_t addr, in_port_t port,
    const void *data, size_t size)
{
  const struct sockaddr *to;
  socklen_t len;
  ssize_t ret;

  RUNTIME_ASSERT(udp_con);
  RUNTIME_ASSERT(data);

  len = net_addr_sockaddr(addr, port, &to);
  ret = sendto(connection_get_fd(udp_con), data, size, 0, to, len);
  if (ret == (ssize_t) -1) {
    DBUG("sendto() failed: %s", compat_strerror(errno));
  } else if (ret == 0) {
    DBUG("sendto() returned zero");
  } else if ((size_t) ret != size) {
    DBUG("sendto() partial write: ret=%ld", (long) ret);
  } else {
#if 0
    DBUG("sendto() succeeded");
#endif
  }
}

void
udp_send_ping(net_addr_t addr, in_port_t port,
  bool with_ggep_scp, bool with_ggep_ip)
{
  static const char ping_data[] = {
    /* 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,*/ /* GUID */
    GNET_P_PING,  /* Function (PING) */
    1,            /* TTL */
    0,            /* Hops */
    0, 0, 0, 0,   /* Size (corrected before sent) */
  };
  struct timeval tv;
  char buf[4096], *p = buf;
  size_t left = sizeof buf, size, len;
  ping_info_t *pi;
  void *udata;

  STATIC_ASSERT(23 - 16 == sizeof ping_data);
  STATIC_ASSERT(16 == sizeof pi->guid);

  RUNTIME_ASSERT(udp_con != NULL);

  if (NULL == (pi = mem_chunk_alloc(sizeof *pi))) {
    CRIT("mem_chunk_alloc() failed");
    return;
  }

  gettimeofday(&tv, NULL);
  guid_create(&pi->guid);
  pi->addr = addr;
  pi->port = port;
  pi->tv = tv;
  pi->replied = false;

  if (guid_is_magic(&pi->guid, &udata)) {
    mem_chunk_free(pi, sizeof *pi);
    CRIT("Oops GUID collision");
    return;
  }

  if (guid_add(&pi->guid, pi)) {
    mem_chunk_free(pi, sizeof *pi);
    CRIT("guid_add() failed");
    return;
  }

  /* 128-bit Message ID */
  p = append_chars(p, &left, cast_to_const_void_ptr(&pi->guid.u8[0]), 16);
  /* Pseudo ping header */
  p = append_chars(p, &left, ping_data, sizeof ping_data);

  /* Payload follows */
  if (with_ggep_scp || with_ggep_ip) {
    uint8_t pref;
    ggep_t gtx;

    (void) ggep_init(&gtx, p, left);
    
    /* LimeWire 4.2.2 doesn't reply to SCP pings without a preference
     * for either ultrapeers or leaves
     */ 
    
    if (with_ggep_scp) {
      pref = 1; /* Prefer for ultrapeers */
      ggep_pack(&gtx, GGEP_ID_SCP, 0, cast_to_const_void_ptr(&pref), 1);
    }
    if (with_ggep_ip) {
      ggep_pack(&gtx, GGEP_ID_IP, 0, NULL, 0);
    }
    len = ggep_end(&gtx);
    RUNTIME_ASSERT(left >= len);
    left -= len;
  }
   
  RUNTIME_ASSERT(left <= sizeof buf);
  size = sizeof buf - left;
  RUNTIME_ASSERT(size >= 23);
  
  len = size - 23;  /* Subtract the header size */
  RUNTIME_ASSERT(len < sizeof buf);

  /* Correct the payload length field of the Gnutella header */
  poke_le16(&buf[19], len);

  udp_send_packet(addr, port, buf, size);
}

void
udp_send_crawler_ping(net_addr_t addr, in_port_t port)
{
  static const char vmsg_data[] = {
    /* 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,*/ /* GUID */
    GNET_P_VMSG,  /* Function (PING) */
    1,            /* TTL */
    0,            /* Hops */
    0, 0, 0, 0,   /* Size (corrected before sent) */
  };
  static const struct vmsg_head vmsg_head = {
    { 'L', 'I', 'M', 'E' }, { 0x05, 0x00 }, { 0x01, 0x00 }
  };
  struct timeval tv;
  char buf[4096], *p = buf;
  size_t left = sizeof buf, size, len;
  ping_info_t *pi;
  void *udata;

  STATIC_ASSERT(23 - 16 == sizeof vmsg_data);
  STATIC_ASSERT(16 == sizeof pi->guid);

  RUNTIME_ASSERT(udp_con != NULL);

  if (NULL == (pi = mem_chunk_alloc(sizeof *pi))) {
    CRIT("mem_chunk_alloc() failed");
    return;
  }

  gettimeofday(&tv, NULL);
  guid_create(&pi->guid);
  pi->addr = addr;
  pi->port = port;
  pi->tv = tv;
  pi->replied = false;

  if (guid_is_magic(&pi->guid, &udata)) {
    mem_chunk_free(pi, sizeof *pi);
    CRIT("Oops GUID collision");
    return;
  }

  if (guid_add(&pi->guid, pi)) {
    mem_chunk_free(pi, sizeof *pi);
    CRIT("guid_add() failed");
    return;
  }

  /* 128-bit Message ID */
  p = append_chars(p, &left, cast_to_const_void_ptr(&pi->guid.u8[0]), 16);
  /* Pseudo vendor message header */
  p = append_chars(p, &left, vmsg_data, sizeof vmsg_data);
  p = append_chars(p, &left,
        cast_to_const_char_ptr(&vmsg_head), sizeof vmsg_head);
  p = append_char(p, &left, 0xffU); /* Number of Ultrapeers */
  p = append_char(p, &left, 0xffU); /* Number of Leaves */
  p = append_char(p, &left,        /* Format */
        0x00 | /* Plain */
        0x01 | /* Connection time */
        0x08 | /* User-Agent */
        0x10   /* Uptime */
        );

  RUNTIME_ASSERT(left <= sizeof buf);
  size = sizeof buf - left;
  RUNTIME_ASSERT(size >= 23);
  
  len = size - 23;  /* Subtract the header size */
  RUNTIME_ASSERT(len < sizeof buf);

  /* Correct the payload length field of the Gnutella header */
  poke_le16(&buf[19], len);

  udp_send_packet(addr, port, buf, size);
}

static void
handle_crawler_pong(const char *data, size_t size)
{
  (void) data;
  (void) size;
}

static void
handle_vmsg(const char *data, size_t size)
{
  const struct vmsg_head *vmsg_head;
  uint16_t selector, version;

  if (size < 23 + sizeof vmsg_head) {
    DBUG("Too small for a vendor message");
    return;
  }
  vmsg_head = cast_to_const_void_ptr(&data[23]);

  selector = peek_le16(vmsg_head->selector);
  version = peek_le16(vmsg_head->version);

  {
    char buf[64], *p = buf;
    size_t avail = sizeof buf;

    p = append_escaped_chars(p, &avail,
          cast_to_const_void_ptr(vmsg_head->vendor_id), 4);
	append_char(p, &avail, '\0');
    DBUG("Vendor ID: \"%s\", Selector=0x%04x, Version=0x%04x (%lu byte%s)",
      buf, (unsigned) selector, (unsigned) version, (unsigned long) size,
	  1 == size ? "" : "s");
  }

  if (
    0 == memcmp(vmsg_head->vendor_id, "LIME", 4) &&
    selector == 0x0006 &&
    version == 0x0001
  ) {
    handle_crawler_pong(data, size);
  }
}

static void
handle_packet(connection_t *c, const char *data, size_t len,
    const net_addr_t sender_addr, in_port_t sender_port)
{
  unsigned int function, ttl, hops, size;
  const char *p = data;
  size_t data_len;
  char addr_buf[NET_ADDR_PORT_BUFLEN];
  ggep_t gtx;
  ggep_id_t id;
  net_addr_t pong_addr = net_addr_unspecified;
  in_port_t pong_port = 0;
  char vendor[5] = { 0, 0, 0, 0, 0 };
  bool has_scp = false;
  bool has_vc = false;  /* set if there was a GGEP VC block */
  uint32_t vc = 0;  /* vendor code */
  struct peer_set ipp_peers;

  (void) c;

  ipp_peers.n = 0;
    
  if (len < 23) {
    DBUG("Packet is too small");
    return;
  }

  function = peek_u8(&data[16]);
  ttl = peek_u8(&data[17]);
  hops = peek_u8(&data[18]);
  size = peek_le32(&data[19]);

  switch (function) {
  case GNET_P_PING:
  case GNET_P_PONG:
  case GNET_P_VMSG:
    break;
  default:
    DBUG("Unsupported message type: 0x%02x", (unsigned char) function);
    return;
  }

  /* TTL of 0 or 1 should be OK */
  if (ttl > 1) {
    DBUG("Invalid TTL (%u)", ttl);
  }
  if (hops != 0) {
    DBUG("Invalid hop count (%u)", hops);
  }
  if (size + 23 != len) {
    DBUG("Invalid size (size=%u, len=%lu)",
        (unsigned) size, (unsigned long) len);
    return;
  }
  
  switch ((gnet_p_t) function) {
  case GNET_P_PING:
    p = &data[23];
#if 0
    if (len == 23)
      DBUG("Got bare ping");
#endif
    break;

  case GNET_P_PONG:
    {
      unsigned long files, kbs;
      in_addr_t ip;
      
      if (len < 37)
        DBUG("Pong is too small");

      pong_port = peek_le16(&data[23]);
      memcpy(&ip, &data[25], sizeof ip);
      pong_addr = 0 != ip ? net_addr_set_ipv4(ip) : net_addr_unspecified;
      files = peek_le32(&data[29]);
      kbs = peek_le32(&data[33]);
      print_ipv4_addr(addr_buf, sizeof addr_buf, ip);
      DBUG("Got %spong (ip=%s, port=%u, files=%lu, kbs=%lu)",
        len == 37 ? "bare " : "", addr_buf, pong_port, files, kbs);

      if (IS_POWER_OF_2(kbs)) {
        DBUG("Kbs is a power of 2 (remote probably runs as UP)");
      } else {
        DBUG("Kbs not a power of 2 (remote probably runs as leaf)");
      }
      
      p = &data[37];
    }
    break;
  
  case GNET_P_VMSG:
    handle_vmsg(data, len);
    break;
  case GNET_P_PUSH:
  case GNET_P_QASK:
  case GNET_P_QHIT:
    break;
  } 
  len -= (p - data);

  if (!ggep_decode(&gtx, p, len)) {
    DBUG("No GGEP data in packet");
    return;
  }
  
  for (;;) {
    char ggep_buf[4096];
    char id_name[GGEP_ID_BUFLEN];
    int ret;

    ret = ggep_next(&gtx, id_name);
    if (0 == ret)
      break;
    
    if (-1 == ret) {
      DBUG("Could not get next GGEP block");
      break;
    }
    
    data_len = ggep_data(&gtx, &p, ggep_buf, sizeof ggep_buf);
    if ((size_t) -1 == data_len) {
      WARN("Decompression of GGEP \"%s\" failed", id_name);
      continue;
    }
    
    id = ggep_map_id_name(id_name, NULL);
    if (GGEP_ID_INVALID == id) {
      DBUG("Unknown GGEP ID: \"%s\"", id_name);
      continue;
    }

    switch (id) {
    case GGEP_ID_UDPHC:
      {

        if (data_len == 0) {
          DBUG("UDPHC: No hostname given");
        } else {
          char host[256 + 1];
          size_t n = sizeof host;
          bool truncated = false;

          if (n >= data_len + 1) {
            n = data_len + 1;
          } else {
            DBUG("UDPHC: Hostname is too long");
            truncated = true;
          }

          (void) append_string(host, &n, p);
          if (n > 1) {
            DBUG("UDPHC: Hostname contained NUL (size=%lu)", (unsigned long) n);
          }
          DBUG("UDPHC: Hostname=\"%s%s\"", host, truncated ? " ..." : "");
        }
      }
      break;

    case GGEP_ID_TLS:
    case GGEP_ID_GTKG_TLS:
      DBUG("Peer supports TLS");
      break;

    case GGEP_ID_IP:
      if (0 == data_len) {
        DBUG("Empty IP extension in reply?");
      } else if (6 == data_len) {
        in_addr_t ip;
        in_port_t port;
            
        memcpy(&ip, &p[0], sizeof ip);
        port = peek_le16(&p[4]);
        print_ipv4_addr(addr_buf, sizeof addr_buf, ip);
        DBUG("Echoed IP: %s:%u", addr_buf, port);
      } else if (18 == data_len) {
        net_addr_t addr;
        in_port_t port;

        addr = net_addr_peek_ipv6(p);
        port = peek_le16(&p[16]);
        print_net_addr(addr_buf, sizeof addr_buf, addr);
        DBUG("Echoed IP: %s:%u", addr_buf, port);
      } else {
        DBUG("IP payload length (%lu) is invalid", (unsigned long) data_len);
      }
      break;

    case GGEP_ID_GTKG_IPV6:
    case GGEP_ID_6:
      if (0 == data_len) {
        DBUG("Peer supports IPv6");
      } else if (data_len >= 16) {
          net_addr_t addr;
          
          addr = net_addr_peek_ipv6(p);
          print_net_addr(addr_buf, sizeof addr_buf, addr);
          DBUG("IPV6 address found in GGEP \"%s\": %s", id_name, addr_buf);
      } else {
        DBUG("GGEP \"%s\": payload length (%lu) is too small",
          id_name, (unsigned long) data_len);
      }
      break;
      
    case GGEP_ID_IPP_TLS:
      {
        size_t i;

        for (i = 0; i < data_len; i++) {
          unsigned bit, byte = peek_u8(&p[i]);

          if (0 == byte) {
              DBUG("%uth byte in IPP_TLS is zero", (unsigned) i);
          }
          for (bit = 0; bit < 8; bit++) {
            if (byte & (0x80U >> bit))
              DBUG("%uth peer in IPP supports TLS", (unsigned) i * 8 + bit);
          }
        }
      }
      break;

    case GGEP_ID_IPP:
      if (0 == data_len || 0 != (data_len % 6)) {
        DBUG("IPP payload length (%lu) is not a multiple of 6",
          (unsigned long) data_len);
      } else {
#if 1 
        DBUG("%lu peers in IPP", (unsigned long) (data_len / 6));
#endif
        while (data_len) {
          in_addr_t ip;
          in_port_t port;
            
          memcpy(&ip, &p[0], sizeof ip);
          port = peek_le16(&p[4]);
          p += 6;
          
          print_ipv4_addr(addr_buf, sizeof addr_buf, ip);
#if 1
          DBUG("IPP: %s:%u", addr_buf, port);
#endif
          
          RUNTIME_ASSERT(data_len >= 6);
          data_len -= 6;

          if (ipp_peers.n < ARRAY_LEN(ipp_peers.addr)) {
            size_t i = ipp_peers.n++;
            
            ipp_peers.addr[i].addr = net_addr_set_ipv4(ip);
            ipp_peers.addr[i].port = port;
          }
        }
      }
      break;

    case GGEP_ID_SCP:
      if (has_scp)
        WARN("Multiple GGEP SCP blocks");

      has_scp = true;
      if (data_len > 0) {
        DBUG("SCP: Prefers free %s slots", *p & 1 ? "ultrapeer" : "leaf");
      } else {
        DBUG("SCP: No slot preferences");
      }
      break;

    case GGEP_ID_PHC:
      if (0 == data_len) {
        DBUG("PHC: No payload");
      }
      
      while (data_len > 0) {
        char buf[512];
        const char *q;
        size_t left, n;

        RUNTIME_ASSERT(data_len <= INT_MAX);
        q = memchr(p, '\n', data_len);
        if (q) {
          q++;
        } else {
          q = &p[data_len];
        }
        n = q - p;
        RUNTIME_ASSERT(data_len >= n);
        data_len -= n;
        left = MIN(sizeof buf, (n + 1));
        (void) append_string(buf, &left, p);
        p = q;

        DBUG("PHC: \"%.*s\"", (int) MAX(n, (unsigned) INT_MAX), buf);
      }
      break;

    case GGEP_ID_DHT:
#if 1
      DBUG("Node supports DHT");
#endif
      if (data_len > 0) {
        char buf[64], *q;
        size_t left = sizeof buf - 1;

        q = append_escaped_chars(buf, &left, p, data_len);
        *q = '\0';
#if 1
        DBUG("DHT payload: \"%s\"", buf);
#endif
      }
      break;

    case GGEP_ID_DU:
      if (data_len > 4) {
        DBUG("Invalid length of DU payload: data_len=%lu", (unsigned long) data_len);
      } else {
        size_t i = data_len;
        unsigned long uptime = 0;

        while (i != 0) {
          i--;
          uptime = (uptime << 8) | peek_u8(&p[i]);
        }
#if 1
        DBUG("Daily Uptime: %lu seconds", uptime);
#endif
      }
      break;

    case GGEP_ID_LOC:
      if (data_len >= 2) {
        char loc[32], *q;
        size_t left = sizeof loc - 1;
       
        q = append_escaped_chars(loc, &left, p, data_len);
        *q = '\0';

#if 1 
        DBUG("Locale preference: \"%s\"", loc);
#endif
      } else {
        DBUG("Invalid length for LOC (len=%lu)", (unsigned long) data_len);
      }
      break;

    case GGEP_ID_GUE:
#if 1
      DBUG("Node supports GUESS");
#endif
      if (data_len > 0) {
        char buf[64], *q;
        size_t left = sizeof buf - 1;

        q = append_escaped_chars(buf, &left, p, data_len);
        *q = '\0';
        
#if 1
        DBUG("GUE payload: \"%s\"", buf);
#endif
      }
      break;

    case GGEP_ID_VC:
      if (has_vc)
        WARN("Multiple GGEP VC blocks");
      
      if (data_len < 5) {
        DBUG("Invalid length for VC (len=%lu)", (unsigned long) data_len);
      }
      
      if (data_len >= 5 && !has_vc) {
        char *q;
        size_t left = sizeof vendor - 1;

        memcpy((char *) &vc, p, 4);
        q = append_escaped_chars(vendor, &left, p, data_len);
        *q = '\0';
        DBUG("Vendor: \"%s\" char=%02x (%u)", vendor,
          (unsigned char) p[4], (unsigned) p[4] & 0xff);
      }

      has_vc = true;
      break;

    case GGEP_ID_UP:
      if (data_len == 3) {
#if 1
        /*
         * LimeWire always got the initial specs wrong, and GTKG adapted to
         * these as well.  The amount of leaf slots in p[1], the amount of
         * ultra slots is p[2], whereas the specs said it was the other way
         * round.   --RAM, 2012-11-02.
         */
        DBUG("Free slots: %u/%u (UP/Leaf) version=%u",
          (unsigned char) p[2], (unsigned char) p[1], (unsigned) p[0] & 0xff);
#endif
      } else {
        DBUG("Invalid length for UP (len=%lu)", (unsigned long) data_len);
      }
      break;

    default:
      DBUG("Unhandled GGEP ID: \"%s\" (payload of %lu byte%s)",
        id_name, (unsigned long) data_len, 1 == data_len ? "" : "s");
    }

  }

  switch (function) {
  case GNET_P_PONG: 
    {
      guid_t guid;
      bool is_magic, ip_match = true, port_match = true, is_dupe = false;
      ping_info_t *pi = NULL;
      void *udata;
      struct timeval tv;
      unsigned rtt = 0;

      memcpy(guid.u8, data, sizeof guid.u8);
      is_magic = guid_is_magic(&guid, &udata);
      if (!is_magic) {
        DBUG("Non-magic GUID");
      } else {
        RUNTIME_ASSERT(udata != NULL);

        pi = udata;
        gettimeofday(&tv, NULL);
        rtt = DIFFTIMEVAL(&tv, &pi->tv) / 1000;
        ip_match = net_addr_equal(pi->addr, sender_addr) ||
          net_addr_equal(pi->addr, net_addr_unspecified);
        port_match = pi->port == sender_port;
        is_dupe = pi->replied;
        pi->replied = false;

        print_net_addr_port(addr_buf, sizeof addr_buf, pi->addr, pi->port);
#if 1 
        DBUG("Extracted: RTT=%ums Peer=%s \t%s%s",
          rtt, addr_buf,
          ip_match && port_match ? "" : " MISMATCH!",
          is_dupe ? " DUPE!" : "");
#endif
      }

      /* Note, we don't ``pi'' here because guppy is not a long-lived
       * process and we might want to catch resent pongs. */
      
      if (
        !ip_match ||
        (
          !net_addr_equal(pong_addr, sender_addr) &&
          !net_addr_equal(pong_addr, net_addr_unspecified)
        )
      ) {
        DBUG("Address mismatch");
      } else if (!port_match || sender_port != pong_port) {
        DBUG("Port mismatch");
      } else if (is_dupe) {
        DBUG("Sender resent pong(?)");
      } else if (!is_magic) {
        DBUG("GUID is not magic");
      } else if (rtt > 3 * 60000U) {
        DBUG("Pong is out of time");
      } else {
        if (pi)
          pi->replied = true;

        udp_pong_callback(sender_addr, sender_port, &ipp_peers);
      }
    }
    break;
    
  case GNET_P_PING:
    {
      guid_t guid;

      memcpy(&guid.u8, data, sizeof guid);

      if (!has_scp) {
        /* Nothing to do */
      } else if (sender_port < 1024) {
        DBUG("Not ponging privileged port");
      } else if (net_addr_equal(sender_addr, connection_get_addr(udp_con))) {
        DBUG("Ping from myself(?)");
      } else if (guid_is_bogus(&guid)) {
        DBUG("Not ponging bogus GUID");
      } else if (net_addr_is_private(sender_addr)) {
        DBUG("Not ponging private address");
      }
    }
    break;

  case GNET_P_PUSH:
  case GNET_P_QASK:
  case GNET_P_QHIT:
    break;
  }
  
}

static void
handle_udp(connection_t *c, ev_type_t ev)
{
  char addr_buf[NET_ADDR_PORT_BUFLEN];
  char buf[4096];
  ssize_t ret;
  int fd;

  fd = connection_get_fd(c);
  if (ev & EVT_READ) {
    static const struct sockaddr_storage zero_from;
    struct sockaddr_storage from;
    socklen_t len = sizeof from;
    net_addr_t addr;
    in_port_t port;
    
    from = zero_from;
    ret = recvfrom(fd, buf, sizeof buf - 1, 0, cast_to_void_ptr(&from), &len);

    switch (from.ss_family) {
    case AF_INET:
      {
        const struct sockaddr_in *sin = cast_to_void_ptr(&from);

        addr = net_addr_set_ipv4(sin->sin_addr.s_addr);
        port = ntohs(sin->sin_port);
        print_net_addr_port(addr_buf, sizeof addr_buf, addr, port);
      }
      break;
      
#ifdef HAVE_IPV6_SUPPORT
    case AF_INET6:
      {
        const struct sockaddr_in6 *sin6 = cast_to_void_ptr(&from);

        addr = net_addr_peek_ipv6(sin6->sin6_addr.s6_addr);
        port = ntohs(sin6->sin6_port);
        print_net_addr_port(addr_buf, sizeof addr_buf, addr, port);
      }
      break;
#endif /* HAVE_IPV6_SUPPORT */

    default:
      {
        size_t size = sizeof addr_buf;
        
        addr = net_addr_unspecified;
        port = 0;
        append_string(addr_buf, &size, "<none>");
      }
    }


    if (ret == 0) {
      DBUG("recvfrom() returned zero (from=%s)", addr_buf);
    } else if (ret == (ssize_t) -1) {
      DBUG("recvfrom() failed (from=%s): %s", addr_buf, compat_strerror(errno));
    } else {
      RUNTIME_ASSERT(ret >= 0 && (size_t) ret < sizeof buf);
      buf[ret] = '\0';
      DBUG("recvfrom()=%ld (from=%s)", (long) ret, addr_buf);

      handle_packet(c, buf, ret, addr, port);
    }
  }
}

int
udp_init(ev_watcher_t *watcher, connection_t *c)
{
  RUNTIME_ASSERT(watcher != NULL);
  RUNTIME_ASSERT(c != NULL);
  udp_con = c;
  
  if (guid_init(1000000)) {
    CRIT("guid_init() failed");
    return -1;
  }

  connection_set_blocking(c, false);
  connection_set_rcvlowat(c, 23); /* Minimum Gnutella packet size */
  connection_set_rcvbuf(c, 2 * 64 * 1000);
  connection_set_sndbuf(c, 2 * 64 * 1000);
  connection_set_event_cb(c, handle_udp);
  ev_watcher_watch_source(watcher, connection_get_source(c), EVT_READ);

  return 0;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
