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

#include "lib/common.h"

#include "lib/oop.h"
#include "lib/event_watcher.h"
#include "lib/nettools.h"
#include "lib/append.h"

#include "ping.h"

#define GUPPY_VERSION "1.3"

static ev_watcher_t *watcher = NULL;

static char *dst_hostname = NULL;
static in_port_t dst_port = 0;
static in_port_t src_port = 0;
static uint32_t ping_flags = 0;

static void
usage(void)
{
  printf(
    "Usage:\tguppy [-c] [-s source_port] [host:port | host port]\n"
    "      \tguppy -h\n"
    "\n"
    "-c\tSend a SCP ping.\n"
    "-h\tShow this usage information.\n"
    "-s\tBind the UDP socket to the supplied port.\n"
    "-v\tPrint version information.\n"
  );

  exit(EXIT_FAILURE);
}

static int
process_args(int argc, char ** const argv)
{
  net_addr_t addr;
  char *port;
  int c;
 
  RUNTIME_ASSERT(argc > 0);
  RUNTIME_ASSERT(argv);
  
  while ((c = getopt(argc, argv, "Cchs:vx")) != -1) {
    switch (c) {
    case 'c':
      ping_flags |= PING_F_SCP;
      break;
      
    case 'C':
      ping_flags |= PING_F_CRAWLER;
      break;
      
    case 'h':
      usage();
      break;

    case 's':
      if (0 != src_port) {
        fprintf(stderr, "Multiple use of -s.\n");
        usage();
      }
      if (!parse_port_number(optarg, &src_port, NULL)) {
        fprintf(stderr, "Invalid source port number\n");
        usage();
      }
      break;
     
    case 'v':
      printf("Guppy " GUPPY_VERSION "\n");
      exit(EXIT_SUCCESS);
      break;

    case 'x':
      ping_flags |= PING_F_SCAN;
      break;

    default:
      usage();
    }
  }
  
  if (optind >= argc || !argv[optind]) {
    fprintf(stderr, "Missing host\n");
    usage();
  }
  
  dst_hostname = compat_strdup(argv[optind]);
  if (!dst_hostname) {
    perror("compat_strdup() failed");
    exit(EXIT_FAILURE);
  }
  
  if (parse_net_addr(dst_hostname, &addr, &port)) {
    char buf[IPV6_ADDR_BUFLEN];
   
    /* Get rid of [] around an IPv6 address */
    print_ipv6_addr(buf, sizeof buf, net_addr_ipv6(&addr));
    /* Just leak dst_hostname so that port points to valid memory */
    dst_hostname = compat_strdup(buf);

    if (':' == *port)
      *port++ = '\0';
    else
      port = NULL;
  } else if (NULL != (port = strchr(dst_hostname, ':'))) {
    *port++ = '\0';
  }

  if (!(PING_F_SCAN & ping_flags)) {
    if (!port) {
      optind++;
      if (optind >= argc || !argv[optind]) {
        fprintf(stderr, "Missing port\n");
        usage();
      }
      port = argv[optind];
    }

    RUNTIME_ASSERT(port != NULL);
    if (!parse_port_number(port, &dst_port, NULL)) {
      fprintf(stderr, "Invalid destination port number\n");
      usage();
    }
  }
  
  return 0;
}

static void
initialize(ev_watcher_t *w, const char *hostname, in_port_t port,
    in_port_t source_port)
{
  static bool was_here = false;

  RUNTIME_ASSERT(!was_here);
  was_here = true;
  
  RUNTIME_ASSERT(w);
  RUNTIME_ASSERT(hostname != NULL);
  RUNTIME_ASSERT((PING_F_SCAN & ping_flags) || port != 0);

  if (ping_init(w, hostname, port, source_port, ping_flags)) {
    CRIT("ping_init() failed");
    exit(EXIT_FAILURE);
  }
 
}

int
main(int argc, char *argv[])
{
  if (0 == getuid() || 0 == geteuid()) {
    CRIT("Refusing to run super-user");
    exit(EXIT_FAILURE);
  }
  
  if (process_args(argc, argv)) {
    exit(EXIT_FAILURE);
  }

  watcher = ev_watcher_new();
  if (!watcher) {
    CRIT("watcher_new() failed");
    exit(EXIT_FAILURE);
  }
  ev_watcher_set_timeout(watcher, 100);
  initialize(watcher, dst_hostname, dst_port, src_port);
  ev_watcher_mainloop(watcher);
  ev_watcher_destruct(watcher);
  
  return EXIT_SUCCESS;
}

/* vi: set ai et ts=2 sts=2 sw=2 cindent: */
