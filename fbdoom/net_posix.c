#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "doomtype.h"
#include "net_defs.h"
#include "net_io.h"

#ifndef DOOM_DEFAULT_PORT
#define DOOM_DEFAULT_PORT 2342
#endif

#ifndef MAX_PACKET_SIZE
#define MAX_PACKET_SIZE 1450
#endif

//
// Internal structures
//

// We store this inside the (void *handle) of net_addr_t
typedef struct {
  struct sockaddr_in sin;
  net_addr_t net_addr;
} posix_addr_entry_t;

static int sockfd = -1;
static uint16_t local_port = 0;
static boolean is_bound = false;

// Address table for reusing address objects (enables pointer comparison)
#define ADDR_TABLE_SIZE 16
static posix_addr_entry_t *addr_table[ADDR_TABLE_SIZE];
static int addr_table_count = 0;

// Forward declaration of the module
net_module_t net_sdl_module;

// We need to access packet creation, usually in net_packet.c
// If headers don't expose it, we declare it here.
extern net_packet_t *NET_NewPacket(size_t len);

// Check if two sockaddr_in are equal
static boolean AddressesEqual(struct sockaddr_in *a, struct sockaddr_in *b) {
  return a->sin_addr.s_addr == b->sin_addr.s_addr &&
         a->sin_port == b->sin_port;
}

//
// Helper: Find or create an address entry (reuses existing for same IP:port)
//
static net_addr_t *POSIX_FindAddress(struct sockaddr_in *sin) {
  int i;
  posix_addr_entry_t *entry;

  // Search for existing entry
  for (i = 0; i < addr_table_count; i++) {
    if (addr_table[i] != NULL && AddressesEqual(sin, &addr_table[i]->sin)) {
      return &addr_table[i]->net_addr;
    }
  }

  // Not found, create new entry
  if (addr_table_count >= ADDR_TABLE_SIZE) {
    // Table full - find a slot with refcount 0
    for (i = 0; i < ADDR_TABLE_SIZE; i++) {
      if (addr_table[i] != NULL && addr_table[i]->net_addr.refcount <= 0) {
        free(addr_table[i]);
        addr_table[i] = NULL;
        break;
      }
    }
    if (i >= ADDR_TABLE_SIZE) {
      fprintf(stderr, "POSIX_FindAddress: address table full!\n");
      return NULL;
    }
  } else {
    i = addr_table_count++;
  }

  entry = malloc(sizeof(posix_addr_entry_t));
  if (entry == NULL)
    return NULL;

  entry->sin = *sin;
  entry->net_addr.module = &net_sdl_module;
  entry->net_addr.handle = &entry->sin;
  entry->net_addr.refcount = 0;

  addr_table[i] = entry;

  return &entry->net_addr;
}

//
// Module Interface Implementation
//

static boolean POSIX_Init(void) {
  if (sockfd >= 0)
    return true; // Already initialized

  sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sockfd < 0) {
    fprintf(stderr, "POSIX_Init: Failed to create socket: %s\n",
            strerror(errno));
    return false;
  }

  // Set non-blocking
  int flags = fcntl(sockfd, F_GETFL, 0);
  if (flags != -1) {
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
  }

  return true;
}

static boolean POSIX_InitClient(void) {
  if (!POSIX_Init())
    return false;

  // Already bound (e.g., by server init) - just return success
  if (is_bound)
    return true;

  // Clients bind to any available port
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = 0; // System assigns port

  if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "POSIX_InitClient: Bind failed: %s\n", strerror(errno));
    return false;
  }

  is_bound = true;
  return true;
}

static boolean POSIX_InitServer(void) {
  if (!POSIX_Init())
    return false;

  // Already bound - just return success
  if (is_bound)
    return true;

  // Servers bind to the specific Doom port (default 2342)
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(DOOM_DEFAULT_PORT);

  if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "POSIX_InitServer: Bind failed: %s\n", strerror(errno));
    return false;
  }

  is_bound = true;
  local_port = DOOM_DEFAULT_PORT;
  return true;
}

static void POSIX_SendPacket(net_addr_t *addr, net_packet_t *packet) {
  struct sockaddr_in *sin;
  char ip_str[INET_ADDRSTRLEN];
  ssize_t sent;

  if (sockfd < 0 || addr == NULL || packet == NULL)
    return;

  sin = (struct sockaddr_in *)addr->handle;

  inet_ntop(AF_INET, &(sin->sin_addr), ip_str, sizeof(ip_str));
  fprintf(stderr, "NET_SEND: %zu bytes to %s:%d\n",
          (size_t)packet->len, ip_str, ntohs(sin->sin_port));

  sent = sendto(sockfd, packet->data, packet->len, 0, (struct sockaddr *)sin,
         sizeof(*sin));
  if (sent < 0) {
    fprintf(stderr, "NET_SEND: sendto failed: %s\n", strerror(errno));
  }
}

static boolean POSIX_RecvPacket(net_addr_t **addr, net_packet_t **packet) {
  struct sockaddr_in from;
  socklen_t fromlen = sizeof(from);
  byte buffer[MAX_PACKET_SIZE]; // Ensure MAX_PACKET_SIZE is defined, usually in
                                // doomdef.h or d_net.h If not, use 1450 (safe
                                // MTU)
  int ret;

  if (sockfd < 0)
    return false;

#ifndef MAX_PACKET_SIZE
#define MAX_PACKET_SIZE 1450
#endif

  ret = recvfrom(sockfd, buffer, MAX_PACKET_SIZE, 0, (struct sockaddr *)&from,
                 &fromlen);

  if (ret > 0) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(from.sin_addr), ip_str, sizeof(ip_str));
    fprintf(stderr, "NET_RECV: %d bytes from %s:%d\n",
            ret, ip_str, ntohs(from.sin_port));

    // 1. Find or create the address object (reuses for same IP:port)
    *addr = POSIX_FindAddress(&from);
    if (*addr == NULL)
      return false;

    // 2. Create the packet object
    *packet = NET_NewPacket(ret);
    if (*packet == NULL) {
      return false;
    }

    // 3. Fill packet data
    memcpy((*packet)->data, buffer, ret);
    (*packet)->len = ret;

    return true;
  }

  return false;
}

static void POSIX_AddrToString(net_addr_t *addr, char *buffer, int buffer_len) {
  struct sockaddr_in *sin = (struct sockaddr_in *)addr->handle;
  char ip_str[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &(sin->sin_addr), ip_str, sizeof(ip_str));
  snprintf(buffer, buffer_len, "%s:%d", ip_str, ntohs(sin->sin_port));
}

static void POSIX_FreeAddress(net_addr_t *addr) {
  // With the address table, we don't actually free addresses.
  // They stay in the table for reuse. The table cleanup happens
  // when it fills up and we find entries with refcount <= 0.
  (void)addr;
}

static net_addr_t *POSIX_ResolveAddress(const char *address) {
  struct sockaddr_in sin;
  char *addr_dup;
  char *colon;
  char *ip_part;
  int port = DOOM_DEFAULT_PORT;

  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;

  addr_dup = strdup(address);
  colon = strrchr(addr_dup, ':');

  if (colon) {
    *colon = '\0';
    port = atoi(colon + 1);
    ip_part = addr_dup;
  } else {
    ip_part = addr_dup;
  }

  sin.sin_port = htons(port);

  // Attempt to parse as raw IP address
  if (inet_pton(AF_INET, ip_part, &sin.sin_addr) == 1) {
    // Valid IP - Success!
  } else {
    // Failed to parse IP.
    // We have DISABLED gethostbyname() to avoid static linking
    // warnings/crashes.
    fprintf(stderr, "NET: DNS resolution disabled. Please use IP addresses "
                    "(e.g. 192.168.1.50)\n");
    free(addr_dup);
    return NULL;
  }

  free(addr_dup);
  return POSIX_FindAddress(&sin);
}

//
// Export the module using the name SDL expects
//
net_module_t net_sdl_module = {POSIX_InitClient,    POSIX_InitServer,
                               POSIX_SendPacket,    POSIX_RecvPacket,
                               POSIX_AddrToString,  POSIX_FreeAddress,
                               POSIX_ResolveAddress};
