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
} posix_addr_handle_t;

static int sockfd = -1;
static uint16_t local_port = 0;

// Forward declaration of the module
net_module_t net_sdl_module;

// We need to access packet creation, usually in net_packet.c
// If headers don't expose it, we declare it here.
extern net_packet_t *NET_NewPacket(size_t len);

//
// Helper: Create a new address with our handle type
//
static net_addr_t *POSIX_NewAddress(struct sockaddr_in *sin) {
  net_addr_t *addr;
  posix_addr_handle_t *handle;

  addr = malloc(sizeof(net_addr_t));
  if (addr == NULL)
    return NULL;

  handle = malloc(sizeof(posix_addr_handle_t));
  if (handle == NULL) {
    free(addr);
    return NULL;
  }

  handle->sin = *sin;

  addr->module = &net_sdl_module;
  addr->handle = handle;
  addr->refcount = 1;

  return addr;
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

  return true;
}

static boolean POSIX_InitServer(void) {
  if (!POSIX_Init())
    return false;

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

  local_port = DOOM_DEFAULT_PORT;
  return true;
}

static void POSIX_SendPacket(net_addr_t *addr, net_packet_t *packet) {
  posix_addr_handle_t *handle;

  if (sockfd < 0 || addr == NULL || packet == NULL)
    return;

  handle = (posix_addr_handle_t *)addr->handle;

  sendto(sockfd, packet->data, packet->len, 0, (struct sockaddr *)&handle->sin,
         sizeof(handle->sin));
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
    // 1. Create the address object
    *addr = POSIX_NewAddress(&from);
    if (*addr == NULL)
      return false;

    // 2. Create the packet object
    *packet = NET_NewPacket(ret);
    if (*packet == NULL) {
      // Free the address we just made
      // We can't call POSIX_FreeAddress directly easily without casting
      // But we know the internals:
      free((*addr)->handle);
      free(*addr);
      return false;
    }

    // 3. Fill packet data
    memcpy((*packet)->data, buffer, ret);

    return true;
  }

  return false;
}

static void POSIX_AddrToString(net_addr_t *addr, char *buffer, int buffer_len) {
  posix_addr_handle_t *handle = (posix_addr_handle_t *)addr->handle;
  char ip_str[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &(handle->sin.sin_addr), ip_str, sizeof(ip_str));
  snprintf(buffer, buffer_len, "%s:%d", ip_str, ntohs(handle->sin.sin_port));
}

static void POSIX_FreeAddress(net_addr_t *addr) {
  if (addr->handle) {
    free(addr->handle);
    addr->handle = NULL;
  }
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
  return POSIX_NewAddress(&sin);
}

//
// Export the module using the name SDL expects
//
net_module_t net_sdl_module = {POSIX_InitClient,    POSIX_InitServer,
                               POSIX_SendPacket,    POSIX_RecvPacket,
                               POSIX_AddrToString,  POSIX_FreeAddress,
                               POSIX_ResolveAddress};
