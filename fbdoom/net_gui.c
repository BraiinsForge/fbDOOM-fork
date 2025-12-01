#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "doomkeys.h"

#include "i_system.h"
#include "i_timer.h"
#include "i_video.h"
#include "m_argv.h"
#include "m_misc.h"

#include "net_client.h"
#include "net_gui.h"
#include "net_query.h"
#include "net_server.h"

// Removed: #include "textscreen.h"

static int expected_nodes;
static int last_printed_players = -1;
static boolean had_warning = false;

//
// Check command line for -nodes <n>
//
static void ParseCommandLineArgs(void) {
  int i;
  i = M_CheckParmWithArgs("-nodes", 1);
  if (i > 0) {
    expected_nodes = atoi(myargv[i + 1]);
  }
}

//
// Attempt to start the game automatically
//
static void CheckAutoLaunch(void) {
  int nodes;

  if (net_client_received_wait_data && net_client_wait_data.is_controller &&
      expected_nodes > 0) {
    nodes = net_client_wait_data.num_players + net_client_wait_data.num_drones;

    if (nodes >= expected_nodes) {
      printf("Target node count reached. Starting game...\n");
      NET_CL_LaunchGame();
      expected_nodes = 0;
    }
  }
}

//
// Print player list to stdout only if it has changed
//
static void UpdateConsoleOutput(void) {
  unsigned int i;

  if (!net_client_received_wait_data)
    return;

  // Only print if the number of players has changed to avoid spamming stdout
  if (net_client_wait_data.num_players == last_printed_players)
    return;

  last_printed_players = net_client_wait_data.num_players;

  printf("\n--- LOBBY UPDATE ---\n");
  printf("Players: %d / %d\n", net_client_wait_data.num_players,
         net_client_wait_data.max_players);

  for (i = 0; i < net_client_wait_data.num_players; ++i) {
    printf(" %d. %s [%s]", i + 1, net_client_wait_data.player_names[i],
           net_client_wait_data.player_addrs[i]);

    if ((signed)i == net_client_wait_data.consoleplayer) {
      printf(" (YOU)");
    }
    printf("\n");
  }

  if (net_client_wait_data.num_drones > 0) {
    printf(" + %d observers\n", net_client_wait_data.num_drones);
  }

  if (net_client_wait_data.is_controller && expected_nodes == 0) {
    printf("WARNING: You are the host, but you did not specify -nodes <n>.\n");
    printf("The game will not start automatically.\n");
  }

  printf("--------------------\n");
}

static void PrintSHA1Digest(const char *s, const byte *digest) {
  unsigned int i;
  printf("%s: ", s);
  for (i = 0; i < sizeof(sha1_digest_t); ++i)
    printf("%02x", digest[i]);
  printf("\n");
}

static void CheckSHA1Sums(void) {
  boolean correct_wad, correct_deh;
  boolean same_freedoom;

  if (!net_client_received_wait_data || had_warning)
    return;

  correct_wad = memcmp(net_local_wad_sha1sum, net_client_wait_data.wad_sha1sum,
                       sizeof(sha1_digest_t)) == 0;
  correct_deh = memcmp(net_local_deh_sha1sum, net_client_wait_data.deh_sha1sum,
                       sizeof(sha1_digest_t)) == 0;
  same_freedoom = net_client_wait_data.is_freedoom == net_local_is_freedoom;

  if (correct_wad && correct_deh && same_freedoom)
    return;

  printf("\n!!! CRITICAL WARNING !!!\n");

  if (!correct_wad) {
    printf("Your WAD file does not match the server!\n");
    PrintSHA1Digest("Local ", net_local_wad_sha1sum);
    PrintSHA1Digest("Server", net_client_wait_data.wad_sha1sum);
  }
  if (!correct_deh) {
    printf("Your Dehacked patch does not match the server!\n");
  }
  if (!same_freedoom) {
    printf("Freedoom/Doom mismatch detected.\n");
  }

  printf("Game may desync or crash.\n\n");
  had_warning = true;
}

static void CheckMasterStatus(void) {
  boolean added;
  static boolean checked = false;

  if (checked)
    return;

  if (NET_Query_CheckAddedToMaster(&added)) {
    if (added)
      printf("Master Server: Registered successfully.\n");
    else
      printf("Master Server: Registration failed (Check ports).\n");

    checked = true;
  }
}

//
// Main Loop
//
void NET_WaitForLaunch(void) {
  printf("NetGUI: Initializing console mode...\n");

  ParseCommandLineArgs();
  had_warning = false;

  printf("NetGUI: Waiting for players...\n");

  while (net_waiting_for_launch) {
    // Run network slices
    NET_CL_Run();
    NET_SV_Run();

    // Console Logic
    UpdateConsoleOutput();
    CheckAutoLaunch();
    CheckSHA1Sums();
    CheckMasterStatus();

    // Check for disconnect
    if (!net_client_connected) {
      I_Error("Lost connection to server");
    }

    // Sleep to save CPU (100ms)
    I_Sleep(100);
  }

  printf("NetGUI: Launching game!\n");
}
