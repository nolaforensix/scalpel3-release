//
// SPDX-License-Identifier: GPL-3.0-only
//
// Scalpel3 is Copyright (C) 2021-2026 by Golden G. Richard III and contributors.
//
// This file is part of Scalpel3.
//
// Scalpel3 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, version 3 only.
//
// Scalpel3 is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along
// with Scalpel3. If not, see <https://www.gnu.org/licenses/>.
//
// For proprietary or commercial use cases that require integration or
// support, contact Golden G. Richard III (golden@cct.lsu.edu) to discuss
// commercial licensing.
//
// Please see LICENSE.md, README.md, and THIRD_PARTY_NOTICES for details.
//

// scalpel3 IPC client. Used to initiate checkpoints, get progress reports, kill carving jobs, etc.
// for a running scalpel3 instance.
//
// (c) Golden G. Richard III (@nolaforensix), 2023-2026.
//

#define SCALPEL3_EXTERNAL 1
#include "scalpel.h"
#include "colors.h"
#include "prioque.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <uuid/uuid.h>

static void usage(void);

// describe how to use scalpel3-ctl
static void usage(void) {

  fprintf(stderr, "%s", BLUE);
  fprintf(stderr, "scalpel3-ctl interacts with a running scalpel3 instance on the local\n"
                  "machine and provides a \"human in the loop\" interface that supports\n"
                  "initiating checkpointed stop operations, periodic checkpoints, various\n"
                  "status reports, and termination of specific carving jobs, using their\n"
                  "unique IDs.\n\n"

                  "Usage:  scalpel3-ctl [-b] [-c] [-h] [-k UUID] [-kq]\n"
                  "                     [-o scalpel_output_dir] [-p] [-s] [-x]\n\n"

                  "Options:\n\n"

                  "-b   Retrieve and display a copy of the current primary blockmap.\n\n"

                  "-c   Request that scalpel3 create a progress checkpoint, which updates\n"
                  "     the INPROGRESS directories.  UUIDs of reassembly jobs can then be\n"
                  "     scrutinized and used with commands such as -k.  This command is\n"
                  "     available only during fragmented recovery; requests during other\n"
                  "     phases are rejected.\n\n"

                  "-o   Specify output directory of targeted scalpel3 instance.  This is used\n"
                  "     to discriminate between multiple scalpel3 instances, as the IPC endpoint\n"
                  "     is stored in the output directory.\n\n"

                  "-h   Say HELLO to scalpel3 instance.  This command can be used to check\n"
                  "     connectivity.\n\n"

                  "-k   Kill a specific carving job, either active or queued, using one of its UUIDs.\n"
                  "     Use -p or -c to obtain UUIDs of candidates currently being considered.\n"
                  "     This option supports human-in-the-loop decision-making regarding which\n"
                  "     carving operations appear to be fruitful.\n\n"

                  "-kq  List all UUIDs currently in the kill queue.\n\n"

                  "-p   List UUIDs, file types, and current lengths for all carving candidates\n"
                  "     that are either actively being reassembled or queued for reassembly.\n\n"

                  "-s   Display current carving statistics.\n\n"

                  "-x   Request that scalpel3 stop as soon as possible.  If restartable\n"
                  "     checkpoint state exists, scalpel3 writes a checkpoint before exiting;\n"
                  "     otherwise, it exits cleanly without writing checkpoint state.\n");
  fprintf(stderr, "%s", BLACK);
}


int main(int argc, char *argv[]) {

  int sock = -1;
  int exit_status = EXIT_FAILURE;
  struct sockaddr_un server;
  char uuid[PATH_MAX + 1];
  char buf;
  ssize_t read_result;
  int n = 1;
  int numcmds = 0;
  bool response_complete = false;
  bool kill = false;
  bool killq = false;
  bool checkpointexit = false;
  bool progresscheckpoint = false;
  bool progress = false;
  bool status = false;
  bool hello = false;
  bool blockmap = false;
  Queue candidates_queue;
  Queue killque;
  EssentialCarveInfo e;
  uuid_t binuuid;
  uuid_string_t textuuid;
  uuid_string_t clone_textuuid;

  Blockmap *b;

  // default IPC endpoint
  snprintf(server.sun_path, sizeof(server.sun_path), "scalpel-output/.scalpel3IPC");

  // ignore SIGPIPE errors
  signal(SIGPIPE, SIG_IGN);

  while (n < argc && numcmds <= 1) {
    if (! strcmp(argv[n], "-b")) {
      blockmap = true;
      numcmds++;
      n++;
    }
    else if (! strcmp(argv[n], "-c")) {
      progresscheckpoint = true;
      numcmds++;
      n++;
    }
    else if (! strcmp(argv[n], "-h")) {
      hello = true;
      numcmds++;
      n++;
    }
    else if (! strcmp(argv[n], "-k")) {
      n++;
      if (n <= argc - 1) {
        if (strlen(argv[n]) != 36) {
          fprintf(stderr, "%s", RED);
          fprintf(stderr, "UUID for -k option is in the incorrect format.\n");
          fprintf(stderr, "%s", BLACK);
          goto done;
        }
        strncpy(uuid, argv[n], 36);
        uuid[36] = 0;
        if (uuid_parse(uuid, binuuid) < 0 || uuid_is_null(binuuid)) {
          fprintf(stderr, "%s", RED);
          fprintf(stderr, "UUID for -k option is invalid.\n");
          fprintf(stderr, "%s", BLACK);
          goto done;
        }
      }
      else {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Missing UUID for -k option.\n");
        fprintf(stderr, "%s", BLACK);
        goto done;
      }
      kill = true;
      numcmds++;
      n++;
    }
    else if (! strcmp(argv[n], "-kq")) {
      killq = true;
      numcmds++;
      n++;
    }
    else if (! strcmp(argv[n], "-o")) {
      n++;
      if (n <= argc - 1) {
	snprintf(server.sun_path, sizeof(server.sun_path), "%s/.scalpel3IPC", argv[n]);
      }
      else {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Missing directory for -o option.\n");
        fprintf(stderr, "%s", BLACK);
        goto done;
      }
      n++;
    }
    else if (! strcmp(argv[n], "-p")) {
      progress = true;
      numcmds++;
      n++;
    }
    else if (! strcmp(argv[n], "-s")) {
      status = true;
      numcmds++;
      n++;
    }
    else if (! strcmp(argv[n], "-x")) {
      checkpointexit = true;
      numcmds++;
      n++;
    }
    else {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Unrecognized option \"%s\".\n\n", argv[n]);
      fprintf(stderr, "%s", BLACK);
      usage();
      goto done;
    }
  }

  if (numcmds != 1) {
    usage();
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nSpecify exactly one of -b, -c, -h, -k, -kq, -p, -s, or -x in a single invocation.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Socket creation failed. This generally occurs when the filesystem containing\n"
                    "the scalpel3 output directory doesn't support Unix domain sockets.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  server.sun_family = AF_UNIX;

  if (connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr_un)) < 0) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Could not connect with the local scalpel3 instance. The scalpel3 output directory\n"
                    "must be correct for this connection to occur and IPC must be ON in the associated\n"
                    "scalpel3 instance.  The default is \"scalpel-output\" in the current working\n"
                    "directory. If this isn't correct, use the -o option to specify the correct scalpel3\n"
                    "output directory and try again.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (kill) {
    fprintf(stdout, "Sending kill request.\n");
    if (write(sock, KILL_CMD, KILL_CMD_LEN) != KILL_CMD_LEN) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error writing data to scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }

    if (write(sock, uuid, 37) != 37) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error writing data to scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }
    fprintf(stdout, "Please follow progress in the main scalpel3 window.\n");
  }
  else if (checkpointexit) {
    fprintf(stdout, "Sending request for checkpoint and exit.\n");
    if (write(sock, CHECKPOINTEXIT_CMD, CHECKPOINTEXIT_CMD_LEN) != CHECKPOINTEXIT_CMD_LEN) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error writing data to scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }
  }
  else if (progresscheckpoint) {
    fprintf(stdout, "Sending request for progress checkpoint.\n");
    if (write(sock, PROGRESSCHECKPOINT_CMD, PROGRESSCHECKPOINT_CMD_LEN) != PROGRESSCHECKPOINT_CMD_LEN) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error writing data to scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }
    fprintf(stdout, "Please wait...\n");
  }
  else if (status) {
    fprintf(stdout, "Sending status request.\n");
    if (write(sock, STATUS_CMD, STATUS_CMD_LEN) != STATUS_CMD_LEN) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error writing data to scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }
  }
  else if (progress) {
    fprintf(stdout, "Sending request for reassembly progress.\n");
    fprintf(stdout, "\nReassembly candidates:\n\n"
                    "File Type\t # Blocks\t UUID\t\t\t\t\t Clone UUID\t\t\t        Priority\t\t\tStatus\n"
                    "---------\t --------\t ----\t\t\t\t\t ----------\t\t\t        --------\t\t\t------\n");

    if (write(sock, PROMISINGQUEUE_CMD, PROMISINGQUEUE_CMD_LEN) != PROMISINGQUEUE_CMD_LEN) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error writing data to scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }

    // get response
    if (! read_essential_carveinfo_queue_h(&candidates_queue, sock, true)) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error retrieving queued candidates from scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }

    if (write(sock, REASSEMBLYQUEUE_CMD, REASSEMBLYQUEUE_CMD_LEN) != REASSEMBLYQUEUE_CMD_LEN) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error writing data to scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }

    // get response
    if (! read_essential_carveinfo_queue_h(&candidates_queue, sock, false)) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error retrieving active candidates from scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }

    if (! queue_length(&candidates_queue)) {
      fprintf(stdout, "NONE.\n");
    }
    else {
      // walk queue to display report
      rewind_queue(&candidates_queue);
      while (! end_of_queue(&candidates_queue)) {
        remove_from_front(&candidates_queue, &e);
        uuid_unparse_lower(e.binuuid, textuuid);
        uuid_unparse_lower(e.clone_binuuid, clone_textuuid);
        fprintf(stdout,
                "%-9s"
                "%9" PRIu64 "\t\t"
                "%37s\t"
                "%37s\t"
                "%9" PRId64 "\t"
                "%s\n",
                e.filetype, e.numblocks, textuuid, clone_textuuid, e.qposition, e.active ? "ACTIVE" : "QUEUED");
      }
      destroy_queue(&candidates_queue);
    }
    exit_status = EXIT_SUCCESS;
    goto done;
  }
  else if (killq) {
    init_queue(&killque, sizeof(uuid_t), false, compare_uuids, false);

    fprintf(stdout, "Sending request for kill queue contents report.\n");
    if (write(sock, KILLQUEUE_CMD, KILLQUEUE_CMD_LEN) != KILLQUEUE_CMD_LEN) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error writing data to scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }

    if (! deserialize_queue_h(&killque, kill_queue_element_serialization, false, sock)) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error reading kill queue data from scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }

    fprintf(stdout, "\nUUIDS in kill queue:\n"
                    "--------------------\n");

    if (! queue_length(&killque)) {
      fprintf(stdout, "NONE.\n");
    }
    else {
      rewind_queue(&killque);
      while (! end_of_queue(&killque)) {
        remove_from_front(&killque, binuuid);
        uuid_unparse_lower(binuuid, textuuid);
        fprintf(stdout, "%s\n", textuuid);
      }
    }
    exit_status = EXIT_SUCCESS;
    goto done;
  }
  else if (hello) {
    fprintf(stdout, "Sending greetings to the local scalpel3 instance.\n");
    if (write(sock, HELLO_CMD, HELLO_CMD_LEN) != HELLO_CMD_LEN) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error writing data to scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }
  }
  else if (blockmap) {
    fprintf(stdout, "Sending request for blockmap.\n");
    if (write(sock, BLOCKMAP_CMD, BLOCKMAP_CMD_LEN) != BLOCKMAP_CMD_LEN) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Error writing data to scalpel3 instance, aborting.\n");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }

    if (! read_blockmap_h(&b, sock)) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Failed to read a blockmap from the scalpel3 instance. This can happen if\n");
      fprintf(stderr, "a blockmap is requested before scalpel3 has finished initializing.  Aborting.");
      fprintf(stderr, "%s", BLACK);
      goto done;
    }

    display_blockmap(b);
    free_blockmap(&b);
    exit_status = EXIT_SUCCESS;
    goto done;
  }
  // get the complete NUL-terminated response from scalpel3 for textual commands
  while (! response_complete) {
    read_result = read(sock, &buf, 1);
    if (read_result > 0) {
      if (! buf) {
        response_complete = true;
      }
      else {
        putchar(buf);
      }
    }
    else if (read_result < 0 && errno == EINTR) {
      continue;
    }
    else {
      break;
    }
  }

  if (! response_complete) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "The scalpel3 instance closed the IPC connection before completing the request.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  putchar('\n');
  exit_status = EXIT_SUCCESS;

done:
  if (sock >= 0) {
    close(sock);
  }
  return exit_status;
}

