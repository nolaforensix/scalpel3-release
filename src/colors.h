//
// SPDX-License-Identifier: GPL-3.0-only
//
// The Scalpel Project is Copyright (C) 2005-2026 by Golden G. Richard III
// and contributors.
//
// Scalpel3 is Copyright (C) 2021-2026 by Golden G. Richard III and the
// contributors listed in AUTHORS.
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

#if ! defined(__SCALPEL_COLOR_H__)
#define __SCALPEL_COLOR_H__

// set to 1 to disable color
#define DISABLE_COLOR 0

// color codes for output
extern char *BLACK;
extern char *BOLD;
extern char *RED;
extern char *GREEN;
extern char *YELLOW;
extern char *BLUE;
extern char *MAGENTA;
extern char *CYAN;
extern char *WHITE;
extern char *GRAY;
extern char *BRED;
extern char *BGREEN;
extern char *BYELLOW;
extern char *BBLUE;
extern char *BMAGENTA;
extern char *BCYAN;
extern char *BWHITE;
extern char *BLINK;
extern char *LOGOP;
extern char *LOGOR;

#define DISABLE_ALL_COLOR {			\
    BLACK     = "";				\
    BOLD      = "";				\
    RED       = "";				\
    GREEN     = "";				\
    YELLOW    = "";				\
    BLUE      = "";				\
    MAGENTA   = "";				\
    CYAN      = "";				\
    WHITE     = "";				\
    GRAY      = "";				\
    BRED      = "";				\
    BGREEN    = "";				\
    BYELLOW   = "";				\
    BBLUE     = "";				\
    BMAGENTA  = "";				\
    BCYAN     = "";				\
    BWHITE    = "";				\
    BLINK     = "";				\
    LOGOP     = "";				\
    LOGOR     = "";				\
  }
#endif
