//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G. Richard III and contributors.
//
// This program is free software : you can redistribute it and / or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program. If
// not, see <https://www.gnu.org/licenses/>.
//
//-----------------------------
// Additional Integration Terms
// ----------------------------
//
// Linking or embedding Scalpel3 (statically or dynamically) into another program such that the
// resulting executable or library forms a single combined work constitutes creation of a derivative
// work under the GPL. Any party distributing such a combined work must make the entire source code
// available under the terms of the GPL as well.
//
// Commercial entities wishing to use Scalpel3 in a closed-source or proprietary product or
// requiring support must obtain a separate commercial license.
//
// For commercial licensing or questions about integration, contact: Golden G. Richard III
// (golden@cct.lsu.edu).
//
// Please see LICENSE.md and README.md for further information.
//
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
