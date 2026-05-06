//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G.Richard III and contributors.
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
// ----------------------------
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
// diskviz -- visualize synthetic disk image layouts from fragmentator .key files
//
// Written by Golden G. Richard III (@nolaforensix), 2026.
//

#include <signal.h>
#include <termios.h>

#define SCALPEL3_EXTERNAL
#include "colors.h"
#include "hashv4.h"
#include "scalpel.h"
#include "scalpelv.h"
#include <SDL.h>
#include <SDL_image.h>
#include <SDL_ttf.h>

#define DISKVIZ_BANNER_STRING                                                                                                      \
  "diskviz v%s -- "                                                                                                                \
  "Written by Golden G. Richard III (@nolaforensix).",                                                                             \
      SCALPEL_VERSION

#define MAX_LINE 4096
#define MAX_PATH_LEN 512
#define INITIAL_FILES 32
#define INITIAL_WIN_W 1200
#define INITIAL_WIN_H 900
#define MIN_CELL_SIZE 4
#define TOOLTIP_PAD 6
#define TOOLTIP_FONT_SIZE 14
#define LABEL_FONT_SIZE 11
#define MEDIUM_FONT_SIZE 22
#define TITLE_FONT_SIZE 40

typedef enum { BTYPE_FILE, BTYPE_HEADER, BTYPE_ZERO, BTYPE_RANDOM } BlockType;

typedef enum {
  FTYPE_PNG,
  FTYPE_JPG,
  FTYPE_GIF,
  FTYPE_ZIP,
  FTYPE_ELF,
  FTYPE_RAR,
  FTYPE_MP3,
  FTYPE_PDF,
  FTYPE_ABC,
  FTYPE_UNKNOWN,
  FTYPE_COUNT
} FileType;

typedef struct {
  BlockType type;
  int file_id;                 // index into files[], -1 for ZERO/RANDOM
  int file_block;              // block within the file, -1 for ZERO/RANDOM
  int disk_block;
} DiskBlock;

typedef struct {
  char path[MAX_PATH_LEN];
  FileType ftype;
  int total_blocks;            // total blocks (FILE+HEADER) of this file
  int type_ordinal;            // 1-based ordinal within its type
  SDL_Texture *texture;        // decoded image texture (visual types only)
  int img_w, img_h;            // decoded image dimensions
  int tile_cols, tile_rows;    // 2D tile grid for image slicing
  int tile_w, tile_h;          // pixel size of each tile in the source image
} FileInfo;

typedef struct {
  int blocksize;
  int total_blocks;
  DiskBlock *blocks;
  int num_files;
  int max_files;
  FileInfo *files;
  oa_hash *file_hash;          // hash table for file path -> index

  int grid_cols, grid_rows;
  int cell_w, cell_h;
  int grid_x, grid_y;          // offset to center the grid
  int scroll_y;                // scroll offset in pixels
  int max_scroll_y;

  SDL_Window *window;
  SDL_Renderer *renderer;
  TTF_Font *font_tooltip;
  TTF_Font *font_label;
  TTF_Font *font_medium;       // medium font for panel labels (~22pt)
  TTF_Font *font_title;        // larger font for frame titles (~40pt)
  SDL_Texture *noise_tex;
  SDL_Texture *prev_frame_tex; // texture for crossfade transition

  int hover_block;
  bool dirty;
  int view_mode;               // 0-7: current demo frame
  int prev_view_mode;          // frame we are transitioning from
  float transition_alpha;      // 0.0-1.0: blend factor for crossfade
  Uint32 transition_start;     // SDL_GetTicks() when transition began
  float zoom;                  // zoom factor (1.0 = default, >1 = zoomed in)
  char basedir[MAX_PATH_LEN];  // base directory for resolving file paths
} AppState;

// -------------------------------------------------------------------
// color table for non-visual types
// -------------------------------------------------------------------

static const SDL_Color type_colors[FTYPE_COUNT] = {
    [FTYPE_PNG] = {120, 200, 120, 255},      // green-ish (won't normally use)
    [FTYPE_JPG] = {200, 180, 100, 255},      // (won't normally use)
    [FTYPE_GIF] = {100, 180, 200, 255},      // (won't normally use)
    [FTYPE_ZIP] = {70, 130, 180, 255},       // steel blue
    [FTYPE_ELF] = {255, 140, 0, 255},        // dark orange
    [FTYPE_RAR] = {147, 112, 219, 255},      // medium purple
    [FTYPE_MP3] = {46, 139, 87, 255},        // sea green
    [FTYPE_PDF] = {220, 20, 60, 255},        // crimson
    [FTYPE_ABC] = {218, 165, 32, 255},       // goldenrod
    [FTYPE_UNKNOWN] = {112, 128, 144, 255},  // slate gray
};

// short labels for non-visual types
static const char *type_labels[] = {
    [FTYPE_PNG] = "PNG", [FTYPE_JPG] = "JPG", [FTYPE_GIF] = "GIF", [FTYPE_ZIP] = "ZIP", [FTYPE_ELF] = "ELF",
    [FTYPE_RAR] = "RAR", [FTYPE_MP3] = "MP3", [FTYPE_PDF] = "PDF", [FTYPE_ABC] = "ABC", [FTYPE_UNKNOWN] = "???",
};

// frame titles for the 8 demo modes
static const char *frame_titles[8] = {
    "Files in a Filesystem",
    "How the Filesystem Tracks Blocks",
    "Filesystem Wiped \xe2\x80\x94 Data Remains",
    "Headers & Footers Reveal File Boundaries",
    "Files in a Filesystem (Fragmented Disk)",
    "The Filesystem Tracks Scattered Blocks",
    "Filesystem Wiped \xe2\x80\x94 Fragmented Chaos",
    "Headers & Footers",
};

// function prototypes for private diskviz functions
static void restore_terminal(void);
static void sigint_handler(int sig);
static void enable_raw_mode(void);
static int read_terminal_key(void);
static void diskviz_logo(void);
static void usage(void);
static bool is_visual_type(FileType ft);
static FileType classify_filetype(const char *path);
static char *trim(char *s);
static void *oa_int_cp(const void *p);
static void oa_int_free(void **p);
static size_t oa_int_sizeof(const void *p);
static void init_file_hash(AppState *st);
static int find_or_add_file(AppState *st, const char *path);
static bool parse_keyfile(const char *path, AppState *st);
static void load_visual_files(AppState *st);
static void create_noise_texture(AppState *st);
static void calc_grid(AppState *st);
static void render_tooltip(AppState *st, int mx, int my);
static void render_block(AppState *st, int idx, SDL_Rect *dst);
static void render_title(AppState *st);
static void render_frame_indicator(AppState *st);
static void render_cards(AppState *st, bool show_overlay, bool fragmented);
static void render_linear(AppState *st, bool highlight_hf);
static void render_jigsaw(AppState *st, bool highlight_hf);
static void render_fs_grid(AppState *st);
static void render_view(AppState *st);
static void begin_transition(AppState *st, int new_mode);

// -------------------------------------------------------------------
// terminal raw mode for stdin key capture
// -------------------------------------------------------------------

static struct termios orig_termios;
static bool raw_mode_active = false;

static void restore_terminal(void) {
  if (raw_mode_active) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
    raw_mode_active = false;
  }
}


static void sigint_handler(int sig) {
  restore_terminal();
  _exit(128 + sig);
}


static void enable_raw_mode(void) {
  if (! isatty(STDIN_FILENO)) {
    return;
  }

  tcgetattr(STDIN_FILENO, &orig_termios);
  atexit(restore_terminal);
  signal(SIGINT, sigint_handler);
  signal(SIGTERM, sigint_handler);

  struct termios raw = orig_termios;
  raw.c_lflag &= ~(ICANON | ECHO);  // disable line buffering and echo
  raw.c_cc[VMIN] = 0;               // non-blocking
  raw.c_cc[VTIME] = 0;
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);

  // also set stdin to non-blocking
  int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
  fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);

  raw_mode_active = true;
}


// read a key from stdin (non-blocking). Returns 0 if nothing available. Handles ESC sequences for
// arrow keys.
static int read_terminal_key(void) {
  unsigned char c;
  if (read(STDIN_FILENO, &c, 1) != 1) {
    return 0;
  }

  if (c == 27) {  // ESC or start of escape sequence
    unsigned char seq[2];
    // try to read the rest of an escape sequence
    if (read(STDIN_FILENO, &seq[0], 1) != 1) {
      return 27;  // bare ESC
    }
    if (read(STDIN_FILENO, &seq[1], 1) != 1) {
      return 27;
    }
    if (seq[0] == '[') {
      if (seq[1] == 'D') {
        return SDLK_LEFT;
      }
      if (seq[1] == 'C') {
        return SDLK_RIGHT;
      }
    }
    return 27;    // unknown escape sequence, treat as ESC
  }
  return c;
}


static void diskviz_logo(void) {
  char *logo[] = {"\n",
                  "\n",
                  " ....................................................\n",
                  ".   _____ _____  _____ _  ____      _______ ______   .\n",
                  ".  |  __ \\_   _|/ ____| |/ /\\ \\    / /_   _|___  /   .\n",
                  ".  | |  | || | | (___ | ' /  \\ \\  / /  | |    / /    .\n",
                  ".  | |  | || |  \\___ \\|  <    \\ \\/ /   | |   / /     .\n",
                  ".  | |__| || |_ ____) | . \\    \\  /   _| |_ / /__    .\n",
                  ".  |_____/_____|_____/|_|\\_\\    \\/   |_____/_____|   .\n",
                  " ....................................................\n",
                  ""};

  int i = 0;
  size_t j;
  size_t len;

  if (get_terminal_width() < 58) {
    return;
  }

  while (logo[i][0]) {
    len = strlen(logo[i]);
    for (j = 0; j < len; j++) {
      if (isspace(logo[i][j]) || i < 3 || i > 8 || j < 2 || j > 52) {
        fprintf(stdout, "%s", BLACK);
      }
      else {
        fprintf(stdout, "%s%s", BOLD, LOGOP);
      }
      fputc(logo[i][j], stdout);
      fprintf(stdout, "%s", BLACK);
    }
    i++;
  }
  fputc('\n', stdout);
}


static void usage(void) {
  fprintf(stderr, "%s", BLUE);
  fprintf(stderr, "diskviz visualizes synthetic disk image layouts from fragmentator .key files.\n"
                  "Image files (PNG, JPG, GIF) are rendered as tiled image blocks. Non-visual file\n"
                  "types (ZIP, ELF, etc.) are shown as colored labeled blocks. RANDOM and ZERO fill\n"
                  "blocks are rendered distinctly.\n\n"
                  "Usage: diskviz keyfile [-d basedir]\n\n"
                  "Options:\n"
                  "-d basedir  Base directory for resolving file paths in the key file.\n\n");
  fprintf(stderr, "%s", BLACK);
}


static bool is_visual_type(FileType ft) {
  return ft == FTYPE_PNG || ft == FTYPE_JPG || ft == FTYPE_GIF;
}


static FileType classify_filetype(const char *path) {
  const char *dot = strrchr(path, '.');
  if (! dot) {
    return FTYPE_UNKNOWN;
  }
  dot++;
  if (! strcasecmp(dot, "png")) {
    return FTYPE_PNG;
  }
  if (! strcasecmp(dot, "jpg")) {
    return FTYPE_JPG;
  }
  if (! strcasecmp(dot, "jpeg")) {
    return FTYPE_JPG;
  }
  if (! strcasecmp(dot, "gif")) {
    return FTYPE_GIF;
  }
  if (! strcasecmp(dot, "zip")) {
    return FTYPE_ZIP;
  }
  if (! strcasecmp(dot, "elf")) {
    return FTYPE_ELF;
  }
  if (! strcasecmp(dot, "rar")) {
    return FTYPE_RAR;
  }
  if (! strcasecmp(dot, "mp3")) {
    return FTYPE_MP3;
  }
  if (! strcasecmp(dot, "pdf")) {
    return FTYPE_PDF;
  }
  if (! strcasecmp(dot, "abc")) {
    return FTYPE_ABC;
  }
  return FTYPE_UNKNOWN;
}


static char *trim(char *s) {
  while (*s && isspace((unsigned char)*s)) {
    s++;
  }
  char *end = s + strlen(s) - 1;
  while (end > s && isspace((unsigned char)*end)) {
    *end-- = '\0';
  }
  return s;
}

static void *oa_int_cp(const void *p) {
  int *copy = malloc(sizeof(int));
  check_memory_allocation(copy, __LINE__, __FILE__, "oa_int_cp");
  *copy = *(const int *)p;
  return copy;
}


static void oa_int_free(void **p) {
  free(*p);
  *p = NULL;
}


static size_t oa_int_sizeof(const void *p) {
  (void)p;
  return sizeof(int);
}


// initialize the file path hash table
static void init_file_hash(AppState *st) {
  oa_key_ops key_ops = {.hash = oa_string_hash,
                        .cp = oa_string_cp,
                        .free = oa_string_free,
                        .eq = oa_string_eq,
                        .serialize = NULL,
                        .size_of = oa_string_sizeof};
  oa_val_ops val_ops = {.cp = oa_int_cp, .free = oa_int_free, .serialize = NULL, .size_of = oa_int_sizeof};
  st->file_hash = oa_hash_new(key_ops, val_ops);
}


// find or add a file, return its index. Uses hash table for O(1) lookup instead of linear scan.
static int find_or_add_file(AppState *st, const char *path) {
  int *existing = (int *)oa_hash_get(st->file_hash, path);
  if (existing) {
    return *existing;
  }

  if (st->num_files >= st->max_files) {
    st->max_files *= 2;
    st->files = realloc(st->files, st->max_files * sizeof(FileInfo));
    if (! st->files) {
      fprintf(stderr, "%sERROR: Memory allocation failure.%s\n", RED, BLACK);
      exit(1);
    }
  }
  int idx = st->num_files++;
  FileInfo *f = &st->files[idx];
  strncpy(f->path, path, MAX_PATH_LEN - 1);
  f->ftype = classify_filetype(path);
  f->total_blocks = 0;
  f->texture = NULL;
  f->img_w = f->img_h = 0;

  // compute type_ordinal: count how many files of same type already exist
  int count = 0;
  for (int i = 0; i < idx; i++) {
    if (st->files[i].ftype == f->ftype) {
      count++;
    }
  }
  f->type_ordinal = count + 1;

  // insert into hash table
  oa_hash_put(st->file_hash, path, &idx);

  return idx;
}


static bool parse_keyfile(const char *path, AppState *st) {
  FILE *fp = fopen(path, "r");
  if (! fp) {
    fprintf(stderr, "%sERROR: Can't open key file: %s%s\n", RED, path, BLACK);
    return false;
  }

  // get file size for progress indicator
  fseek(fp, 0, SEEK_END);
  long file_size = ftell(fp);
  fseek(fp, 0, SEEK_SET);

  fprintf(stdout, "Parsing key file...    ");
  fflush(stdout);
  int last_perc = -1;
  long bytes_read = 0;

  char line[MAX_LINE];
  bool past_header = false;
  int max_disk_block = -1;

  // first pass: count blocks to allocate also parse header config
  int capacity = 4096;
  DiskBlock *tmp = malloc(capacity * sizeof(DiskBlock));
  int count = 0;

  while (fgets(line, sizeof(line), fp)) {
    // update progress
    bytes_read += strlen(line);
    if (file_size > 0) {
      int perc = (int)(bytes_read * 100 / file_size);
      if (perc > 100) {
        perc = 100;
      }
      if (perc != last_perc) {
        fprintf(stdout, "\b\b\b\b%3d%%", perc);
        fflush(stdout);
        last_perc = perc;
      }
    }
    // parse header values
    if (! past_header) {
      if (sscanf(line, "BLOCKSIZE: %d", &st->blocksize) == 1) {
        continue;
      }
      if (strstr(line, "------------")) {
        past_header = true;
        continue;
      }
      continue;
    }

    // find the bracket-delimited block entry
    char *bracket = strchr(line, '[');
    if (! bracket) {
      continue;
    }

    // parse: [ TYPE | PATH | FILEBLOCK ] DISKBLOCK
    char *pipe1 = strchr(bracket + 1, '|');
    if (! pipe1) {
      continue;
    }
    char *pipe2 = strchr(pipe1 + 1, '|');
    if (! pipe2) {
      continue;
    }
    char *close = strchr(pipe2 + 1, ']');
    if (! close) {
      continue;
    }

    // extract type
    char type_str[32];
    int len = (int)(pipe1 - bracket - 1);
    if (len >= (int)sizeof(type_str)) {
      len = sizeof(type_str) - 1;
    }
    strncpy(type_str, bracket + 1, len);
    type_str[len] = '\0';
    char *ts = trim(type_str);

    // extract path
    char path_str[MAX_PATH_LEN];
    len = (int)(pipe2 - pipe1 - 1);
    if (len >= (int)sizeof(path_str)) {
      len = sizeof(path_str) - 1;
    }
    strncpy(path_str, pipe1 + 1, len);
    path_str[len] = '\0';
    char *ps = trim(path_str);

    // extract file block number
    char fb_str[32];
    len = (int)(close - pipe2 - 1);
    if (len >= (int)sizeof(fb_str)) {
      len = sizeof(fb_str) - 1;
    }
    strncpy(fb_str, pipe2 + 1, len);
    fb_str[len] = '\0';
    int file_block = atoi(trim(fb_str));

    // extract disk block number (after the ] )
    int disk_block = atoi(close + 1);

    // determine block type
    BlockType btype;
    if (! strcmp(ts, "FILE")) {
      btype = BTYPE_FILE;
    }
    else if (! strcmp(ts, "HEADER")) {
      btype = BTYPE_HEADER;
    }
    else if (! strcmp(ts, "ZERO")) {
      btype = BTYPE_ZERO;
    }
    else if (! strcmp(ts, "RANDOM")) {
      btype = BTYPE_RANDOM;
    }
    else {
      continue;
    }

    // find or add file
    int file_id = -1;
    if (btype == BTYPE_FILE || btype == BTYPE_HEADER) {
      file_id = find_or_add_file(st, ps);
      st->files[file_id].total_blocks++;
    }

    // grow array if needed
    if (count >= capacity) {
      capacity *= 2;
      tmp = realloc(tmp, capacity * sizeof(DiskBlock));
    }

    tmp[count].type = btype;
    tmp[count].file_id = file_id;
    tmp[count].file_block = (btype == BTYPE_ZERO || btype == BTYPE_RANDOM) ? -1 : file_block;
    tmp[count].disk_block = disk_block;

    if (disk_block > max_disk_block) {
      max_disk_block = disk_block;
    }
    count++;
  }
  fclose(fp);
  fprintf(stdout, "\b\b\b\b%3d%%\n", 100);
  fflush(stdout);

  if (count == 0) {
    fprintf(stderr, "%sERROR: No blocks found in key file.%s\n", RED, BLACK);
    free(tmp);
    return false;
  }

  // allocate final block array indexed by disk block
  st->total_blocks = max_disk_block + 1;
  st->blocks = calloc(st->total_blocks, sizeof(DiskBlock));

  // initialize all as ZERO by default
  for (int i = 0; i < st->total_blocks; i++) {
    st->blocks[i].type = BTYPE_ZERO;
    st->blocks[i].file_id = -1;
    st->blocks[i].file_block = -1;
    st->blocks[i].disk_block = i;
  }

  // fill in parsed blocks
  for (int i = 0; i < count; i++) {
    int db = tmp[i].disk_block;
    if (db >= 0 && db < st->total_blocks) {
      st->blocks[db] = tmp[i];
    }
  }

  free(tmp);

  // count zero and random blocks
  int zero_count = 0, random_count = 0;
  for (int i = 0; i < st->total_blocks; i++) {
    if (st->blocks[i].type == BTYPE_ZERO) {
      zero_count++;
    }
    else if (st->blocks[i].type == BTYPE_RANDOM) {
      random_count++;
    }
  }

  printf("Parsed %d disk blocks, %d unique files, %d zero blocks, %d random blocks, blocksize=%d.\n", st->total_blocks,
         st->num_files, zero_count, random_count, st->blocksize);
  return true;
}

static void load_visual_files(AppState *st) {
  // count visual files for progress indicator
  int visual_count = 0;
  for (int i = 0; i < st->num_files; i++) {
    if (is_visual_type(st->files[i].ftype)) {
      visual_count++;
    }
  }
  if (visual_count > 0) {
    fprintf(stdout, "Loading %d image files...    ", visual_count);
    fflush(stdout);
  }
  int loaded = 0, last_perc = -1;

  for (int i = 0; i < st->num_files; i++) {
    FileInfo *f = &st->files[i];
    if (! is_visual_type(f->ftype)) {
      continue;
    }

    char fullpath[MAX_PATH_LEN * 2];
    if (st->basedir[0]) {
      snprintf(fullpath, sizeof(fullpath), "%s/%s", st->basedir, f->path);
    }
    else {
      strncpy(fullpath, f->path, sizeof(fullpath) - 1);
    }

    SDL_Surface *surf = IMG_Load(fullpath);
    if (! surf) {
      fprintf(stderr, "%sERROR: Can't load image '%s': %s%s\n", RED, fullpath, IMG_GetError(), BLACK);
      continue;
    }

    f->img_w = surf->w;
    f->img_h = surf->h;
    f->texture = SDL_CreateTextureFromSurface(st->renderer, surf);
    SDL_FreeSurface(surf);

    if (! f->texture) {
      fprintf(stderr, "%sERROR: Can't create texture for '%s': %s%s\n", RED, fullpath, SDL_GetError(), BLACK);
    }

    // compute 2D tile grid: arrange N blocks into a grid that respects image aspect ratio
    int n = f->total_blocks;
    double img_aspect = (double)f->img_w / f->img_h;
    f->tile_cols = (int)ceil(sqrt((double)n * img_aspect));
    if (f->tile_cols < 1) {
      f->tile_cols = 1;
    }
    f->tile_rows = (n + f->tile_cols - 1) / f->tile_cols;
    f->tile_w = f->img_w / f->tile_cols;
    f->tile_h = f->img_h / f->tile_rows;
    if (f->tile_w < 1) {
      f->tile_w = 1;
    }
    if (f->tile_h < 1) {
      f->tile_h = 1;
    }

    loaded++;
    if (visual_count > 0) {
      int perc = loaded * 100 / visual_count;
      if (perc != last_perc) {
        fprintf(stdout, "\b\b\b\b%3d%%", perc);
        fflush(stdout);
        last_perc = perc;
      }
    }
  }
  if (visual_count > 0) {
    fprintf(stdout, "\b\b\b\b%3d%%\n", 100);
    fflush(stdout);
  }
}


static void create_noise_texture(AppState *st) {
  int sz = 128;
  SDL_Surface *surf = SDL_CreateRGBSurface(0, sz, sz, 32, 0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000);
  if (! surf) {
    return;
  }

  srand((unsigned)time(NULL));
  uint32_t *pixels = (uint32_t *)surf->pixels;
  for (int i = 0; i < sz * sz; i++) {
    uint8_t r = rand() % 256;
    uint8_t g = rand() % 256;
    uint8_t b = rand() % 256;
    pixels[i] = 0xFF000000 | (r << 16) | (g << 8) | b;
  }

  st->noise_tex = SDL_CreateTextureFromSurface(st->renderer, surf);
  SDL_FreeSurface(surf);
}


static void calc_grid(AppState *st) {
  // use renderer output size (handles HiDPI correctly)
  int win_w, win_h;
  SDL_GetRendererOutputSize(st->renderer, &win_w, &win_h);

  // find column count where total_blocks divides evenly and cells are closest to square
  double aspect = (double)win_w / win_h;
  int best_cols = (int)round(sqrt((double)st->total_blocks * aspect) / st->zoom);
  if (best_cols < 1) {
    best_cols = 1;
  }

  // search nearby column counts for one that divides evenly
  int cols = best_cols;
  for (int delta = 0; delta <= 4; delta++) {
    if (best_cols + delta > 0 && st->total_blocks % (best_cols + delta) == 0) {
      cols = best_cols + delta;
      break;
    }
    if (best_cols - delta > 0 && st->total_blocks % (best_cols - delta) == 0) {
      cols = best_cols - delta;
      break;
    }
  }
  int rows = (st->total_blocks + cols - 1) / cols;

  st->grid_cols = cols;
  st->grid_rows = rows;
  // reserve space for title bar (top) and frame indicator (bottom)
  int top_margin = 70;    // clear 40pt title bar
  int bot_margin = 36;    // clear frame indicator dots
  int avail_h = win_h - top_margin - bot_margin;
  if (avail_h < 100) avail_h = 100;
  st->cell_w = win_w / cols;
  st->cell_h = avail_h / rows;
  st->grid_x = 0;
  st->grid_y = top_margin;

  if (st->cell_w < MIN_CELL_SIZE) {
    st->cell_w = MIN_CELL_SIZE;
  }
  if (st->cell_h < MIN_CELL_SIZE) {
    st->cell_h = MIN_CELL_SIZE;
  }

  int total_h = rows * st->cell_h;
  st->max_scroll_y = total_h > avail_h ? total_h - avail_h : 0;
  if (st->scroll_y > st->max_scroll_y) {
    st->scroll_y = st->max_scroll_y;
  }
  if (st->scroll_y < 0) {
    st->scroll_y = 0;
  }

  st->dirty = true;
}


static void render_tooltip(AppState *st, int mx, int my) {
  if (st->hover_block < 0 || st->hover_block >= st->total_blocks) {
    return;
  }
  if (! st->font_tooltip) {
    return;
  }

  DiskBlock *b = &st->blocks[st->hover_block];
  char tip[1024];

  if (b->type == BTYPE_ZERO) {
    snprintf(tip, sizeof(tip), "Disk block %d: ZERO fill", b->disk_block);
  }
  else if (b->type == BTYPE_RANDOM) {
    snprintf(tip, sizeof(tip), "Disk block %d: RANDOM fill", b->disk_block);
  }
  else {
    FileInfo *f = &st->files[b->file_id];
    const char *tname = (b->type == BTYPE_HEADER) ? "HEADER" : "FILE";
    // show just the filename, not full path
    const char *fname = strrchr(f->path, '/');
    fname = fname ? fname + 1 : f->path;
    snprintf(tip, sizeof(tip), "Disk block %d: %s\n%s  (block %d of %d)", b->disk_block, tname, fname, b->file_block,
             f->total_blocks);
  }

  SDL_Color white = {255, 255, 255, 255};
  SDL_Surface *surf = TTF_RenderText_Blended_Wrapped(st->font_tooltip, tip, white, 400);
  if (! surf) {
    return;
  }

  SDL_Texture *tex = SDL_CreateTextureFromSurface(st->renderer, surf);
  int tw = surf->w, th = surf->h;
  SDL_FreeSurface(surf);
  if (! tex) {
    return;
  }

  // position tooltip near mouse, clamped to window
  int win_w, win_h;
  SDL_GetRendererOutputSize(st->renderer, &win_w, &win_h);

  int tx = mx + 16;
  int ty = my + 16;
  if (tx + tw + TOOLTIP_PAD > win_w) {
    tx = mx - tw - 16;
  }
  if (ty + th + TOOLTIP_PAD > win_h) {
    ty = my - th - 16;
  }
  if (tx < 0) {
    tx = 0;
  }
  if (ty < 0) {
    ty = 0;
  }

  // background
  SDL_Rect bg = {tx - TOOLTIP_PAD, ty - TOOLTIP_PAD, tw + TOOLTIP_PAD * 2, th + TOOLTIP_PAD * 2};
  SDL_SetRenderDrawColor(st->renderer, 20, 20, 20, 230);
  SDL_SetRenderDrawBlendMode(st->renderer, SDL_BLENDMODE_BLEND);
  SDL_RenderFillRect(st->renderer, &bg);
  SDL_SetRenderDrawColor(st->renderer, 200, 200, 200, 255);
  SDL_RenderDrawRect(st->renderer, &bg);

  SDL_Rect dst = {tx, ty, tw, th};
  SDL_RenderCopy(st->renderer, tex, NULL, &dst);
  SDL_DestroyTexture(tex);
}


static void render_block(AppState *st, int idx, SDL_Rect *dst) {
  DiskBlock *b = &st->blocks[idx];

  if (b->type == BTYPE_ZERO) {
    // dark background filled with repeating "0"s
    SDL_SetRenderDrawColor(st->renderer, 20, 20, 20, 255);
    SDL_RenderFillRect(st->renderer, dst);
    if (st->font_label) {
      SDL_Color dim = {200, 200, 200, 255};
      SDL_Surface *zsurf = TTF_RenderText_Blended(st->font_tooltip, "0", dim);
      if (zsurf) {
        SDL_Texture *ztex = SDL_CreateTextureFromSurface(st->renderer, zsurf);
        if (ztex) {
          int zw = zsurf->w, zh = zsurf->h;
          int pad = 2;
          for (int y = dst->y + pad; y < dst->y + dst->h - pad; y += zh + pad) {
            for (int x = dst->x + pad; x < dst->x + dst->w - pad; x += zw + pad) {
              SDL_Rect zr = {x, y, zw, zh};
              SDL_RenderCopy(st->renderer, ztex, NULL, &zr);
            }
          }
          SDL_DestroyTexture(ztex);
        }
        SDL_FreeSurface(zsurf);
      }
    }
    return;
  }

  if (b->type == BTYPE_RANDOM) {
    // noise texture
    if (st->noise_tex) {
      SDL_RenderCopy(st->renderer, st->noise_tex, NULL, dst);
    }
    else {
      SDL_SetRenderDrawColor(st->renderer, 80, 80, 80, 255);
      SDL_RenderFillRect(st->renderer, dst);
    }
    return;
  }

  // FILE or HEADER block
  FileInfo *f = &st->files[b->file_id];

  if (is_visual_type(f->ftype) && f->texture) {
    // render a 2D tile of the decoded image block N maps to (row, col) in the file's tile grid
    int tile_col = b->file_block % f->tile_cols;
    int tile_row = b->file_block / f->tile_cols;
    int src_x = tile_col * f->tile_w;
    int src_y = tile_row * f->tile_h;
    // clamp to image bounds
    int tw = f->tile_w, th = f->tile_h;
    if (src_x + tw > f->img_w) {
      tw = f->img_w - src_x;
    }
    if (src_y + th > f->img_h) {
      th = f->img_h - src_y;
    }
    if (tw < 1) {
      tw = 1;
    }
    if (th < 1) {
      th = 1;
    }
    SDL_Rect src = {src_x, src_y, tw, th};
    SDL_RenderCopy(st->renderer, f->texture, &src, dst);

    // if HEADER, overlay a semi-transparent tint
    if (b->type == BTYPE_HEADER) {
      SDL_SetRenderDrawBlendMode(st->renderer, SDL_BLENDMODE_BLEND);
      SDL_SetRenderDrawColor(st->renderer, 0, 80, 200, 80);
      SDL_RenderFillRect(st->renderer, dst);
    }
  }
  else {
    // non-visual: colored rectangle
    SDL_Color c = type_colors[f->ftype];
    if (b->type == BTYPE_HEADER) {
      // darken for header
      c.r = c.r * 2 / 3;
      c.g = c.g * 2 / 3;
      c.b = c.b * 2 / 3;
    }
    SDL_SetRenderDrawColor(st->renderer, c.r, c.g, c.b, 255);
    SDL_RenderFillRect(st->renderer, dst);

    // draw label if cells are large enough
    if (st->font_label && st->cell_w >= 28 && st->cell_h >= 14) {
      char label[32];
      snprintf(label, sizeof(label), "%s %d/%d", type_labels[f->ftype], f->type_ordinal, b->file_block);

      SDL_Color black = {0, 0, 0, 255};
      SDL_Surface *surf = TTF_RenderText_Blended(st->font_label, label, black);
      if (surf) {
        SDL_Texture *tex = SDL_CreateTextureFromSurface(st->renderer, surf);
        if (tex) {
          // center the text in the cell, scale down if needed
          int tw = surf->w, th = surf->h;
          if (tw > dst->w - 2) {
            th = th * (dst->w - 2) / tw;
            tw = dst->w - 2;
          }
          if (th > dst->h - 2) {
            tw = tw * (dst->h - 2) / th;
            th = dst->h - 2;
          }
          SDL_Rect tdst = {dst->x + (dst->w - tw) / 2, dst->y + (dst->h - th) / 2, tw, th};
          SDL_RenderCopy(st->renderer, tex, NULL, &tdst);
          SDL_DestroyTexture(tex);
        }
        SDL_FreeSurface(surf);
      }
    }
  }
}


// -------------------------------------------------------------------
// render_title: frame title bar at top center
// -------------------------------------------------------------------
static void render_title(AppState *st) {
  TTF_Font *font = st->font_title ? st->font_title : st->font_tooltip;
  if (! font) {
    return;
  }
  if (st->view_mode < 0 || st->view_mode > 7) {
    return;
  }
  const char *title = frame_titles[st->view_mode];

  int win_w, win_h;
  SDL_GetRendererOutputSize(st->renderer, &win_w, &win_h);
  (void)win_h;

  SDL_Color white = {255, 255, 255, 255};
  SDL_Surface *surf = TTF_RenderUTF8_Blended(font, title, white);
  if (! surf) {
    return;
  }
  SDL_Texture *tex = SDL_CreateTextureFromSurface(st->renderer, surf);
  int tw = surf->w, th = surf->h;
  SDL_FreeSurface(surf);
  if (! tex) {
    return;
  }

  int pad = 8;
  int bar_h = th + pad * 2;
  // semi-transparent dark background bar
  SDL_SetRenderDrawBlendMode(st->renderer, SDL_BLENDMODE_BLEND);
  SDL_SetRenderDrawColor(st->renderer, 0, 0, 0, 180);
  SDL_Rect bar = {0, 0, win_w, bar_h};
  SDL_RenderFillRect(st->renderer, &bar);

  // centered text
  SDL_Rect tdst = {(win_w - tw) / 2, pad, tw, th};
  SDL_RenderCopy(st->renderer, tex, NULL, &tdst);
  SDL_DestroyTexture(tex);
}


// -------------------------------------------------------------------
// render_frame_indicator: 8 circles at bottom center
// -------------------------------------------------------------------
static void render_frame_indicator(AppState *st) {
  int win_w, win_h;
  SDL_GetRendererOutputSize(st->renderer, &win_w, &win_h);

  int r = 7;           // circle radius
  int spacing = 24;    // center-to-center spacing
  int n = 8;
  int total_w = (n - 1) * spacing;
  int cx_start = (win_w - total_w) / 2;
  int cy = win_h - 20;

  TTF_Font *font = st->font_tooltip;

  // draw frame number "N/8" first (left of circles)
  if (font) {
    char label[16];
    snprintf(label, sizeof(label), "%d/8", st->view_mode + 1);
    SDL_Color white = {200, 200, 200, 255};
    SDL_Surface *surf = TTF_RenderText_Blended(font, label, white);
    if (surf) {
      SDL_Texture *tex = SDL_CreateTextureFromSurface(st->renderer, surf);
      if (tex) {
        int tw = surf->w, th = surf->h;
        SDL_Rect tdst = {cx_start - tw - 16, cy - th / 2, tw, th};
        SDL_RenderCopy(st->renderer, tex, NULL, &tdst);
        SDL_DestroyTexture(tex);
      }
      SDL_FreeSurface(surf);
    }
  }

  SDL_SetRenderDrawBlendMode(st->renderer, SDL_BLENDMODE_BLEND);

  for (int i = 0; i < n; i++) {
    int cx = cx_start + i * spacing;
    bool current = (i == st->view_mode);

    if (current) {
      // filled circle (bright white)
      SDL_SetRenderDrawColor(st->renderer, 255, 255, 255, 255);
    }
    else {
      // hollow circle (dim)
      SDL_SetRenderDrawColor(st->renderer, 120, 120, 120, 200);
    }

    // draw circle using midpoint algorithm
    int x = r, y = 0;
    int err = 0;
    while (x >= y) {
      if (current) {
        // fill horizontal spans for filled circle
        SDL_RenderDrawLine(st->renderer, cx - x, cy + y, cx + x, cy + y);
        SDL_RenderDrawLine(st->renderer, cx - x, cy - y, cx + x, cy - y);
        SDL_RenderDrawLine(st->renderer, cx - y, cy + x, cx + y, cy + x);
        SDL_RenderDrawLine(st->renderer, cx - y, cy - x, cx + y, cy - x);
      }
      else {
        // draw just the perimeter pixels
        SDL_RenderDrawPoint(st->renderer, cx + x, cy + y);
        SDL_RenderDrawPoint(st->renderer, cx - x, cy + y);
        SDL_RenderDrawPoint(st->renderer, cx + x, cy - y);
        SDL_RenderDrawPoint(st->renderer, cx - x, cy - y);
        SDL_RenderDrawPoint(st->renderer, cx + y, cy + x);
        SDL_RenderDrawPoint(st->renderer, cx - y, cy + x);
        SDL_RenderDrawPoint(st->renderer, cx + y, cy - x);
        SDL_RenderDrawPoint(st->renderer, cx - y, cy - x);
      }
      if (err <= 0) {
        y++;
        err += 2 * y + 1;
      }
      if (err > 0) {
        x--;
        err -= 2 * x + 1;
      }
    }
  }
}


// -------------------------------------------------------------------
// render_cards: frames 0, 1, 4, 5
// show_overlay: draw disk strip + lines (frames 1, 5)
// fragmented: use actual disk_block positions for strip (frames 4, 5)
// -------------------------------------------------------------------
static void render_cards(AppState *st, bool show_overlay, bool fragmented) {
  int win_w, win_h;
  SDL_GetRendererOutputSize(st->renderer, &win_w, &win_h);

  SDL_SetRenderDrawColor(st->renderer, 18, 18, 28, 255);
  SDL_RenderClear(st->renderer);

  int nfiles = st->num_files;
  if (nfiles == 0) {
    return;
  }

  // filesystem overlay: cards on left, tall vertical disk strip on right
  int sidebar_w = show_overlay ? (int)(win_w * 0.22) : 0;
  int card_area_w = win_w - sidebar_w;
  int card_area_h = win_h;

  // card grid layout
  int cols, rows;
  if (nfiles <= 3) {
    cols = nfiles;
    rows = 1;
  }
  else if (nfiles <= 6) {
    cols = 3;
    rows = (nfiles + 2) / 3;
  }
  else {
    cols = (int)ceil(sqrt((double)nfiles * 1.3));
    rows = (nfiles + cols - 1) / cols;
  }

  int h_pad = card_area_w / 30;
  int v_pad = card_area_h / 20;
  int card_w = (card_area_w - h_pad * (cols + 1)) / cols;
  int card_h = (card_area_h - v_pad * (rows + 1)) / rows;

  // title bar height (approx) - leave space at top
  int title_bar_h = 40;

  // card center-bottom positions for line drawing
  int *card_cx = malloc(nfiles * sizeof(int));
  int *card_cy_bottom = malloc(nfiles * sizeof(int));

  for (int i = 0; i < nfiles; i++) {
    FileInfo *f = &st->files[i];
    int r = i / cols;
    int c = i % cols;

    int sx = h_pad + c * (card_w + h_pad);
    int sy = title_bar_h + v_pad + r * (card_h + v_pad);

    SDL_Color clr = type_colors[f->ftype];
    SDL_Rect card_rect = {sx, sy, card_w, card_h};

    // For small cards: fill entire card with type color (visual types get
    // a tinted background) so the grid always has visible color.
    bool small_card = (card_w < 60 || card_h < 50);

    if (small_card) {
      // fill card with type color
      if (is_visual_type(f->ftype) && f->texture) {
        // fill with image, stretched to card
        SDL_RenderCopy(st->renderer, f->texture, NULL, &card_rect);
      }
      else {
        SDL_SetRenderDrawColor(st->renderer, clr.r, clr.g, clr.b, 255);
        SDL_RenderFillRect(st->renderer, &card_rect);
      }
      // border
      SDL_SetRenderDrawColor(st->renderer, 20, 20, 30, 255);
      SDL_RenderDrawRect(st->renderer, &card_rect);
    }
    else {
      // card background
      SDL_SetRenderDrawColor(st->renderer, 40, 40, 55, 255);
      SDL_RenderFillRect(st->renderer, &card_rect);
      // card border in type color
      SDL_SetRenderDrawColor(st->renderer, clr.r, clr.g, clr.b, 180);
      SDL_RenderDrawRect(st->renderer, &card_rect);

      // image or colored type icon
      int img_pad = 6;
      int label_h = 22;
      int img_area_h = card_h - label_h - img_pad * 2;
      int img_area_w = card_w - img_pad * 2;

      if (img_area_w < 4) {
        img_area_w = 4;
      }
      if (img_area_h < 4) {
        img_area_h = 4;
      }

      if (is_visual_type(f->ftype) && f->texture) {
        // aspect-ratio fit
        double aspect = (double)f->img_w / f->img_h;
        int dw, dh;
        if (aspect > (double)img_area_w / img_area_h) {
          dw = img_area_w;
          dh = (int)(img_area_w / aspect);
        }
        else {
          dh = img_area_h;
          dw = (int)(img_area_h * aspect);
        }
        int dx = sx + img_pad + (img_area_w - dw) / 2;
        int dy = sy + img_pad + (img_area_h - dh) / 2;
        SDL_Rect idst = {dx, dy, dw, dh};
        SDL_RenderCopy(st->renderer, f->texture, NULL, &idst);
      }
      else {
        // colored type icon rectangle
        SDL_Rect icon = {sx + img_pad, sy + img_pad, img_area_w, img_area_h};
        SDL_SetRenderDrawColor(st->renderer, clr.r, clr.g, clr.b, 255);
        SDL_RenderFillRect(st->renderer, &icon);

        // type label centered in icon
        if (st->font_label) {
          SDL_Color black = {0, 0, 0, 255};
          SDL_Surface *surf = TTF_RenderText_Blended(st->font_label, type_labels[f->ftype], black);
          if (surf) {
            SDL_Texture *tex = SDL_CreateTextureFromSurface(st->renderer, surf);
            if (tex) {
              int tw = surf->w, th = surf->h;
              SDL_Rect tdst = {sx + img_pad + (img_area_w - tw) / 2, sy + img_pad + (img_area_h - th) / 2, tw, th};
              SDL_RenderCopy(st->renderer, tex, NULL, &tdst);
              SDL_DestroyTexture(tex);
            }
            SDL_FreeSurface(surf);
          }
        }
      }

      // filename label below image
      if (st->font_label) {
        const char *fname = strrchr(f->path, '/');
        fname = fname ? fname + 1 : f->path;
        SDL_Color light = {200, 200, 220, 255};
        SDL_Surface *surf = TTF_RenderText_Blended(st->font_label, fname, light);
        if (surf) {
          SDL_Texture *tex = SDL_CreateTextureFromSurface(st->renderer, surf);
          if (tex) {
            int tw = surf->w, th = surf->h;
            if (tw > card_w - 4) {
              th = th * (card_w - 4) / tw;
              tw = card_w - 4;
            }
            int ty_label = sy + card_h - label_h + (label_h - th) / 2;
            SDL_Rect tdst = {sx + (card_w - tw) / 2, ty_label, tw, th};
            SDL_RenderCopy(st->renderer, tex, NULL, &tdst);
            SDL_DestroyTexture(tex);
          }
          SDL_FreeSurface(surf);
        }
      }
    }

    card_cx[i] = sx + card_w / 2;
    card_cy_bottom[i] = sy + card_h;
  }

  // Filesystem overlay: cards on left, tall vertical disk strip on right.
  // Filesystem overlay on the right side.
  // Unfragmented: tall vertical color strip + segment lines.
  // Fragmented: mini jigsaw grid (actual block tiles) + segment lines.
  if (show_overlay && st->total_blocks > 0) {
    int tb = st->total_blocks;
    int sb_x = card_area_w + 4;
    int sb_w = sidebar_w - 8;
    int sb_top = 50;
    int sb_bot = win_h - 30;
    int sb_h = sb_bot - sb_top;
    if (sb_h < 20) sb_h = 20;

    SDL_SetRenderDrawBlendMode(st->renderer, SDL_BLENDMODE_BLEND);

    // Build per-position file_id map
    int *strip_file = malloc(tb * sizeof(int));
    for (int i = 0; i < tb; i++) strip_file[i] = -1;

    if (fragmented) {
      // disk order — scattered
      for (int b = 0; b < tb; b++) {
        if (st->blocks[b].file_id >= 0)
          strip_file[b] = st->blocks[b].file_id;
      }
    } else {
      // contiguous file order
      int pos = 0;
      for (int fi = 0; fi < nfiles && pos < tb; fi++) {
        for (int k = 0; k < st->files[fi].total_blocks && pos < tb; k++)
          strip_file[pos++] = fi;
      }
    }

    // Arrays to store per-block pixel positions for line drawing
    int *blk_cx = malloc(tb * sizeof(int));
    int *blk_cy = malloc(tb * sizeof(int));

    // Both views use the same tall colored strip — only the block
    // ordering differs.  Unfragmented: contiguous file order.
    // Fragmented: actual disk order (scattered).
    {
      SDL_SetRenderDrawColor(st->renderer, 10, 10, 20, 255);
      SDL_Rect sb_bg = {sb_x, sb_top, sb_w, sb_h};
      SDL_RenderFillRect(st->renderer, &sb_bg);
      SDL_SetRenderDrawColor(st->renderer, 70, 70, 90, 255);
      SDL_RenderDrawRect(st->renderer, &sb_bg);

      // Draw colored rows using strip_file (already set above:
      // disk order for fragmented, contiguous for unfragmented)
      for (int p = 0; p < tb; p++) {
        int py = sb_top + 2 + (int)((double)p / tb * (sb_h - 4));
        int py2 = sb_top + 2 + (int)((double)(p+1) / tb * (sb_h - 4));
        if (py2 <= py) py2 = py + 1;

        if (strip_file[p] >= 0 && strip_file[p] < nfiles) {
          SDL_Color c = type_colors[st->files[strip_file[p]].ftype];
          SDL_SetRenderDrawColor(st->renderer, c.r, c.g, c.b, 240);
        } else {
          SDL_SetRenderDrawColor(st->renderer, 25, 25, 35, 200);
        }
        SDL_Rect row = {sb_x + 2, py, sb_w - 4, py2 - py};
        SDL_RenderFillRect(st->renderer, &row);

        blk_cx[p] = sb_x;
        blk_cy[p] = (py + py2) / 2;
      }
    }

    // "DISK" label above
    if (st->font_tooltip) {
      SDL_Color dim = {160, 160, 180, 255};
      SDL_Surface *ls = TTF_RenderText_Blended(st->font_tooltip, "DISK", dim);
      if (ls) {
        SDL_Texture *lt = SDL_CreateTextureFromSurface(st->renderer, ls);
        if (lt) {
          SDL_Rect lr = {sb_x + (sb_w - ls->w) / 2, sb_top - ls->h - 2, ls->w, ls->h};
          SDL_RenderCopy(st->renderer, lt, NULL, &lr);
          SDL_DestroyTexture(lt);
        }
        SDL_FreeSurface(ls);
      }
    }

    // Draw segment-based connector lines from cards to disk.
    // Vivid unique color per file, bold. Capped at 12 segments per file.
    static const SDL_Color vp[] = {
      {255, 0, 0, 255}, {0, 80, 255, 255}, {255, 255, 0, 255},
      {255, 0, 255, 255}, {0, 220, 0, 255}, {255, 120, 0, 255},
      {220, 0, 120, 255}, {120, 0, 255, 255}, {0, 200, 200, 255},
      {255, 0, 120, 255}, {160, 255, 0, 255}, {255, 180, 0, 255},
    };
    int vp_size = (int)(sizeof(vp) / sizeof(vp[0]));
    int max_segs_per_file = 12;
    for (int fi = 0; fi < nfiles; fi++) {
      SDL_Color vc = vp[fi % vp_size];
      SDL_SetRenderDrawColor(st->renderer, vc.r, vc.g, vc.b, 255);
      int seg_count = 0;
      int seg_start = -1;
      for (int p = 0; p <= tb; p++) {
        bool is_mine = (p < tb && strip_file[p] == fi);

        if (is_mine && seg_start < 0) {
          seg_start = p;
        }
        else if (!is_mine && seg_start >= 0) {
          if (seg_count < max_segs_per_file) {
            int x1 = card_cx[fi] - card_w / 2;
            int y1 = card_cy_bottom[fi] - card_h;
            int x2 = blk_cx[seg_start];
            int y2 = blk_cy[seg_start];
            // thick line (5px)
            for (int d = -2; d <= 2; d++) {
              SDL_RenderDrawLine(st->renderer, x1, y1 + d, x2, y2 + d);
            }
            // arrowhead at card end
            double dx = x1 - x2, dy = y1 - y2;
            double len = sqrt(dx*dx + dy*dy);
            if (len > 10) {
              double ux = dx / len, uy = dy / len;
              int ax = x1 - (int)(ux * 14);
              int ay = y1 - (int)(uy * 14);
              int px = (int)(-uy * 7), py = (int)(ux * 7);
              for (int d = -1; d <= 1; d++) {
                SDL_RenderDrawLine(st->renderer, x1, y1 + d, ax + px, ay + py + d);
                SDL_RenderDrawLine(st->renderer, x1, y1 + d, ax - px, ay - py + d);
              }
            }
          }
          seg_count++;
          seg_start = -1;
        }
      }
    }

    free(strip_file);
    free(blk_cx);
    free(blk_cy);
  }

  free(card_cx);
  free(card_cy_bottom);
}


// -------------------------------------------------------------------
// render_linear: frames 2, 3 — unfragmented block view
// Shows files as contiguous color bands (file order, not disk order).
// Each file occupies a horizontal band proportional to its block count.
// highlight_hf: bright markers on header/footer blocks (frame 3)
// -------------------------------------------------------------------
static void render_linear(AppState *st, bool highlight_hf) {
  int win_w, win_h;
  SDL_GetRendererOutputSize(st->renderer, &win_w, &win_h);

  SDL_SetRenderDrawColor(st->renderer, 0, 0, 0, 255);
  SDL_RenderClear(st->renderer);

  if (st->total_blocks == 0 || st->num_files == 0) {
    return;
  }

  // Build a linear block ordering: files in order, each file's blocks
  // sorted by file_block.  This is the "unfragmented" view — every
  // file is contiguous, like it would be on a fresh filesystem.
  int tb = st->total_blocks;
  int *linear_map = malloc(tb * sizeof(int));
  if (!linear_map) return;
  for (int i = 0; i < tb; i++) linear_map[i] = -1;

  // find max file_block per file for footer detection
  int *max_fb = calloc(st->num_files, sizeof(int));
  if (!max_fb) { free(linear_map); return; }
  for (int i = 0; i < st->num_files; i++) max_fb[i] = -1;
  for (int b = 0; b < tb; b++) {
    DiskBlock *blk = &st->blocks[b];
    if (blk->file_id >= 0 && blk->file_id < st->num_files) {
      if (blk->file_block > max_fb[blk->file_id])
        max_fb[blk->file_id] = blk->file_block;
    }
  }

  // For each file, gather its disk blocks sorted by file_block
  int pos = 0;
  for (int fi = 0; fi < st->num_files && pos < tb; fi++) {
    int cap = st->files[fi].total_blocks + 1;
    int cnt = 0;
    int *buf_fb = malloc(cap * sizeof(int));
    int *buf_db = malloc(cap * sizeof(int));
    if (!buf_fb || !buf_db) { free(buf_fb); free(buf_db); break; }
    for (int b = 0; b < tb; b++) {
      if (st->blocks[b].file_id == fi) {
        if (cnt >= cap) {
          cap *= 2;
          buf_fb = realloc(buf_fb, cap * sizeof(int));
          buf_db = realloc(buf_db, cap * sizeof(int));
        }
        buf_fb[cnt] = st->blocks[b].file_block;
        buf_db[cnt] = b;
        cnt++;
      }
    }
    // insertion sort by file_block
    for (int a = 1; a < cnt; a++) {
      int kfb = buf_fb[a], kdb = buf_db[a];
      int j = a - 1;
      while (j >= 0 && buf_fb[j] > kfb) {
        buf_fb[j+1] = buf_fb[j]; buf_db[j+1] = buf_db[j]; j--;
      }
      buf_fb[j+1] = kfb; buf_db[j+1] = kdb;
    }
    for (int k = 0; k < cnt && pos < tb; k++, pos++)
      linear_map[pos] = buf_db[k];
    free(buf_fb); free(buf_db);
  }
  // fill remaining with ZERO/RANDOM
  for (int b = 0; b < tb && pos < tb; b++) {
    if (st->blocks[b].type == BTYPE_ZERO || st->blocks[b].type == BTYPE_RANDOM)
      linear_map[pos++] = b;
  }

  // Use the same grid layout as jigsaw so the block count and
  // proportions are identical — only the ORDER changes.
  int cols = st->grid_cols;
  int cw = st->cell_w;
  int ch = st->cell_h;

  // Track start position of each file group for drawing borders
  int *file_start_pos = calloc(st->num_files, sizeof(int));
  int *file_end_pos = calloc(st->num_files, sizeof(int));
  for (int i = 0; i < st->num_files; i++) {
    file_start_pos[i] = tb;
    file_end_pos[i] = -1;
  }
  for (int i = 0; i < tb; i++) {
    int di = (linear_map[i] >= 0) ? linear_map[i] : i;
    int fid = st->blocks[di].file_id;
    if (fid >= 0 && fid < st->num_files) {
      if (i < file_start_pos[fid]) file_start_pos[fid] = i;
      if (i > file_end_pos[fid]) file_end_pos[fid] = i;
    }
  }

  for (int i = 0; i < tb; i++) {
    int row = i / cols;
    int col = i % cols;
    int disk_idx = (linear_map[i] >= 0) ? linear_map[i] : i;

    SDL_Rect dst = {st->grid_x + col * cw,
                    st->grid_y + row * ch - st->scroll_y,
                    cw, ch};
    render_block(st, disk_idx, &dst);

    // Draw white border on file group boundaries — this makes
    // the unfragmented view look ORGANIZED (each file is a neat
    // contiguous region) vs the jigsaw's scattered chaos.
    int fid = st->blocks[disk_idx].file_id;
    if (fid >= 0 && fid < st->num_files) {
      // Check if this block is at the boundary of its file group
      int prev_fid = -1, next_fid = -1;
      if (i > 0) {
        int pi = (linear_map[i-1] >= 0) ? linear_map[i-1] : i-1;
        prev_fid = st->blocks[pi].file_id;
      }
      if (i < tb - 1) {
        int ni = (linear_map[i+1] >= 0) ? linear_map[i+1] : i+1;
        next_fid = st->blocks[ni].file_id;
      }

      SDL_SetRenderDrawColor(st->renderer, 255, 255, 255, 200);
      SDL_SetRenderDrawBlendMode(st->renderer, SDL_BLENDMODE_BLEND);

      // top edge: first row of this file group OR first column
      if (prev_fid != fid || i < cols) {
        SDL_RenderDrawLine(st->renderer, dst.x, dst.y, dst.x + dst.w, dst.y);
      }
      // left edge: first block of group or first column
      if (col == 0 || prev_fid != fid) {
        SDL_RenderDrawLine(st->renderer, dst.x, dst.y, dst.x, dst.y + dst.h);
      }
      // bottom edge: last row of this file group
      if (next_fid != fid || i >= tb - cols) {
        SDL_RenderDrawLine(st->renderer, dst.x, dst.y + dst.h, dst.x + dst.w, dst.y + dst.h);
      }
      // right edge: last block of group or last column
      if (col == cols - 1 || next_fid != fid) {
        SDL_RenderDrawLine(st->renderer, dst.x + dst.w, dst.y, dst.x + dst.w, dst.y + dst.h);
      }

      // Label at the start of each file group
      if (i == file_start_pos[fid] && st->font_label && cw >= 20 && ch >= 14) {
        const char *fname = strrchr(st->files[fid].path, '/');
        fname = fname ? fname + 1 : st->files[fid].path;
        SDL_Color white = {255, 255, 255, 255};
        SDL_Surface *ls = TTF_RenderText_Blended(st->font_label, fname, white);
        if (ls) {
          SDL_Texture *lt = SDL_CreateTextureFromSurface(st->renderer, ls);
          if (lt) {
            int lw = ls->w, lh = ls->h;
            if (lw > cw * 4) { lh = lh * cw * 4 / lw; lw = cw * 4; }
            SDL_Rect lr = {dst.x + 2, dst.y + 2, lw, lh};
            // dark background behind label for readability
            SDL_SetRenderDrawColor(st->renderer, 0, 0, 0, 180);
            SDL_Rect lbg = {lr.x - 1, lr.y - 1, lr.w + 2, lr.h + 2};
            SDL_RenderFillRect(st->renderer, &lbg);
            SDL_RenderCopy(st->renderer, lt, NULL, &lr);
            SDL_DestroyTexture(lt);
          }
          SDL_FreeSurface(ls);
        }
      }
    }

    if (highlight_hf) {
      // Use position in linear ordering: first block of file group = Header,
      // last block of file group = Footer.
      int fid = st->blocks[disk_idx].file_id;
      bool is_header = (fid >= 0 && fid < st->num_files && i == file_start_pos[fid]);
      bool is_footer = (fid >= 0 && fid < st->num_files && i == file_end_pos[fid] && !is_header);

      if (is_header) {
        // Header: thick green border + green "H"
        SDL_SetRenderDrawColor(st->renderer, 30, 255, 30, 255);
        for (int b = 0; b < 6; b++) {
          SDL_Rect br = {dst.x + b, dst.y + b, dst.w - 2*b, dst.h - 2*b};
          SDL_RenderDrawRect(st->renderer, &br);
        }
        if (st->font_label && cw >= 12 && ch >= 12) {
          SDL_Color yc = {30, 255, 30, 255};
          SDL_Surface *s = TTF_RenderText_Blended(st->font_label, "H", yc);
          if (s) {
            SDL_Texture *t = SDL_CreateTextureFromSurface(st->renderer, s);
            if (t) { SDL_Rect r = {dst.x+6, dst.y+6, s->w, s->h}; SDL_RenderCopy(st->renderer, t, NULL, &r); SDL_DestroyTexture(t); }
            SDL_FreeSurface(s);
          }
        }
      }
      else if (is_footer) {
        // Footer: thick red border + red "F"
        SDL_SetRenderDrawColor(st->renderer, 255, 30, 30, 255);
        for (int b = 0; b < 6; b++) {
          SDL_Rect br = {dst.x + b, dst.y + b, dst.w - 2*b, dst.h - 2*b};
          SDL_RenderDrawRect(st->renderer, &br);
        }
        if (st->font_label && cw >= 12 && ch >= 12) {
          SDL_Color cc = {255, 30, 30, 255};
          SDL_Surface *s = TTF_RenderText_Blended(st->font_label, "F", cc);
          if (s) {
            SDL_Texture *t = SDL_CreateTextureFromSurface(st->renderer, s);
            if (t) { SDL_Rect r = {dst.x+6, dst.y+6, s->w, s->h}; SDL_RenderCopy(st->renderer, t, NULL, &r); SDL_DestroyTexture(t); }
            SDL_FreeSurface(s);
          }
        }
      }
    }
  }

  free(linear_map);
  free(max_fb);
  free(file_start_pos);
  free(file_end_pos);
}


// -------------------------------------------------------------------
// render_fs_grid: frame 5 — fragmented filesystem view
// Left: jigsaw grid (~70% width, same layout as frame 7).
// Right: file cards (thumbnails/icons + labels) with arrows to blocks.
// Shows the filesystem's job of tracking scattered blocks.
// -------------------------------------------------------------------
static void render_fs_grid(AppState *st) {
  int win_w, win_h;
  SDL_GetRendererOutputSize(st->renderer, &win_w, &win_h);

  SDL_SetRenderDrawColor(st->renderer, 12, 12, 22, 255);
  SDL_RenderClear(st->renderer);

  int tb = st->total_blocks;
  int nfiles = st->num_files;
  if (tb == 0 || nfiles == 0) return;

  // Layout: jigsaw grid on left, file cards on right
  int panel_w = (int)(win_w * 0.30);
  int grid_left = 4;
  int grid_top = 70;   // clear the 40pt title bar
  int grid_w = win_w - panel_w - grid_left - 8;
  int grid_h = win_h - grid_top - 30;
  int panel_x = win_w - panel_w;

  // Compute grid layout for the left area (same algorithm as calc_grid/render_jigsaw)
  double aspect = (double)grid_w / grid_h;
  int gcols = (int)round(sqrt((double)tb * aspect));
  if (gcols < 1) gcols = 1;
  int best = gcols;
  for (int d = 0; d <= 4; d++) {
    if (gcols + d > 0 && tb % (gcols + d) == 0) { best = gcols + d; break; }
    if (gcols - d > 0 && tb % (gcols - d) == 0) { best = gcols - d; break; }
  }
  gcols = best;
  int grows = (tb + gcols - 1) / gcols;
  int gcw = grid_w / gcols;
  int gch = grid_h / grows;
  if (gcw < 2) gcw = 2;
  if (gch < 2) gch = 2;

  // Render the jigsaw grid on the left (disk order — same as frame 7)
  int *blk_cx = malloc(tb * sizeof(int));
  int *blk_cy = malloc(tb * sizeof(int));

  for (int i = 0; i < tb; i++) {
    int row = i / gcols;
    int col = i % gcols;
    int bx = grid_left + col * gcw;
    int by = grid_top + row * gch;
    SDL_Rect dst = {bx, by, gcw, gch};
    render_block(st, i, &dst);
    blk_cx[i] = bx + gcw / 2;
    blk_cy[i] = by + gch / 2;
  }

  // Overlay: colored border on EVERY file block to show the filesystem
  // tracks all of them.  Use a 2px border in the file's type color.
  SDL_SetRenderDrawBlendMode(st->renderer, SDL_BLENDMODE_BLEND);
  for (int i = 0; i < tb; i++) {
    if (st->blocks[i].file_id < 0) continue;
    SDL_Color c = type_colors[st->files[st->blocks[i].file_id].ftype];
    SDL_SetRenderDrawColor(st->renderer, c.r, c.g, c.b, 220);
    int row = i / gcols;
    int col = i % gcols;
    int bx = grid_left + col * gcw;
    int by = grid_top + row * gch;
    SDL_Rect dst = {bx, by, gcw, gch};
    SDL_RenderDrawRect(st->renderer, &dst);
    SDL_Rect inner = {bx + 1, by + 1, gcw - 2, gch - 2};
    SDL_RenderDrawRect(st->renderer, &inner);
  }

  // Right panel: dark background with border
  SDL_SetRenderDrawColor(st->renderer, 24, 24, 36, 255);
  SDL_Rect panel_bg = {panel_x, grid_top, panel_w, grid_h};
  SDL_RenderFillRect(st->renderer, &panel_bg);
  SDL_SetRenderDrawColor(st->renderer, 60, 60, 80, 255);
  SDL_RenderDrawRect(st->renderer, &panel_bg);

  // "FILESYSTEM" label at top of panel
  int fs_label_h = 0;
  if (st->font_title) {
    SDL_Color dim = {180, 180, 200, 255};
    SDL_Surface *ls = TTF_RenderText_Blended(st->font_title, "FILESYSTEM", dim);
    if (ls) {
      SDL_Texture *lt = SDL_CreateTextureFromSurface(st->renderer, ls);
      if (lt) {
        // scale down if wider than panel
        int tw = ls->w, th = ls->h;
        if (tw > panel_w - 12) { th = th * (panel_w - 12) / tw; tw = panel_w - 12; }
        SDL_Rect lr = {panel_x + (panel_w - tw) / 2, grid_top + 8, tw, th};
        SDL_RenderCopy(st->renderer, lt, NULL, &lr);
        fs_label_h = th + 16;
        SDL_DestroyTexture(lt);
      }
      SDL_FreeSurface(ls);
    }
  }

  // File cards inside the panel — evenly spaced with visible gaps
  int card_top = grid_top + fs_label_h + 4;
  int card_area_h = grid_h - fs_label_h - 8;
  int card_side_pad = 8;
  int card_w = panel_w - card_side_pad * 2;
  // card height capped so there's always a gap
  int card_h = (card_area_h * 2 / 3) / nfiles;
  if (card_h > 80) card_h = 80;
  if (card_h < 24) card_h = 24;
  // distribute remaining space as gaps
  int total_cards_h_raw = nfiles * card_h;
  int total_gap = card_area_h - total_cards_h_raw;
  int card_pad = (nfiles > 1) ? total_gap / (nfiles - 1) : 0;
  if (card_pad < 4) card_pad = 4;

  // center cards vertically if they don't fill the panel
  int total_cards_h = nfiles * card_h + (nfiles - 1) * card_pad;
  int card_start_y = card_top + (card_area_h - total_cards_h) / 2;
  if (card_start_y < card_top) card_start_y = card_top;

  int *card_lx = malloc(nfiles * sizeof(int));
  int *card_cy = malloc(nfiles * sizeof(int));

  for (int i = 0; i < nfiles; i++) {
    FileInfo *f = &st->files[i];
    int cx = panel_x + card_side_pad;
    int cy = card_start_y + i * (card_h + card_pad);

    // card background
    SDL_SetRenderDrawColor(st->renderer, 40, 40, 55, 255);
    SDL_Rect card_rect = {cx, cy, card_w, card_h};
    SDL_RenderFillRect(st->renderer, &card_rect);
    // card border in file type color
    SDL_Color clr = type_colors[f->ftype];
    SDL_SetRenderDrawColor(st->renderer, clr.r, clr.g, clr.b, 200);
    SDL_RenderDrawRect(st->renderer, &card_rect);

    // thumbnail or type icon on the left side of the card
    int img_pad = 4;
    int img_size = card_h - img_pad * 2;
    if (img_size < 8) img_size = 8;

    if (is_visual_type(f->ftype) && f->texture) {
      // aspect-ratio fit thumbnail
      double img_aspect = (double)f->img_w / f->img_h;
      int dw, dh;
      if (img_aspect > 1.0) {
        dw = img_size;
        dh = (int)(img_size / img_aspect);
      }
      else {
        dh = img_size;
        dw = (int)(img_size * img_aspect);
      }
      int dx = cx + img_pad + (img_size - dw) / 2;
      int dy = cy + img_pad + (img_size - dh) / 2;
      SDL_Rect idst = {dx, dy, dw, dh};
      SDL_RenderCopy(st->renderer, f->texture, NULL, &idst);
    }
    else {
      // colored type icon
      SDL_Rect icon = {cx + img_pad, cy + img_pad, img_size, img_size};
      SDL_SetRenderDrawColor(st->renderer, clr.r, clr.g, clr.b, 255);
      SDL_RenderFillRect(st->renderer, &icon);
      // type label centered
      if (st->font_label) {
        SDL_Color black = {0, 0, 0, 255};
        SDL_Surface *surf = TTF_RenderText_Blended(st->font_label, type_labels[f->ftype], black);
        if (surf) {
          SDL_Texture *tex = SDL_CreateTextureFromSurface(st->renderer, surf);
          if (tex) {
            int tw = surf->w, th = surf->h;
            SDL_Rect tdst = {icon.x + (icon.w - tw) / 2, icon.y + (icon.h - th) / 2, tw, th};
            SDL_RenderCopy(st->renderer, tex, NULL, &tdst);
            SDL_DestroyTexture(tex);
          }
          SDL_FreeSurface(surf);
        }
      }
    }

    // filename label to the right of the thumbnail (use medium font)
    TTF_Font *name_font = st->font_medium ? st->font_medium : st->font_tooltip;
    if (name_font) {
      const char *fname = strrchr(f->path, '/');
      fname = fname ? fname + 1 : f->path;
      SDL_Color white = {220, 220, 230, 255};
      SDL_Surface *ls = TTF_RenderText_Blended(name_font, fname, white);
      if (ls) {
        SDL_Texture *lt = SDL_CreateTextureFromSurface(st->renderer, ls);
        if (lt) {
          int tw = ls->w, th = ls->h;
          int label_x = cx + img_pad + img_size + 8;
          int max_tw = card_w - img_size - img_pad * 2 - 12;
          if (tw > max_tw && max_tw > 0) { th = th * max_tw / tw; tw = max_tw; }
          SDL_Rect lr = {label_x, cy + (card_h - th) / 2, tw, th};
          SDL_RenderCopy(st->renderer, lt, NULL, &lr);
          SDL_DestroyTexture(lt);
        }
        SDL_FreeSurface(ls);
      }
    }

    card_lx[i] = panel_x;
    card_cy[i] = cy + card_h / 2;
  }

  // Draw a line from the filesystem card to EVERY block belonging to that file.
  // Each file gets a vivid, high-contrast color so lines pop.
  SDL_SetRenderDrawBlendMode(st->renderer, SDL_BLENDMODE_BLEND);

  static const SDL_Color vivid_palette[] = {
    {255, 0, 0, 240},      // red
    {0, 80, 255, 240},     // blue
    {255, 255, 0, 240},    // yellow
    {255, 0, 255, 240},    // magenta
    {0, 220, 0, 240},      // green
    {255, 120, 0, 240},    // orange
    {220, 0, 120, 240},    // crimson
    {120, 0, 255, 240},    // violet
    {0, 200, 200, 240},    // teal
    {255, 0, 120, 240},    // hot pink
    {160, 255, 0, 240},    // lime
    {255, 180, 0, 240},    // amber
  };
  int palette_size = (int)(sizeof(vivid_palette) / sizeof(vivid_palette[0]));

  // Draw lines in random block order so no file consistently gets buried.
  // Build a shuffled index array.
  int *draw_order = malloc(tb * sizeof(int));
  for (int i = 0; i < tb; i++) draw_order[i] = i;
  for (int i = tb - 1; i > 0; i--) {
    int j = rand() % (i + 1);
    int tmp = draw_order[i]; draw_order[i] = draw_order[j]; draw_order[j] = tmp;
  }
  for (int k = 0; k < tb; k++) {
    int i = draw_order[k];
    int fi = st->blocks[i].file_id;
    if (fi < 0 || fi >= nfiles) continue;
    SDL_Color c = vivid_palette[fi % palette_size];
    SDL_SetRenderDrawColor(st->renderer, c.r, c.g, c.b, c.a);
    int x1 = card_lx[fi];
    int y1 = card_cy[fi];
    int x2 = blk_cx[i];
    int y2 = blk_cy[i];
    SDL_RenderDrawLine(st->renderer, x1, y1, x2, y2);
    SDL_RenderDrawLine(st->renderer, x1, y1 + 1, x2, y2 + 1);
  }
  free(draw_order);

  free(blk_cx);
  free(blk_cy);
  free(card_lx);
  free(card_cy);
}


// -------------------------------------------------------------------
// render_jigsaw: frames 6, 7 (disk-order block layout)
// highlight_hf: bright borders on header/footer blocks (frame 7)
// -------------------------------------------------------------------
static void render_jigsaw(AppState *st, bool highlight_hf) {
  int win_w, win_h;
  SDL_GetRendererOutputSize(st->renderer, &win_w, &win_h);
  (void)win_w;
  (void)win_h;

  SDL_SetRenderDrawColor(st->renderer, 0, 0, 0, 255);
  SDL_RenderClear(st->renderer);

  // find max file_block per file for footer detection
  int *max_fb = NULL;
  if (highlight_hf && st->num_files > 0) {
    max_fb = malloc(st->num_files * sizeof(int));
    if (max_fb) {
      for (int i = 0; i < st->num_files; i++) {
        max_fb[i] = -1;
      }
      for (int b = 0; b < st->total_blocks; b++) {
        DiskBlock *blk = &st->blocks[b];
        if (blk->file_id >= 0 && blk->file_id < st->num_files) {
          if (blk->file_block > max_fb[blk->file_id]) {
            max_fb[blk->file_id] = blk->file_block;
          }
        }
      }
    }
  }

  for (int row = 0; row < st->grid_rows; row++) {
    for (int col = 0; col < st->grid_cols; col++) {
      int idx = row * st->grid_cols + col;
      if (idx >= st->total_blocks) {
        break;
      }

      SDL_Rect dst = {st->grid_x + col * st->cell_w, st->grid_y + row * st->cell_h - st->scroll_y, st->cell_w, st->cell_h};
      render_block(st, idx, &dst);

      // highlight hovered block
      if (idx == st->hover_block) {
        SDL_SetRenderDrawColor(st->renderer, 255, 255, 0, 255);
        SDL_RenderDrawRect(st->renderer, &dst);
        SDL_Rect inner = {dst.x + 1, dst.y + 1, dst.w - 2, dst.h - 2};
        SDL_RenderDrawRect(st->renderer, &inner);
      }

      // H/F highlighting
      if (highlight_hf && max_fb) {
        DiskBlock *blk = &st->blocks[idx];
        if (blk->type == BTYPE_HEADER) {
          // Header: thick green border + green "H"
          SDL_SetRenderDrawColor(st->renderer, 30, 255, 30, 255);
          for (int b = 0; b < 6; b++) {
            SDL_Rect br = {dst.x + b, dst.y + b, dst.w - 2*b, dst.h - 2*b};
            SDL_RenderDrawRect(st->renderer, &br);
          }
          if (st->font_label && st->cell_w >= 12 && st->cell_h >= 12) {
            SDL_Color yclr = {30, 255, 30, 255};
            SDL_Surface *hs = TTF_RenderText_Blended(st->font_label, "H", yclr);
            if (hs) {
              SDL_Texture *ht = SDL_CreateTextureFromSurface(st->renderer, hs);
              if (ht) {
                int hw = hs->w, hh = hs->h;
                SDL_Rect hr = {dst.x + 6, dst.y + 6, hw, hh};
                SDL_RenderCopy(st->renderer, ht, NULL, &hr);
                SDL_DestroyTexture(ht);
              }
              SDL_FreeSurface(hs);
            }
          }
        }
        else if (blk->file_id >= 0 && blk->file_id < st->num_files && blk->file_block == max_fb[blk->file_id]) {
          // Footer: thick red border + red "F"
          SDL_SetRenderDrawColor(st->renderer, 255, 30, 30, 255);
          for (int b = 0; b < 6; b++) {
            SDL_Rect br = {dst.x + b, dst.y + b, dst.w - 2*b, dst.h - 2*b};
            SDL_RenderDrawRect(st->renderer, &br);
          }
          if (st->font_label && st->cell_w >= 12 && st->cell_h >= 12) {
            SDL_Color cclr = {255, 30, 30, 255};
            SDL_Surface *fs = TTF_RenderText_Blended(st->font_label, "F", cclr);
            if (fs) {
              SDL_Texture *ft_tex = SDL_CreateTextureFromSurface(st->renderer, fs);
              if (ft_tex) {
                int fw = fs->w, fh = fs->h;
                SDL_Rect fr = {dst.x + 6, dst.y + 6, fw, fh};
                SDL_RenderCopy(st->renderer, ft_tex, NULL, &fr);
                SDL_DestroyTexture(ft_tex);
              }
              SDL_FreeSurface(fs);
            }
          }
        }
      }
    }
  }

  if (max_fb) {
    free(max_fb);
  }
}


// -------------------------------------------------------------------
// render_view: dispatch to the correct renderer for view_mode
// -------------------------------------------------------------------
static void render_view(AppState *st) {
  switch (st->view_mode) {
  case 0:
    render_cards(st, false, false);
    break;
  case 1:
    render_cards(st, true, false);
    break;
  case 2:
    render_linear(st, false);
    break;
  case 3:
    render_linear(st, true);
    break;
  case 4:
    render_cards(st, false, true);
    break;
  case 5:
    render_fs_grid(st);
    break;
  case 6:
    render_jigsaw(st, false);
    break;
  case 7:
    render_jigsaw(st, true);
    break;
  default:
    render_jigsaw(st, false);
    break;
  }
  render_title(st);
  render_frame_indicator(st);
}


// -------------------------------------------------------------------
// begin_transition: capture current frame, start crossfade to new_mode
// -------------------------------------------------------------------
static void begin_transition(AppState *st, int new_mode) {
  if (new_mode == st->view_mode) {
    return;
  }

  int win_w, win_h;
  SDL_GetRendererOutputSize(st->renderer, &win_w, &win_h);

  // destroy old prev_frame_tex if any
  if (st->prev_frame_tex) {
    SDL_DestroyTexture(st->prev_frame_tex);
    st->prev_frame_tex = NULL;
  }

  // create a render target texture to capture current frame
  SDL_Texture *capture = SDL_CreateTexture(st->renderer, SDL_PIXELFORMAT_RGBA8888, SDL_TEXTUREACCESS_TARGET, win_w, win_h);
  if (capture) {
    // render current view into the capture texture
    SDL_SetRenderTarget(st->renderer, capture);
    render_view(st);
    SDL_SetRenderTarget(st->renderer, NULL);
    st->prev_frame_tex = capture;
    SDL_SetTextureBlendMode(st->prev_frame_tex, SDL_BLENDMODE_BLEND);
  }

  st->prev_view_mode = st->view_mode;
  st->view_mode = new_mode;
  st->transition_alpha = 0.0f;
  st->transition_start = SDL_GetTicks();
  st->dirty = true;
}


// -------------------------------------------------------------------
// Main
// -------------------------------------------------------------------

int main(int argc, char *argv[]) {

  // disable color if not a terminal
  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  diskviz_logo();
  fprintf(stdout, DISKVIZ_BANNER_STRING);
  fprintf(stdout, "\n\n");
  fflush(stdout);

  if (argc < 2) {
    usage();
    fprintf(stderr, "%sERROR: No key file specified.%s\n", RED, BLACK);
    return 1;
  }

  AppState st = {0};
  st.hover_block = -1;
  st.view_mode = 0;
  st.prev_view_mode = 0;
  st.transition_alpha = 1.0f;  // no transition at start
  st.zoom = 1.0f;
  st.basedir[0] = '\0';
  st.max_files = INITIAL_FILES;
  st.files = calloc(st.max_files, sizeof(FileInfo));
  init_file_hash(&st);

  const char *keyfile = argv[1];
  for (int i = 2; i < argc - 1; i++) {
    if (! strcmp(argv[i], "-d")) {
      strncpy(st.basedir, argv[i + 1], MAX_PATH_LEN - 1);
      i++;
    }
  }

  if (! parse_keyfile(keyfile, &st)) {
    return 1;
  }

  // init SDL
  if (SDL_Init(SDL_INIT_VIDEO) < 0) {
    fprintf(stderr, "%sERROR: SDL_Init failed: %s%s\n", RED, SDL_GetError(), BLACK);
    return 1;
  }
  if (IMG_Init(IMG_INIT_PNG | IMG_INIT_JPG) == 0) {
    fprintf(stderr, "%sERROR: IMG_Init failed: %s%s\n", RED, IMG_GetError(), BLACK);
    return 1;
  }
  if (TTF_Init() < 0) {
    fprintf(stderr, "%sERROR: TTF_Init failed: %s%s\n", RED, TTF_GetError(), BLACK);
    return 1;
  }

  st.window = SDL_CreateWindow("diskviz - Disk Image Visualizer", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, INITIAL_WIN_W,
                               INITIAL_WIN_H, SDL_WINDOW_SHOWN | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
  if (! st.window) {
    fprintf(stderr, "%sERROR: SDL_CreateWindow failed: %s%s\n", RED, SDL_GetError(), BLACK);
    return 1;
  }

  st.renderer = SDL_CreateRenderer(st.window, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
  if (! st.renderer) {
    fprintf(stderr, "%sERROR: SDL_CreateRenderer failed: %s%s\n", RED, SDL_GetError(), BLACK);
    return 1;
  }
  SDL_SetRenderDrawBlendMode(st.renderer, SDL_BLENDMODE_BLEND);

  // load fonts -- try several common paths
  const char *font_paths[] = {"/Library/Fonts/Arial.ttf",
                              "/Library/Fonts/Helvetica.ttc",
                              "/System/Library/Fonts/Helvetica.ttc",
                              "/System/Library/Fonts/SFNSMono.ttf",
                              "/System/Library/Fonts/Monaco.ttf",
                              "/opt/local/share/fonts/dejavu/DejaVuSans.ttf",
                              "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                              NULL};
  for (int i = 0; font_paths[i]; i++) {
    st.font_tooltip = TTF_OpenFont(font_paths[i], TOOLTIP_FONT_SIZE);
    if (st.font_tooltip) {
      st.font_label = TTF_OpenFont(font_paths[i], LABEL_FONT_SIZE);
      st.font_medium = TTF_OpenFont(font_paths[i], MEDIUM_FONT_SIZE);
      st.font_title = TTF_OpenFont(font_paths[i], TITLE_FONT_SIZE);
      // font loaded successfully
      break;
    }
  }
  if (! st.font_tooltip) {
    fprintf(stderr, "%sERROR: No font found, tooltips/labels disabled.%s\n", RED, BLACK);
  }

  // load image files and create noise texture
  load_visual_files(&st);
  create_noise_texture(&st);

  // print interaction instructions to terminal
  fprintf(stdout, "\n");
  fprintf(stdout, "%sPress SPACEBAR or RIGHT ARROW to advance to next frame (8 frames total).%s\n", BLUE, BLACK);
  fprintf(stdout, "%sPress LEFT ARROW to go back.%s\n", BLUE, BLACK);
  fprintf(stdout, "%sPress 1-8 to jump to a specific frame.%s\n", BLUE, BLACK);
  fprintf(stdout, "%sPress + to zoom in, - to zoom out, 0 to reset zoom (block views only).%s\n", BLUE, BLACK);
  fprintf(stdout, "%sPress Q or ESC to quit.%s\n\n", BLUE, BLACK);

  // initial grid layout
  calc_grid(&st);

  // enable raw mode on terminal for key capture
  enable_raw_mode();

  // main loop
  bool quit = false;
  int prev_hover = -1;

  while (! quit) {
    SDL_Event ev;
    bool need_render = st.dirty;

    // update transition alpha
    if (st.transition_alpha < 1.0f) {
      float elapsed = (float)(SDL_GetTicks() - st.transition_start) / 500.0f;
      st.transition_alpha = elapsed > 1.0f ? 1.0f : elapsed;
      need_render = true;
    }

    while (SDL_PollEvent(&ev)) {
      switch (ev.type) {
      case SDL_QUIT:
        quit = true;
        break;

      case SDL_WINDOWEVENT:
        if (ev.window.event == SDL_WINDOWEVENT_RESIZED || ev.window.event == SDL_WINDOWEVENT_SIZE_CHANGED) {
          calc_grid(&st);
          need_render = true;
        }
        if (ev.window.event == SDL_WINDOWEVENT_EXPOSED) {
          need_render = true;
        }
        break;

      case SDL_MOUSEMOTION: {
        // only update hover in block-grid views (2, 3, 6, 7)
        if (st.view_mode == 2 || st.view_mode == 3 || st.view_mode == 6 || st.view_mode == 7) {
          int rw, rh, ww, wh;
          SDL_GetRendererOutputSize(st.renderer, &rw, &rh);
          SDL_GetWindowSize(st.window, &ww, &wh);
          float sx = (float)rw / ww, sy = (float)rh / wh;
          int mx = (int)(ev.motion.x * sx) - st.grid_x;
          int my = (int)(ev.motion.y * sy) - st.grid_y;
          int col = mx / st.cell_w;
          int row = (my + st.scroll_y) / st.cell_h;
          int idx = row * st.grid_cols + col;
          if (col >= 0 && col < st.grid_cols && idx >= 0 && idx < st.total_blocks) {
            st.hover_block = idx;
          }
          else {
            st.hover_block = -1;
          }
        }
        else {
          st.hover_block = -1;
        }
        if (st.hover_block != prev_hover) {
          need_render = true;
          prev_hover = st.hover_block;
        }
        break;
      }

      case SDL_MOUSEWHEEL: {
        // scroll only active in block-grid views
        if (st.view_mode == 2 || st.view_mode == 3 || st.view_mode == 6 || st.view_mode == 7) {
          int scroll_speed = st.cell_h * 3;
          st.scroll_y -= ev.wheel.y * scroll_speed;
          if (st.scroll_y < 0) {
            st.scroll_y = 0;
          }
          if (st.scroll_y > st.max_scroll_y) {
            st.scroll_y = st.max_scroll_y;
          }
          need_render = true;
        }
        break;
      }

      case SDL_KEYDOWN:
        if (ev.key.keysym.sym == SDLK_ESCAPE || ev.key.keysym.sym == SDLK_q) {
          quit = true;
        }
        else if (ev.key.keysym.sym == SDLK_SPACE || ev.key.keysym.sym == SDLK_RIGHT) {
          if (st.view_mode < 7) begin_transition(&st, st.view_mode + 1);
          need_render = true;
        }
        else if (ev.key.keysym.sym == SDLK_LEFT) {
          if (st.view_mode > 0) begin_transition(&st, st.view_mode - 1);
          need_render = true;
        }
        else if (ev.key.keysym.sym >= SDLK_1 && ev.key.keysym.sym <= SDLK_8) {
          int target = ev.key.keysym.sym - SDLK_1;
          begin_transition(&st, target);
          need_render = true;
        }
        else if (ev.key.keysym.sym == SDLK_EQUALS || ev.key.keysym.sym == SDLK_PLUS || ev.key.keysym.sym == SDLK_KP_PLUS) {
          if (st.view_mode == 2 || st.view_mode == 3 || st.view_mode == 6 || st.view_mode == 7) {
            st.zoom *= 1.25f;
            if (st.zoom > 8.0f) {
              st.zoom = 8.0f;
            }
            calc_grid(&st);
            need_render = true;
          }
        }
        else if (ev.key.keysym.sym == SDLK_MINUS || ev.key.keysym.sym == SDLK_KP_MINUS) {
          if (st.view_mode == 2 || st.view_mode == 3 || st.view_mode == 6 || st.view_mode == 7) {
            st.zoom /= 1.25f;
            if (st.zoom < 0.1f) {
              st.zoom = 0.1f;
            }
            calc_grid(&st);
            need_render = true;
          }
        }
        else if (ev.key.keysym.sym == SDLK_0 || ev.key.keysym.sym == SDLK_KP_0) {
          if (st.view_mode == 2 || st.view_mode == 3 || st.view_mode == 6 || st.view_mode == 7) {
            st.zoom = 1.0f;
            calc_grid(&st);
            need_render = true;
          }
        }
        break;
      }
    }

    // poll terminal stdin for key presses
    int tkey = read_terminal_key();
    if (tkey == 27 || tkey == 'q' || tkey == 'Q') {
      quit = true;
    }
    else if (tkey == ' ' || tkey == SDLK_RIGHT) {
      if (st.view_mode < 7) begin_transition(&st, st.view_mode + 1);
      need_render = true;
    }
    else if (tkey == SDLK_LEFT) {
      if (st.view_mode > 0) begin_transition(&st, st.view_mode - 1);
      need_render = true;
    }
    else if (tkey >= '1' && tkey <= '8') {
      begin_transition(&st, tkey - '1');
      need_render = true;
    }
    else if (tkey == '=' || tkey == '+') {
      if (st.view_mode == 2 || st.view_mode == 3 || st.view_mode == 6 || st.view_mode == 7) {
        st.zoom *= 1.25f;
        if (st.zoom > 8.0f) {
          st.zoom = 8.0f;
        }
        calc_grid(&st);
        need_render = true;
      }
    }
    else if (tkey == '-') {
      if (st.view_mode == 2 || st.view_mode == 3 || st.view_mode == 6 || st.view_mode == 7) {
        st.zoom /= 1.25f;
        if (st.zoom < 0.1f) {
          st.zoom = 0.1f;
        }
        calc_grid(&st);
        need_render = true;
      }
    }
    else if (tkey == '0') {
      if (st.view_mode == 2 || st.view_mode == 3 || st.view_mode == 6 || st.view_mode == 7) {
        st.zoom = 1.0f;
        calc_grid(&st);
        need_render = true;
      }
    }

    if (need_render) {
      // render new frame
      render_view(&st);

      // crossfade: if transition in progress, blend prev frame on top
      if (st.prev_frame_tex && st.transition_alpha < 1.0f) {
        Uint8 alpha = (Uint8)((1.0f - st.transition_alpha) * 255);
        SDL_SetTextureAlphaMod(st.prev_frame_tex, alpha);
        int win_w, win_h;
        SDL_GetRendererOutputSize(st.renderer, &win_w, &win_h);
        SDL_Rect full = {0, 0, win_w, win_h};
        SDL_RenderCopy(st.renderer, st.prev_frame_tex, NULL, &full);
      }
      else if (st.transition_alpha >= 1.0f && st.prev_frame_tex) {
        // transition complete, free prev texture
        SDL_DestroyTexture(st.prev_frame_tex);
        st.prev_frame_tex = NULL;
      }

      // render tooltip on top (block-grid views only)
      if ((st.view_mode == 2 || st.view_mode == 3 || st.view_mode == 6 || st.view_mode == 7) && st.hover_block >= 0) {
        int mx, my;
        SDL_GetMouseState(&mx, &my);
        // scale to renderer coords for HiDPI
        int rw, rh, ww, wh;
        SDL_GetRendererOutputSize(st.renderer, &rw, &rh);
        SDL_GetWindowSize(st.window, &ww, &wh);
        render_tooltip(&st, mx * rw / ww, my * rh / wh);
      }

      SDL_RenderPresent(st.renderer);
      st.dirty = false;
    }
    else {
      SDL_Delay(16);
    }
  }

  // restore terminal before cleanup
  restore_terminal();

  // cleanup
  for (int i = 0; i < st.num_files; i++) {
    if (st.files[i].texture) {
      SDL_DestroyTexture(st.files[i].texture);
    }
  }
  if (st.noise_tex) {
    SDL_DestroyTexture(st.noise_tex);
  }
  if (st.prev_frame_tex) {
    SDL_DestroyTexture(st.prev_frame_tex);
  }
  if (st.font_tooltip) {
    TTF_CloseFont(st.font_tooltip);
  }
  if (st.font_label) {
    TTF_CloseFont(st.font_label);
  }
  if (st.font_medium) {
    TTF_CloseFont(st.font_medium);
  }
  if (st.font_title) {
    TTF_CloseFont(st.font_title);
  }
  free(st.blocks);
  free(st.files);
  oa_hash_free(&st.file_hash);
  SDL_DestroyRenderer(st.renderer);
  SDL_DestroyWindow(st.window);
  TTF_Quit();
  IMG_Quit();
  SDL_Quit();

  return 0;
}
