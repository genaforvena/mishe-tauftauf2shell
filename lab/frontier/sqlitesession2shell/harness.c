/* Frontier harness for CVE-2026-119379 (SQLite Session sessionUpdateFind).
 *
 * Applies a fixed 242-byte changeset that reuses table "t" with nCol=64
 * after a first block with nCol=2. The bytes are the verbatim fixture from
 * the upstream fix commit's ext/session/sessioncorrupt.test, pinned in
 * pins/changeset-trigger.bin. pins/changeset-control.bin is its first
 * 28 bytes (one ordinary nCol=2 UPDATE).
 *
 * The DB setup, conflict handler and sqlite3changeset_apply() call follow
 * the published PoC pins/poc/poc.c. No upstream SQLite source is edited.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sqlite3.h"

#ifndef SQLITE_ENABLE_SESSION
#error "SQLITE_ENABLE_SESSION is required"
#endif

static const char *fixture_path(const char *mode){
  if( strcmp(mode, "trigger")==0 ) return "pins/changeset-trigger.bin";
  if( strcmp(mode, "control")==0 ) return "pins/changeset-control.bin";
  return 0;
}

static unsigned char *read_file(const char *zPath, int *pnByte){
  FILE *f = fopen(zPath, "rb");
  unsigned char *a = 0;
  long n;
  if( f==0 ) return 0;
  if( fseek(f, 0, SEEK_END)!=0 ){ fclose(f); return 0; }
  n = ftell(f);
  if( n<0 || n>4096 || fseek(f, 0, SEEK_SET)!=0 ){ fclose(f); return 0; }
  a = (unsigned char*)malloc((size_t)n ? (size_t)n : 1);
  if( a==0 || fread(a, 1, (size_t)n, f)!=(size_t)n ){
    free(a); fclose(f); return 0;
  }
  fclose(f);
  *pnByte = (int)n;
  return a;
}

static int conflict_cb(void *pCtx, int eConflict, sqlite3_changeset_iter *pIt){
  (void)pCtx; (void)eConflict; (void)pIt;
  return SQLITE_CHANGESET_OMIT;
}

int main(int argc, char **argv){
  const char *zMode = (argc>1) ? argv[1] : "trigger";
  const char *zPath;
  unsigned char *aChange;
  int nChange = 0;
  sqlite3 *db = 0;
  int rc;
  int applyRc;

  printf("label=sqlite-session-ncol\n");
  printf("witness=SQLITE-SESSION-NCOL-WITNESS\n");
  printf("version=%s\n", sqlite3_libversion());
  printf("source-id=%s\n", sqlite3_sourceid());
  printf("mode=%s\n", zMode);
  fflush(stdout);

  if( strcmp(zMode,"version")==0 ) return 0;
  zPath = fixture_path(zMode);
  if( zPath==0 ){
    fprintf(stderr, "usage: harness [version|control|trigger]\n");
    return 2;
  }
  aChange = read_file(zPath, &nChange);
  if( aChange==0 ){
    fprintf(stderr, "cannot read fixture %s\n", zPath);
    return 2;
  }
  printf("fixture=%s n-changeset=%d first-nCol=2 second-nCol=%d\n",
         zPath, nChange, nChange==242 ? 64 : 2);
  fflush(stdout);

  rc = sqlite3_open(":memory:", &db);
  if( rc!=SQLITE_OK ){
    fprintf(stderr, "open-rc=%d\n", rc);
    free(aChange);
    return 2;
  }
  rc = sqlite3_exec(db,
      "CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT);"
      "INSERT INTO t VALUES(1, 'old');", 0, 0, 0);
  if( rc!=SQLITE_OK ){
    fprintf(stderr, "exec-rc=%d\n", rc);
    sqlite3_close(db);
    free(aChange);
    return 2;
  }
  applyRc = sqlite3changeset_apply(db, nChange, (void*)aChange, 0,
                                   conflict_cb, 0);
  printf("apply-rc=%d\n", applyRc);
  fflush(stdout);
  sqlite3_close(db);
  free(aChange);
  return applyRc==SQLITE_OK ? 0 : 1;
}
