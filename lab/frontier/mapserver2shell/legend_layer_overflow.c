/* Extracted, source-bound harness for CVE-2026-77326 / GHSA-4mwc-qc95-5959.
 *
 * Models the two 100-entry cgiRequestObj arrays allocated by msAllocCgiObj
 * (cgiutil.c:493-503, rel-8-6-4) and the GetLegendGraphic LAYER->LAYERS append
 * loop in msWMSDispatch (mapwms.cpp:5989-5995, rel-8-6-4). Only the parameter
 * table and the dispatch branch are reproduced; map rendering, GDAL and HTTP
 * are deliberately out of scope. No network activity of any kind.
 *
 * Layout note: rung1/rung3 allocate EXACTLY 100*sizeof(char*) per array, as
 * upstream does, so ASan sees the real allocation boundary. Rung2/rung4 use
 * a physically longer allocation with the same logical capacity 100 so that
 * canary stamps and pointer slots beyond the logical capacity can be read
 * back; the write extent and the vulnerable loop are identical. This is the
 * same canary-vs-ASan detector split used by the Brotli frontier harness.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define MS_DEFAULT_CGI_PARAMS 100
#define BASE_PARAMS 4
#define PHYSICAL_SLOTS 700

typedef struct {
  char **ParamNames;
  char **ParamValues;
  int NumParams;
} cgiRequestObj;

typedef struct {
  cgiRequestObj *req;
  int logical_cap;   /* loadParams' local maxParams, lost on return */
  int physical_slots;
} harness_request;

static char *xstrdup(const char *s) {
  char *p = strdup(s);
  if (!p) {
    fprintf(stderr, "xstrdup: out of memory\n");
    exit(2);
  }
  return p;
}

/* cgiutil.c:493-503 + cgiutil.c:131-226: two independent allocations, initial
 * capacity 100, doubled in loadParams when the parsed count crosses it. */
static harness_request *build_request(int K, int exact, const char *layer_value) {
  int parsed = K + BASE_PARAMS;
  int cap = MS_DEFAULT_CGI_PARAMS;
  while (parsed > cap)
    cap *= 2;
  int phys = exact ? cap : PHYSICAL_SLOTS;
  if (phys < cap)
    phys = cap;

  harness_request *h = calloc(1, sizeof(*h));
  h->req = calloc(1, sizeof(cgiRequestObj));
  h->logical_cap = cap;
  h->physical_slots = phys;
  h->req->ParamNames = malloc((size_t)phys * sizeof(char *));
  h->req->ParamValues = malloc((size_t)phys * sizeof(char *));
  if (!h->req || !h->req->ParamNames || !h->req->ParamValues) {
    fprintf(stderr, "build_request: out of memory\n");
    exit(2);
  }
  memset(h->req->ParamNames, 0, (size_t)phys * sizeof(char *));
  memset(h->req->ParamValues, 0, (size_t)phys * sizeof(char *));

  const char *base_names[BASE_PARAMS] = {"SERVICE", "VERSION", "REQUEST", "BBOX"};
  const char *base_values[BASE_PARAMS] = {"WMS", "1.1.0", "GetLegendGraphic",
                                          "0,0,1,1"};
  for (int j = 0; j < BASE_PARAMS; j++) {
    int m = h->req->NumParams++;
    h->req->ParamNames[m] = xstrdup(base_names[j]);
    h->req->ParamValues[m] = xstrdup(base_values[j]);
  }
  for (int k = 0; k < K; k++) {
    int m = h->req->NumParams++;
    h->req->ParamNames[m] = xstrdup("LAYER");
    h->req->ParamValues[m] = xstrdup(layer_value);
  }
  return h;
}

/* mapwms.cpp:5989-5995 (vulnerable) / rel-8-6-5:5987-5989 (fixed).
 * oob_appends counts writes at index >= logical_cap; each append writes both
 * arrays, hence oob_writes = 2 * oob_appends. */
static int wms_dispatch_legend(harness_request *h, int fixed,
                               int *oob_appends, int *first, int *last) {
  cgiRequestObj *req = h->req;
  const char *request = NULL;
  int found_bbox = 0;
  for (int i = 0; i < req->NumParams; i++) {
    if (strcasecmp(req->ParamNames[i], "REQUEST") == 0)
      request = req->ParamValues[i];
    if (strcasecmp(req->ParamNames[i], "BBOX") == 0 && req->ParamValues[i] &&
        *req->ParamValues[i])
      found_bbox = 1;
  }
  if (!request || strcasecmp(request, "GetLegendGraphic") != 0 || !found_bbox)
    return -1;

  if (!fixed) {
    for (int i = 0; i < req->NumParams; i++) {
      if (strcasecmp(req->ParamNames[i], "LAYER") == 0) {
        int idx = req->NumParams;
        /* No guard: at index >= logical_cap this is the upstream OOB write. */
        req->ParamNames[idx] = xstrdup("LAYERS");
        req->ParamValues[idx] = xstrdup(req->ParamValues[i]);
        if (idx >= h->logical_cap) {
          if (*oob_appends == 0)
            *first = idx;
          *last = idx;
          (*oob_appends)++;
        }
        req->NumParams++;
      }
    }
  }
  return 0;
}

/* rel-8-6-4 mapwms.cpp:1023 checks "LAYERS"; rel-8-6-5 mapwms.cpp:1018-1026
 * selects "LAYER" for GetLegendGraphic. Both see K layer entries after the
 * respective dispatch path, which is the functional equivalence control. */
static int load_getmap_layers(harness_request *h, int fixed) {
  const char *key = (fixed && h->req->ParamValues &&
                     strcasecmp(h->req->ParamValues[2], "GetLegendGraphic") == 0)
                        ? "LAYER"
                        : "LAYERS";
  int seen = 0;
  for (int i = 0; i < h->req->NumParams; i++)
    if (strcasecmp(h->req->ParamNames[i], key) == 0)
      seen++;
  return seen;
}

static void dump_hex(const char *label, const char *s) {
  printf("%s=", label);
  const unsigned char *p = (const unsigned char *)s;
  for (; *p; p++)
    printf(p == (const unsigned char *)s ? "%02x" : " %02x", *p);
}

static void mode_rung1(void) {
  harness_request *h = build_request(95, 1, "payload");
  int oob = 0, first = -1, last = -1;
  int rc = wms_dispatch_legend(h, 0, &oob, &first, &last);
  int layers = load_getmap_layers(h, 0);
  printf("mode=rung1 rc=%d K=95 parsed=99 logical_cap=100 oob_appends=%d "
         "oob_writes=%d first_oob=%d last_oob=%d layers_seen=%d verdict=%s\n",
         rc, oob, 2 * oob, first, last, layers,
         (rc == 0 && oob == 94 && first == 100 && last == 193 && layers == 95)
             ? "TRIGGER"
             : "UNEXPECTED");
}

static void mode_rung2(void) {
  const int Ks[] = {95, 96, 97, 195, 196, 197};
  printf("mode=rung2\n");
  for (unsigned j = 0; j < sizeof(Ks) / sizeof(Ks[0]); j++) {
    int K = Ks[j];
    harness_request *h = build_request(K, 0, "payload");
    int cap = h->logical_cap;
    int sa = cap + 20, sb = cap + 120;
    char *mark_a = xstrdup("STAMP_A");
    char *mark_b = xstrdup("STAMP_B");
    h->req->ParamNames[sa] = h->req->ParamValues[sa] = mark_a;
    h->req->ParamNames[sb] = h->req->ParamValues[sb] = mark_b;
    int oob = 0, first = -1, last = -1;
    int rc = wms_dispatch_legend(h, 0, &oob, &first, &last);
    int a_hit = (h->req->ParamValues[sa] != mark_a);
    int b_hit = (h->req->ParamValues[sb] != mark_b);
    printf("K=%d parsed=%d cap=%d final=%d oob_appends=%d oob_writes=%d "
           "stampA_clobbered=%d stampB_clobbered=%d rc=%d\n",
           K, K + BASE_PARAMS, cap, h->req->NumParams, oob, 2 * oob, a_hit,
           b_hit, rc);
  }
  printf("verdict=LAYER_COUNT_CONTROL_OBSERVED\n");
}

static void mode_rung3(void) {
  printf("mode=rung3 K=95 logical_cap=100 exact_allocation=800_bytes\n");
  fflush(stdout);
  harness_request *h = build_request(95, 1, "payload");
  int oob = 0, first = -1, last = -1;
  wms_dispatch_legend(h, 0, &oob, &first, &last);
  printf("UNEXPECTED_NO_FAULT oob_writes=%d\n", 2 * oob);
}

static void mode_rung4(void) {
  const char payload[] = "DEADBEEFCAFEBABE";
  const int slots[3] = {110, 150, 190};
  harness_request *h = build_request(95, 0, payload);
  int oob = 0, first = -1, last = -1;
  int rc = wms_dispatch_legend(h, 0, &oob, &first, &last);
  int exact = 1;
  printf("mode=rung4 rc=%d K=95 logical_cap=100 oob_writes=%d payload=%s\n",
         rc, 2 * oob, payload);
  for (unsigned j = 0; j < sizeof(slots) / sizeof(slots[0]); j++) {
    int s = slots[j];
    char *v = h->req->ParamValues[s];
    int ok = v && strcmp(v, payload) == 0;
    if (!ok)
      exact = 0;
    printf("slot=%d byte_offset=%d %s", s, s * (int)sizeof(char *),
           ok ? "value=" : "value=UNREADABLE ");
    if (ok)
      dump_hex("bytes", v);
    printf("\n");
  }
  printf("chosen_bytes_written=%d offsets_exact=%d value_source=layer_query_values "
         "verdict=%s\n",
         exact ? 3 * (int)sizeof(payload) - 3 : 0, exact,
         exact ? "CHOSEN_BYTES_AT_CHOSEN_OFFSETS" : "UNEXPECTED");
}

static void mode_fixed(void) {
  harness_request *h = build_request(95, 0, "payload");
  int cap = h->logical_cap;
  int sa = cap + 20, sb = cap + 120;
  char *mark_a = xstrdup("STAMP_A");
  char *mark_b = xstrdup("STAMP_B");
  h->req->ParamNames[sa] = h->req->ParamValues[sa] = mark_a;
  h->req->ParamNames[sb] = h->req->ParamValues[sb] = mark_b;
  int oob = 0, first = -1, last = -1;
  int rc = wms_dispatch_legend(h, 1, &oob, &first, &last);
  int layers = load_getmap_layers(h, 1);
  int intact = (h->req->ParamValues[sa] == mark_a && h->req->ParamValues[sb] == mark_b);
  printf("mode=fixed rc=%d K=95 logical_cap=%d oob_writes=%d layers_seen=%d "
         "stamps_intact=%d verdict=%s\n",
         rc, cap, 2 * oob, layers, intact ? 2 : 0,
         (rc == 0 && oob == 0 && layers == 95 && intact) ? "PASS" : "UNEXPECTED");
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s rung1|rung2|rung3|rung4|fixed\n", argv[0]);
    return 2;
  }
  if (strcmp(argv[1], "rung1") == 0)
    mode_rung1();
  else if (strcmp(argv[1], "rung2") == 0)
    mode_rung2();
  else if (strcmp(argv[1], "rung3") == 0)
    mode_rung3();
  else if (strcmp(argv[1], "rung4") == 0)
    mode_rung4();
  else if (strcmp(argv[1], "fixed") == 0)
    mode_fixed();
  else {
    fprintf(stderr, "unknown mode %s\n", argv[1]);
    return 2;
  }
  return 0;
}
