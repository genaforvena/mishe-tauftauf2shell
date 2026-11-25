// Stand-ins for vtkDICOM dependencies. The vulnerable/fixed logic in
// pinned.inc is copied verbatim from Source/vtkDICOMItem.cxx at the two
// pinned commits; only the dependency classes are stand-ins.
#ifndef MISHE_VTKDICOM_COMMON_H
#define MISHE_VTKDICOM_COMMON_H
#include <cstdint>
#include <cstdio>

struct vtkDICOMTag {
  unsigned int Key;
  vtkDICOMTag() : Key(0) {}
  vtkDICOMTag(int group, int element) : Key((unsigned(group) << 16) | unsigned(element)) {}
  unsigned short GetGroup() const { return Key >> 16; }
  unsigned short GetElement() const { return Key & 0xffffu; }
};
inline bool operator<(const vtkDICOMTag& a, const vtkDICOMTag& b) { return a.Key < b.Key; }
inline bool operator==(const vtkDICOMTag& a, const vtkDICOMTag& b) { return a.Key == b.Key; }
inline bool operator!=(const vtkDICOMTag& a, const vtkDICOMTag& b) { return a.Key != b.Key; }

struct vtkDICOMVR { int dummy; };
struct vtkDICOMCharacterSet { int dummy; };
struct vtkDICOMDictEntry { int dummy; };

struct vtkDICOMValue {
  bool Valid;
  uint32_t Payload;
  vtkDICOMValue() : Valid(false), Payload(0) {}
  vtkDICOMValue(uint32_t p) : Valid(true), Payload(p) {}
  bool IsValid() const { return Valid; }
  vtkDICOMValue& operator=(const vtkDICOMValue& o) { Valid=o.Valid; Payload=o.Payload; return *this; }
};

struct vtkDICOMDataElement {
  vtkDICOMTag Tag;
  vtkDICOMValue Value;
  vtkDICOMDataElement *Next;
  vtkDICOMDataElement *Prev;
  vtkDICOMDataElement() : Next(nullptr), Prev(nullptr) {}
  vtkDICOMTag GetTag() const { return Tag; }
};

class vtkDICOMItem {
private:
  struct List {
    vtkDICOMDataElement Head;
    vtkDICOMDataElement Tail;
    int ReferenceCount;
    int NumberOfDataElements;
#ifdef FIXED
    vtkDICOMDataElement *DataElementStore;
    int DataElementStoreCount;
#else
    vtkDICOMDataElement *DataElements;
#endif
    unsigned int ByteOffset;
    bool Delimited;
    vtkDICOMCharacterSet CharacterSet;
    vtkDICOMVR VRForXS;
    List() : ReferenceCount(1), NumberOfDataElements(0),
#ifdef FIXED
             DataElementStore(nullptr), DataElementStoreCount(0),
#else
             DataElements(nullptr),
#endif
             ByteOffset(0), Delimited(false) {}
  };
  List *L;
public:
  vtkDICOMItem() : L(nullptr) {}
  ~vtkDICOMItem() { this->Clear(); }
  void Clear() {
    if (this->L && --(this->L->ReferenceCount) == 0) { this->FreeList(); }
    else { this->L = nullptr; }
  }
  int Count() const { return L ? L->NumberOfDataElements : 0; }
  uintptr_t StoreAddr() const {
#ifdef FIXED
    return L ? reinterpret_cast<uintptr_t>(L->DataElementStore) : 0;
#else
    return L ? reinterpret_cast<uintptr_t>(L->DataElements) : 0;
#endif
  }
  vtkDICOMDataElement *FindDataElementOrInsert(vtkDICOMTag tag);
  void Set(vtkDICOMTag tag, const vtkDICOMValue& v);
  void FreeList();
  void CopyList(const List *o, List *t);
  void CopyDataElements(const vtkDICOMDataElement *begin,
                        const vtkDICOMDataElement *end, List *t);
  vtkDICOMDataElement *NewDataElement(vtkDICOMDataElement **iter);
};
#endif
