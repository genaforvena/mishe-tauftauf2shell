// API-level probe against the real vtkDICOMItem object from the vulnerable
// build. NOT a wire/file path: the invalid-value deletes are direct calls.
#include "vtkDICOMItem.h"
#include "vtkDICOMValue.h"
#include <cstdio>

static vtkDICOMValue us(unsigned short v)
{
  return vtkDICOMValue(vtkDICOMVR::US, v);
}

int main()
{
  vtkDICOMItem item;
  for (int i = 1; i <= 4; ++i)
  {
    item.Set(vtkDICOMTag(0x0008, i), us(static_cast<unsigned short>(0x100 + i)));
  }
  item.Set(vtkDICOMTag(0x0008, 3), vtkDICOMValue()); // delete interior
  item.Set(vtkDICOMTag(0x0008, 5), us(0x105));
  item.Set(vtkDICOMTag(0x0008, 5), vtkDICOMValue()); // delete again
  item.Set(vtkDICOMTag(0x0008, 6), us(0x106));
  item.Set(vtkDICOMTag(0x0008, 7), us(0x107));
  item.Set(vtkDICOMTag(0x0008, 8), us(0x108)); // indexes slot 5 of 4
  std::printf("survived real item probe, count=%d\n", item.GetNumberOfDataElements());
  return 0;
}
