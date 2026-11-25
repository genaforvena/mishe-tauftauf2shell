// Advisory-shaped reader probe: a live vtkDICOMReader reads a DICOM file,
// mirroring the Talos dicom2vtk.cpp harness. Local lab use only.
#include "vtkDICOMReader.h"
#include "vtkSmartPointer.h"
#include <cstdio>

int main(int argc, char **argv)
{
  if (argc < 2) { return 2; }
  vtkSmartPointer<vtkDICOMReader> reader = vtkSmartPointer<vtkDICOMReader>::New();
  reader->SetFileName(argv[1]);
  reader->Update();
  std::printf("reader Update completed: %s\n", argv[1]);
  return 0;
}
