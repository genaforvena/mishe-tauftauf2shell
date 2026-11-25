// Verbatim extraction from upstream Source/vtkDICOMItem.cxx (bcc8b26)
vtkDICOMDataElement *vtkDICOMItem::NewDataElement(vtkDICOMDataElement **iter)
{
  int n = this->L->DataElementStoreCount++;

  // if no data elements yet, then allocate four
  if (n == 0)
  {
    this->L->DataElementStore = new vtkDICOMDataElement[4];
  }
  // if n is a power of two, double allocated space
  else if (n >= 4 && (n & (n-1)) == 0)
  {
    // but first check if a free element exists
    int m = n;
    do { --m; } while (m > 0 && this->L->DataElementStore[m].Next != nullptr);

    if (this->L->DataElementStore[m].Next == nullptr)
    {
      // don't increase count, use the free slot that we found
      this->L->DataElementStoreCount--;
      n = m;
    }
    else
    {
      // more space is needed, so double the allocation
      vtkDICOMDataElement *oldptr = this->L->DataElementStore;
      this->L->DataElementStore = new vtkDICOMDataElement[2*n];
      vtkDICOMItem::CopyDataElements(
        this->L->Head.Next, &this->L->Tail, this->L);
      if (iter)
      {
        // fix the address of the provided node, since it was re-alloced
        vtkDICOMDataElement *tptr = *iter;
        vtkDICOMDataElement *nptr = &this->L->Tail;
        do { tptr = tptr->Next; nptr = nptr->Prev; }
        while (tptr != &this->L->Tail);
        *iter = nptr;
      }
      delete [] oldptr;
    }
  }

  return &this->L->DataElementStore[n];
}
void vtkDICOMItem::FreeList()
{
  delete [] this->L->DataElementStore;
  delete this->L;
  this->L = nullptr;
}
void vtkDICOMItem::CopyList(const List *o, List *t)
{
  t->NumberOfDataElements = o->NumberOfDataElements;
  t->DataElementStore = nullptr;
  t->DataElementStoreCount = o->NumberOfDataElements;
  t->ByteOffset = o->ByteOffset;
  t->Delimited = o->Delimited;
  t->CharacterSet = o->CharacterSet;
  t->VRForXS = o->VRForXS;
  t->Head.Next = &t->Tail;
  t->Tail.Prev = &t->Head;

  int n = o->NumberOfDataElements;
  if (n > 0)
  {
    // round up to power of two
    int m = n - 1;
    m |= m >> 1;
    m |= m >> 2;
    m |= m >> 4;
    m |= m >> 8;
    m |= m >> 16;
    m += 1;

    // allocate a minimum of 4 elements
    if (m < 4) { m = 4; }
    t->DataElementStore = new vtkDICOMDataElement[m];
    vtkDICOMItem::CopyDataElements(o->Head.Next, &o->Tail, t);
  }
}
void vtkDICOMItem::CopyDataElements(
  const vtkDICOMDataElement *begin, const vtkDICOMDataElement *end, List *t)
{
  vtkDICOMDataElement *e = t->DataElementStore;
  t->Head.Next = e;

  const vtkDICOMDataElement *ptr = begin;
  while (ptr != end)
  {
    e->Tag = ptr->Tag;
    e->Value = ptr->Value;
    e->Next = e + 1;
    e->Prev = e - 1;
    ptr = ptr->Next;
    e++;
  }

  t->Tail.Prev = e - 1;
  t->Head.Next->Prev = &t->Head;
  t->Tail.Prev->Next = &t->Tail;
}
vtkDICOMDataElement *vtkDICOMItem::FindDataElementOrInsert(vtkDICOMTag tag)
{
  // make a container if we don't have one yet
  if (this->L == nullptr)
  {
    this->L = new List;
    this->L->Head.Next = &this->L->Tail;
    this->L->Tail.Prev = &this->L->Head;
  }
  // if we aren't the sole owner, copy before modifying
  else if (this->L->ReferenceCount != 1)
  {
    List *t = new List;
    vtkDICOMItem::CopyList(this->L, t);
    this->Clear();
    this->L = t;
  }

  // find the insert location in the linked list
  vtkDICOMDataElement *tptr = &this->L->Tail;
  do
  {
    tptr = tptr->Prev;
  }
  while (tag < tptr->GetTag());

  if (tag != tptr->GetTag())
  {
    // create a new data element
    vtkDICOMDataElement *e = this->NewDataElement(&tptr);
    e->Tag = tag;
    e->Prev = tptr;
    e->Next = tptr->Next;
    e->Prev->Next = e;
    e->Next->Prev = e;

    tptr = e;
    this->L->NumberOfDataElements++;
  }

  return tptr;
}
void vtkDICOMItem::Set(vtkDICOMTag tag, const vtkDICOMValue& v)
{
  vtkDICOMDataElement *tptr = this->FindDataElementOrInsert(tag);

  tptr->Value = v;

  if (!v.IsValid())
  {
    // setting a value to the invalid value causes deletion
    tptr->Prev->Next = tptr->Next;
    tptr->Next->Prev = tptr->Prev;
    tptr->Next = nullptr;
    tptr->Prev = nullptr;
    this->L->NumberOfDataElements--;
  }
}
