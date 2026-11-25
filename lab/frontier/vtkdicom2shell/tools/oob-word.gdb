set pagination off
set confirm off
break vtkDICOMItem.cxx:195
commands
silent
if this->L->NumberOfDataElements >= 5 && e == this->L->DataElements + 5
printf "OOBPRE n=%d store=%p e=%p slot=%ld tag=%04x,%04x\n", this->L->NumberOfDataElements, (void*)this->L->DataElements, (void*)e, (long)(e-this->L->DataElements), tag.GetGroup(), tag.GetElement()
printf "OOBWORD e+0=%016lx e+8(V)=%016lx\n", *(unsigned long*)e, *(unsigned long*)((char*)e+8)
end
continue
end
