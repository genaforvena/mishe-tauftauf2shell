set pagination off
set confirm off
break vtkDICOMItem.cxx:195
commands
silent
printf "OOBWRITE tag=%04x,%04x key=%08x n=%d store=%p e=%p slot=%ld\n", tag.GetGroup(), tag.GetElement(), (tag.GetGroup()<<16)|tag.GetElement(), this->L->NumberOfDataElements, (void*)this->L->DataElements, (void*)e, (long)(e-this->L->DataElements)
continue
end
run evidence/undef-ob-chosen.dcm
quit
