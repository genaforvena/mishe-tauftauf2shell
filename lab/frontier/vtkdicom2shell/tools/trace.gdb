set pagination off
set confirm off
break vtkDICOMItem::NewDataElement
commands
silent
printf "NewDataElement n=%d ptr=%p\n", this->L->NumberOfDataElements, (void*)this->L->DataElements
continue
end
break vtkDICOMItem::Set(vtkDICOMTag, vtkDICOMValue const&)
commands
silent
printf "Set tag=%04x,%04x valid=%d n=%d\n", tag.GetGroup(), tag.GetElement(), (int)v.IsValid(), this->L ? this->L->NumberOfDataElements : -1
continue
end
run
quit
