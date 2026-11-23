#line 307 "s7_micro_client.cpp.30f37da"
int TSnap7MicroClient::opReadMultiVars()
{
    PS7DataItem       Item;
    PReqFunReadParams ReqParams;
    PS7ResHeader23    Answer;
    PResFunReadParams ResParams;
    TResFunReadData   ResData;

    word       RPSize; // ReqParams size
    uintptr_t  Offset =0 ;
    word       Slice;
    longword   Address;
    int        IsoSize;
    pbyte      P;
    int        ItemsCount, c, Result;

    Item       = PS7DataItem(Job.pData);
    ItemsCount = Job.Amount;

    // Some useful initial check to detail the errors (Since S7 CPU always answers
    // with $05 if (something is wrong in params)
    if (ItemsCount>MaxVars)
    	return errCliTooManyItems;

    // Adjusts Word Length in case of timers and counters and clears results
    for (c = 0; c < ItemsCount; c++)
    {
    	Item->Result=0;
        if (Item->Area==S7AreaCT)
          Item->WordLen=S7WLCounter;
        if (Item->Area==S7AreaTM)
          Item->WordLen=S7WLTimer;
        Item++;
    };

    // Let's build the PDU
    RPSize    = word(2 + ItemsCount * sizeof(TReqFunReadItem));
    ReqParams = PReqFunReadParams(pbyte(PDUH_out)+sizeof(TS7ReqHeader));
    Answer    = PS7ResHeader23(&PDU.Payload);
    ResParams = PResFunReadParams(pbyte(Answer)+ResHeaderSize23);
    // Fill Header
    PDUH_out->P=0x32;                    // Always 0x32
    PDUH_out->PDUType=PduType_request;   // 0x01
    PDUH_out->AB_EX=0x0000;              // Always 0x0000
    PDUH_out->Sequence=GetNextWord();    // AutoInc
    PDUH_out->ParLen=SwapWord(RPSize);   // Request params size
    PDUH_out->DataLen=0x0000;            // No data in output

    // Fill Params
    ReqParams->FunRead=pduFuncRead;      // 0x04
    ReqParams->ItemsCount=ItemsCount;

    Item = PS7DataItem(Job.pData);
    for (c = 0; c < ItemsCount; c++)
    {
        ReqParams->Items[c].ItemHead[0]=0x12;
        ReqParams->Items[c].ItemHead[1]=0x0A;
        ReqParams->Items[c].ItemHead[2]=0x10;

        ReqParams->Items[c].TransportSize=Item->WordLen;
        ReqParams->Items[c].Length=SwapWord(Item->Amount);
        ReqParams->Items[c].Area=Item->Area;
        // Automatically drops DBNumber if (Area is not DB
        if (Item->Area==S7AreaDB)
	        ReqParams->Items[c].DBNumber=SwapWord(Item->DBNumber);
        else
    	    ReqParams->Items[c].DBNumber=0x0000;
        // Adjusts the offset
        if ((Item->WordLen==S7WLBit) || (Item->WordLen==S7WLCounter) || (Item->WordLen==S7WLTimer))
        	Address=Item->Start;
        else
        	Address=Item->Start*8;
        // Builds the offset
        ReqParams->Items[c].Address[2]=Address & 0x000000FF;
        Address=Address >> 8;
        ReqParams->Items[c].Address[1]=Address & 0x000000FF;
        Address=Address >> 8;
        ReqParams->Items[c].Address[0]=Address & 0x000000FF;
        Item++;
    };

    IsoSize=RPSize+sizeof(TS7ReqHeader);
	if (IsoSize>PDULength) 
		return errCliSizeOverPDU;
	Result=isoExchangeBuffer(0,IsoSize);

	if (Result!=0)
        return Result;

    // Function level error
    if (Answer->Error!=0)
    	return CpuError(SwapWord(Answer->Error));

    if (ResParams->ItemCount!=ItemsCount)
    	return errCliInvalidPlcAnswer;

    P=pbyte(ResParams)+sizeof(TResFunReadParams);
    Item = PS7DataItem(Job.pData);
    for (c = 0; c < ItemsCount; c++)
    {
        ResData[c] =PResFunReadItem(pbyte(P)+Offset);
        Slice=0;
        // Item level error
        if (ResData[c]->ReturnCode==0xFF) // <-- 0xFF means Result OK
        {
          // Calcs data size in bytes
          Slice=SwapWord(ResData[c]->DataLength);
          // Adjust Size in accord of TransportSize
          if ((ResData[c]->TransportSize != TS_ResOctet) && (ResData[c]->TransportSize != TS_ResReal) && (ResData[c]->TransportSize != TS_ResBit))
            Slice=Slice >> 3;

		  memcpy(Item->pdata, ResData[c]->Data, Slice);
          Item->Result=0;
        }
        else
          Item->Result=CpuError(ResData[c]->ReturnCode);

        if ((Slice % 2)!=0)
        	Slice++; // Skip fill byte for Odd frame

        Offset+=(4+Slice);
        Item++;
    };
    return Result;
}
