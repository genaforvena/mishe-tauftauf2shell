#line 631 "src/dissectors/ec_gg.c"
void gg_get_version(u_int32 version, char *str, size_t size)  {
   char buf[128];

   buf[0] = '\0';

switch ((version&0x00ff)) {

case 0x0000002A:
   strcpy(buf,"7.7");
   break;

case 0x00000029:
   strcpy(buf,"7.6");
   break;

case 0x00000024:
   strcpy(buf,"6.1/7.6");
   break;

case 0x00000028:
   strcpy(buf,"7.5");
   break;

case 0x00000027:
case 0x00000026:
case 0x00000025:
   strcpy(buf,"7.0");
   break;

case 0x00000022:
case 0x00000021:
case 0x00000020:
   strcpy(buf,"6.0");
   break;

case 0x0000001E:
case 0x0000001C:
   strcpy(buf,"5.7");
   break;

case 0x0000001B:
case 0x00000019:
   strcpy(buf,"5.0");
   break;

case 0x00000018:
   strcpy(buf,"5.0/4.9");
   break;

case 0x00000017:
case 0x00000016:
   strcpy(buf,"4.9");
   break;

case 0x00000015:
case 0x00000014:
   strcpy(buf,"4.8");
   break;

case 0x00000011:
   strcpy(buf,"4.6");
   break;

case 0x00000010:
case 0x0000000f:
   strcpy(buf,"4.5");
   break;

case 0x0000000b:
   strcpy(buf,"4.0");
   break;

default:
   sprintf(buf,"unknown (0x%X)",version);
}

if ((version&0xf0000000)==0x40000000)
   strcat(buf," + has audio");

if ((version&0x0f000000)== 0x04000000)
   strcat(buf," + eraomnix");

/* GHSA-vrjv-f8gv-2h35: the helper composes into an ample private buffer
 * and only ever hands the caller a bounded copy */
snprintf(str, size, "%s", buf);

}
