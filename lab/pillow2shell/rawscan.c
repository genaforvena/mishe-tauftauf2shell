#include <stdio.h>
#include <stdlib.h>
#include <jpeglib.h>
int main(int argc, char**argv){
  FILE*f=fopen(argv[1],"rb"); struct jpeg_decompress_struct c; struct jpeg_error_mgr e;
  c.err=jpeg_std_error(&e); jpeg_create_decompress(&c); jpeg_stdio_src(&c,f);
  jpeg_read_header(&c,TRUE);
  printf("jpeg_color_space=%d num_components=%d\n",c.jpeg_color_space,c.num_components);
  c.jpeg_color_space=JCS_UNKNOWN; c.out_color_space=JCS_UNKNOWN; jpeg_start_decompress(&c);
  printf("output_width=%u output_components=%d\n",c.output_width,c.output_components);
  JSAMPROW row=malloc(c.output_width*c.output_components);
  jpeg_read_scanlines(&c,&row,1);
  printf("RAW:"); for(int i=0;i<32;i++) printf(" %02x",row[i]); printf("\n");
  printf("RAW48_72:"); for(int i=48;i<72;i++) printf(" %02x",row[i]); printf("\n");
  return 0;
}
