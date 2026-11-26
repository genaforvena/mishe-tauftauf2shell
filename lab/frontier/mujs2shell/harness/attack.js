// Inflate a simple array's logical length without extending its flat storage.
var a = [3, 1, 2];
a.length = 1000;
a.sort();
print("sorted-length=" + a.length);
