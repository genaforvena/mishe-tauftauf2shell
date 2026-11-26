// Safe control: shrink then read only live slots; no regrow or push.
const a = [1, 2, 3];
a.length = 2;
print(a.length);
print(JSON.stringify(a));
