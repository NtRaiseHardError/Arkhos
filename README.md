# Arkhos

## File Infecting Binder

----

### How To Compile:

#### Shellcode Executable

Using GCC to compile `shellcode.c` to object code:

```
gcc -c shellcode.c
```

Using NASM to compile `shellcode.asm` to object code:

```
nasm -fwin32 -o shell.o shellcode.asm
```

Using ld to link the files:

```
ld -s -o shellcode.exe shell.o shellcode.o
```

#### Arkhos Executable

Use MSVC++ ;-)

----

## TODO:

1. Remove redundant `PAYLOAD` string
2. Clean up Binder::Bind function
3. Fix GUI code

----

## Improvements:

* Add payload obfuscation - compression and encryption (in this order)
* Remove error checking for smaller shellcode size? (is this significant enough?)