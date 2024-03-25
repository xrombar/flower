# README

```c
/*!
 *
 * FLOWER
 *
 * flowing sleep obfuscation 
 *
 * bakki - sillywa.re
 *
!*/

```

This is a primitive implementation of the technique I discuss in my blogpost @ https://sillywa.re/posts/flower-da-flowin-shc, for any technical explanation, caveats or IOCs, do give it a read.

A version of this that does not rely on any external technique to queue the ropchain will be made available.

## FLAGS

To showcase the compatibility of this technique, several flags are made available for the user

### techniques

Self explanatory, specifies which technique you wish to use to queue the ropchain
```c
FLOWER_EKKO_OBF
FLOWER_FOLIAGE_OBF
FLOWER_ZILEAN_OBF
```

### zero

Freeing the old region means a copy of our shellcode is still there for as long as the old region does not get used. Considering changing the protection back to RW has, at this time, no perceivable caveats stealth wise; I added the option to zero out the old region before freeing it.

```c
FLOWER_ZERO_PROTECT
```
### jop

Using jump gadgets is nowadays the preferred way to evade the [PATRIOT]() memory scanner which targets the research of both [@C5pider] and [ilove2pwn_]. In simple terms, PATRIOT will check if the **Rip** field of a CONTEXT struct points to a \*Protect function. Since it doesn't inspect non-volatile registers we can simply store the address of our function in a non-volatile register and point the **Rip** of the CONTEXT to an arbitrary gadget that jumps to said register.

```c
//
// use the given register to store our function address
// we then execute it through a JMP gadget
//
FLOWER_GADGET_RAX
FLOWER_GADGET_RBX
```
### stackspoofing

Will conceal the instruction pointer (RtlUserThreadStart + 0x21) and stack of the beacon thread (Rsp pointing to an empty buffer)

```c
FLOWER_STACKSPOOF
```
# NOTE
Should you use this out of the box ? probably not. Is it better than endlessly toggling the permissions of our region ? yes. 

# CREDITS

- Austin Hudson [@ilove2pwn_](https://twitter.com/ilove2pwn_)
- 5pider [@C5pider](https://twitter.com/C5pider)
