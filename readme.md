dogio
---

Hello gamers this is my fork of the [aimeio-pcsc project](https://github.com/Nat-Lab/aimeio-pcsc).  
It exists because I wanted wider card support that ignored the nuances of authenticating NFC cards.  

Instead of authenticating and getting real card data we just grab the card's UID and add some extra garbage to use as an access code.  
In theory this will now allow you to scan banapass (mifare 1k with some extra stank), generic mifare 1k classic, NTAG216, and some mifare ultralight cards.  
More cards could be added!?  
Amazing.  

### Usage

To test if your card reader is supported, run `aimereader.exe` and try read your card.
To use it with a game, copy `aimeio.dll` to your `segatools` folder and add the following to your `segatools.ini`:

```ini
[aimeio]
path=aimeio.dll
```

### Build
I build on windows like a heathen, mileage on this may vary.
```sh
meson setup --cross cross-mingw.txt target
ninja -C target
```